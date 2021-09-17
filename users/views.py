import os
import requests
from django.views.generic import FormView, DetailView, UpdateView
from django.urls import reverse_lazy
from django.shortcuts import redirect, reverse
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.views import PasswordChangeView
from django.contrib.auth.decorators import login_required
from django.core.files.base import ContentFile
from django.contrib import messages
from . import forms, models

# Create your views here.
class LoginView(FormView):

    template_name = "users/login.html"
    form_class = forms.LoginForm
    success_url = reverse_lazy("core:home")

    def form_valid(self, form):
        email = form.cleaned_data.get("email")
        password = form.cleaned_data.get("password")
        user = authenticate(self.request, username=email, password=password)
        if user is not None:
            login(self.request, user)
            messages.success(self.request, f"Welcome back {user.first_name}")
        return super().form_valid(form)


def log_out(request):
    messages.info(request, f"See you later!")
    logout(request)
    return redirect(reverse("core:home"))


class SignUpView(FormView):
    template_name = "users/signup.html"
    form_class = forms.SignUpForm
    success_url = reverse_lazy("core:home")

    def form_valid(self, form):
        form.save()

        email = form.cleaned_data.get("email")
        password = form.cleaned_data.get("password")
        user = authenticate(self.request, username=email, password=password)
        if user is not None:
            login(self.request, user)
        user.verify_email()
        return super().form_valid(form)


def complete_verification(request, key):
    try:
        user = models.User.objects.get(email_secret=key)
        user.email_verified = True
        user.email_secret = ""
        user.save()
    except models.User.DoesNotExist:
        pass
    return redirect(reverse("core:home"))


def github_login(request):
    client_id = os.environ.get("GH_ID")
    redirect_uri = "http://127.0.0.1:8000/users/login/github/callback"
    return redirect(
        f"https://github.com/login/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope=read:user"
    )


class GithubException(Exception):
    pass


def github_callback(request):
    try:
        code = request.GET.get("code", None)
        client_id = os.environ.get("GH_ID")
        client_secret = os.environ.get("GH_SECRET")
        if code is not None:  # callback으로 준 CODE가 잘 넘어왔다.
            token = requests.post(
                f"https://github.com/login/oauth/access_token?client_id={client_id}&client_secret={client_secret}&code={code}",
                headers={"Accept": "application/json"},
            )
            token_json = token.json()
            error = token_json.get("error", None)
            if error is not None:  # Access Token 못 받아왔다.
                raise GithubException("Can't get access token.")
            else:  # Access Token 잘 받아왔다 .
                access_token = token_json.get("access_token")
                profile_request = requests.get(
                    "https://api.github.com/user",
                    headers={
                        "Authorization": f"token {access_token}",
                        "Accept": "application/json",
                    },
                )
                profile_json = profile_request.json()
                username = profile_json.get("login")
                if username is not None:  # Github API로 username 잘 받아왔다
                    name = profile_json.get("name")
                    email = profile_json.get("email")
                    bio = profile_json.get("bio")
                    if name is None:
                        name = username
                    if email is None:
                        email = username
                    if bio is None:
                        bio = ""
                    try:  # 우리 사이트에 이미 있는 user일 때 Login해준다. (email이나 kakao로 login한 적이 있는 경우 제외)
                        user = models.User.objects.get(email=email)
                        if user.login_method != models.User.LOGIN_GITHUB:
                            raise GithubException(f"Please log in with: {user.login_method}")  # email이나 kakao로 login한 적이 있는 경우
                    except models.User.DoesNotExist:
                        # 우리 사이트에 없는 user라면 가입시킨다.
                        user = models.User.objects.create(
                            username=email,
                            first_name=name,
                            bio=bio,
                            email=email,
                            login_method=models.User.LOGIN_GITHUB,
                            email_verified=True,
                        )
                        user.set_unusable_password()
                        user.save()
                    login(request, user)
                    messages.success(request, f"Welcome back {user.first_name}")
                    return redirect(reverse("core:home"))
                else:  # Github API에서 username 못 받아옴
                    raise GithubException("Can't get your profile.")
        else:  # callback으로 Code를 못받아왔다.
            raise GithubException("Can't get code.")
    except GithubException as e:
        messages.error(request, e)
        return redirect(reverse("users:login"))


def kakao_login(request):
    client_id = os.environ.get("KAKAO_REST_API_KEY")
    redirect_uri = "http://127.0.0.1:8000/users/login/kakao/callback"
    return redirect(
        f"https://kauth.kakao.com/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code"
    )


class KakaoException(Exception):
    pass


def kakao_callback(request):
    try:
        code = request.GET.get("code", None)
        client_id = os.environ.get("KAKAO_REST_API_KEY")
        redirect_uri = "http://127.0.0.1:8000/users/login/kakao/callback"
        token_request = requests.get(
            f"https://kauth.kakao.com/oauth/token?grant_type=authorization_code&client_id={client_id}&redirect_uri={redirect_uri}&code={code}"
        )
        token_json = token_request.json()
        error = token_json.get("error", None)
        if error is not None:  # Access Token 못 받아왔다.
            raise KakaoException("Can't get authorization code.")
        else:  # Access Token 잘 받아왔다 .
            access_token = token_json.get("access_token")
            profile_request = requests.get(
                "https://kapi.kakao.com/v2/user/me",
                headers={
                    "Authorization": f"Bearer {access_token}",
                },
            )
            profile_json = profile_request.json()
            properties = profile_json.get("kakao_account")
            email = properties.get("email")
            if email is None:  # Kakao API로 email 못 받아온 경우
                raise KakaoException("Please also give me your email.")
            # Kakao API로 email 잘 받아왔다
            profile = properties.get("profile")
            nickname = profile.get("nickname")
            profile_image = profile.get("profile_image_url")
            try:  # 우리 사이트에 이미 있는 user일 때 Login해준다.
                user = models.User.objects.get(email=email)
                if (
                    user.login_method != models.User.LOGIN_KAKAO
                ):  # email이나 github으로 login한 적이 있는 경우
                    raise KakaoException(f"Please log in with: {user.login_method}")
            except models.User.DoesNotExist:
                # 우리 사이트에 없는 user라면 가입시킨다.
                user = models.User.objects.create(
                    username=email,
                    first_name=nickname,
                    email=email,
                    login_method=models.User.LOGIN_KAKAO,
                    email_verified=True,
                )
                user.set_unusable_password()
                user.save()
                if profile_image is not None:
                    photo_request = requests.get(profile_image)
                    user.profile.save(
                        f"{nickname}-profile", ContentFile(photo_request.content)
                    )
            login(request, user)
            messages.success(request, f"Welcome back {user.first_name}")
            return redirect(reverse("core:home"))

    except KakaoException as e:
        messages.error(request, e)
        return redirect(reverse("users:login"))

class UserProfileView(DetailView):

    model = models.User
    context_object_name = "user_obj"

class UpdateProfileView(UpdateView):
    
    model = models.User
    template_name = "users/update-profile.html"
    fields = (
        "email",
        "first_name", 
        "last_name", 
        "profile", 
        "gender", 
        "bio", 
        "birthdate", 
        "language", 
        "currency", 
    )

    def get_object(self, queryset=None):
        return self.request.user
    
    def form_valid(self, form):
        email = form.cleaned_data.get("email")
        self.object.username = email
        self.object.save()
        return super().form_valid(form)

class UpdatePasswordView(PasswordChangeView):
    template_name = "users/update-password.html"

@login_required
def switch_hosting(request):
    try:
        del request.session["is_hosting"]
    except KeyError:
        request.session["is_hosting"] = True
    return redirect(reverse("core:home"))
