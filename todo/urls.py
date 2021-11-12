from django.urls import path, include
from .views import userAPIView,LoginView,LogoutView,RegistrationView,ResetPasswordView,ChangePasswordView,UserLogoutView

urlpatterns = [
    path('users', userAPIView.as_view()),
    path('login',LoginView.as_view(),name='login'),
    path('logout',LogoutView.as_view(),name='logout'),
    path('user_logout',UserLogoutView.as_view(),name='UserLogout'),
    path('register',RegistrationView.as_view(),name='register'),
    path('reset',include('django_rest_passwordreset.urls', namespace='password_reset')),
    # path('confirm',reset_password_confirm)
    path('confirm',ResetPasswordView.as_view()),
    path('change',ChangePasswordView.as_view())
]

