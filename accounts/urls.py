from django.urls import path
from . import views


urlpatterns = [
    path('create-user/', views.CreateUserView.as_view(), name='create-user'),
    path('check-email/', views.CheckEmailExistsView.as_view(), name='check_email'),
    path('send-reset-email/', views.SendPasswordResetEmailView.as_view(), name='send-reset-email'),
    path('delete-reset-email/', views.DeletePasswordResetEmailView.as_view(), name='delete-reset-email'),
    path('get-reset-email/', views.GetPasswordResetEmailView.as_view(), name='get-reset-email'),
    path('change-reset-password/', views.ChangePasswordView.as_view(), name='change-reset-password'),
    path('login-guest/', views.GuestLoginView.as_view(), name='login-guest'),
    path('token/', views.CustomTokenObtainPairView.as_view(), name='custom_token_obtain'),
    path('token/refresh/', views.CustomTokenRefreshView.as_view(), name='custom_token_refresh'),
    path('update/', views.UserUpdateView.as_view(), name='update'),
    path('get-users/', views.UserListView.as_view(), name='get-users'),
    path('logout-user/', views.UserLogoutView.as_view(), name='logout-user'),
]
