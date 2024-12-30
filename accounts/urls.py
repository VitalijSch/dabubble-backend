from django.urls import path
from . import views


urlpatterns = [
    path('create-user/', views.CreateUserView.as_view(), name='create-user'),
    path('check-email/', views.CheckEmailExistsView.as_view(), name='check_email'),
    path('send-reset-email/', views.SendPasswordResetEmailView.as_view(), name='send-reset-email'),
    path('delete-reset-email/', views.DeletePasswordResetEmailView.as_view(), name='delete-reset-email'),
    path('get-reset-email/', views.GetPasswordResetEmailView.as_view(), name='get-reset-email'),
    path('change-reset-password/', views.ChangePasswordView.as_view(), name='change-reset-password'),
]
