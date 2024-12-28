from django.urls import path
from . import views


urlpatterns = [
    path('create-user/', views.CreateUserView.as_view(), name='create-user'),
    path('check-email/', views.CheckEmailExistsView.as_view(), name='check_email'),
]
