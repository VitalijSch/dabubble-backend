from django.urls import path
from . import views


urlpatterns = [
    path('create-channel/', views.CreateChannelView.as_view(), name='create-channel'),
]
