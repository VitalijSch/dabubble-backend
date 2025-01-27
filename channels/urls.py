from django.urls import path
from . import views


urlpatterns = [
    path('create-channel/', views.ChannelCreateView.as_view(), name='create-channel'),
    path('get-all-channels/', views.ChannelListView.as_view(), name='get-all-channels'),
    path('update-channel/', views.ChannelUpdateView.as_view(), name='update-channel'),
]
