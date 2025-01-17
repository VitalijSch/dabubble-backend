from rest_framework import generics, permissions
from .models import CustomChannel
from .serializers import ChannelSerializer


class CreateChannelView(generics.CreateAPIView):
    queryset = CustomChannel.objects.all()
    serializer_class = ChannelSerializer
    permission_classes = [permissions.IsAuthenticated]
