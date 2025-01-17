from rest_framework import serializers
from .models import CustomChannel


class ChannelSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomChannel
        fields = ['name', 'description', 'creator', 'members']
