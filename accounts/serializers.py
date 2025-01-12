from rest_framework import serializers
from .models import CustomUser, PasswordResetToken


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'password', 'uploaded_avatar', 'selected_avatar', 'is_online']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = CustomUser.objects.create_user(**validated_data)
        return user
    
    def update(self, instance, validated_data):
        instance.username = validated_data.get('username', instance.username)
        instance.email = validated_data.get('email', instance.email)
        if 'uploaded_avatar' in validated_data:
            instance.uploaded_avatar = validated_data['uploaded_avatar']
        if 'selected_avatar' in validated_data:
            instance.selected_avatar = validated_data['selected_avatar']
        instance.save()
        return instance


class SendPasswordResetEmailSerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordResetToken
        fields = ['email', 'token']
