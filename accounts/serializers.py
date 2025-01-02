from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from .models import CustomUser, PasswordResetToken


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'password', 'uploaded_avatar', 'selected_avatar']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = CustomUser.objects.create_user(**validated_data)
        return user


class SendPasswordResetEmailSerializer(serializers.ModelSerializer):
    class Meta:
        model = PasswordResetToken
        fields = ['email', 'token']
