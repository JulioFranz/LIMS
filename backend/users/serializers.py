from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password as django_validate_password
from django.core.exceptions import ValidationError as DjangoValidationError


class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True, min_length=8)

    def validate_password(self, value):
        try:
            django_validate_password(value)
        except DjangoValidationError as e:
            raise serializers.ValidationError(e.messages)
        return value


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class TwoFactorSerializer(serializers.Serializer):
    token = serializers.CharField()


class TOTPPendingSerializer(serializers.Serializer):
    pending_token = serializers.CharField()


class TOTPCodeSerializer(serializers.Serializer):
    pending_token = serializers.CharField()
    totp_code = serializers.CharField(min_length=6, max_length=6)


class DisableTOTPSerializer(serializers.Serializer):
    totp_code = serializers.CharField(min_length=6, max_length=6)


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()  # segredo
    new_password = serializers.CharField(write_only=True, min_length=8)
