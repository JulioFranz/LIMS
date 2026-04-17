from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return f"Profile of {self.user.username}"

class ProfileChangeToken(models.Model):
    CHANGE_TYPES = [
        ('email', 'Email'),
        ('email_new', 'Email New'),
        ('password', 'Password'),
        ('verify', 'Verify'),
        ('2fa_login', '2FA Login'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='change_tokens')
    token = models.UUIDField(unique=True)
    change_type = models.CharField(max_length=20, choices=CHANGE_TYPES)
    new_value = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} — {self.change_type} token"