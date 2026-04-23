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
        ('password_reset', 'Password Reset'),
    ]
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='change_tokens')
    token = models.UUIDField(unique=True)
    change_type = models.CharField(max_length=20, choices=CHANGE_TYPES)
    new_value = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    token_hash = models.CharField(max_length=64, blank=True, default='')
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'change_type']),
        ]

    def __str__(self):
        return f"{self.user.username} — {self.change_type} token"

class AuditLog(models.Model):
    EVENTS = [
        ('password_reset_requested', 'Password Reset Requested'),
        ('password_reset_confirmed', 'Password Reset Confirmed'),
    ]
    RESULTS = [
        ('email_sent', 'Email Sent'),
        ('no_user', 'No User'),
        ('email_send_failed', 'Email Send Failed'),
        ('success', 'Success'),
        ('token_not_found', 'Token Not Found'),
        ('token_already_used', 'Token Already Used'),
        ('invalid_secret', 'Invalid Secret'),
        ('token_expired', 'Token Expired'),
        ('weak_password', 'Weak Password'),
    ]

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    event = models.CharField(max_length=64, choices=EVENTS, db_index=True)
    result = models.CharField(max_length=32, choices=RESULTS)
    user = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='audit_logs',
    )
    email_hash = models.CharField(max_length=32, blank=True, default='')
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=200, blank=True, default='')

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['event', 'result']),
            models.Index(fields=['-created_at']),
        ]

    def __str__(self):
        return f"{self.created_at:%Y-%m-%d %H:%M:%S} {self.event} {self.result}"