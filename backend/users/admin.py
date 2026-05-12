from django.contrib import admin
from .models import AuditLog


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'event', 'result', 'user', 'ip')
    list_filter = ('event', 'result')
    search_fields = ('user__username', 'email_hash', 'ip')
    readonly_fields = ('created_at', 'event', 'result', 'user',
                       'email_hash', 'ip', 'user_agent')
    ordering = ('-created_at',)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False