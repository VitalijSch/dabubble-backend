from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _

from .forms import UserChangeAdminForm, UserCreationAdminForm
from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin[User]):
    form = UserChangeAdminForm
    add_form = UserCreationAdminForm

    ordering = ("email",)
    list_display = ("email", "full_name", "is_staff", "is_active", "email_verified_at")
    list_filter = ("is_staff", "is_superuser", "is_active", "groups")
    search_fields = ("email", "full_name")

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (_("Personal info"), {"fields": ("full_name", "avatar", "default_avatar")}),
        (
            _("Permissions"),
            {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")},
        ),
        (_("Important dates"), {"fields": ("last_login", "date_joined", "email_verified_at")}),
        (
            _("Privacy policy"),
            {"fields": ("privacy_policy_accepted_at", "privacy_policy_version")},
        ),
    )
    # Evidence of what the user accepted; nobody should edit it by hand.
    readonly_fields = ("privacy_policy_accepted_at", "privacy_policy_version")
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "full_name",
                    "default_avatar",
                    "usable_password",
                    "password1",
                    "password2",
                ),
            },
        ),
    )
