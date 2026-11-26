from django.contrib.auth.forms import AdminUserCreationForm, UserChangeForm

from .models import User


class UserCreationAdminForm(AdminUserCreationForm[User]):
    class Meta:
        model = User
        fields = ("email", "full_name", "default_avatar")


class UserChangeAdminForm(UserChangeForm[User]):
    class Meta:
        model = User
        fields = "__all__"
