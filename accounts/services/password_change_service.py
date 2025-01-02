from ..models import CustomUser


class PasswordChangeService:

    @staticmethod
    def get_user_by_email(email):
        try:
            return CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return None

    @staticmethod
    def update_user_password(user, new_password):
        user.set_password(new_password)
        user.save()

    @staticmethod
    def change_user_password(email, new_password):
        user = PasswordChangeService.get_user_by_email(email)
        if not user:
            raise ValueError('User with this email does not exist.')
        PasswordChangeService.update_user_password(user, new_password)
