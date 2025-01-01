from ..models import CustomUser

def email_exists(email):
    return CustomUser.objects.filter(email=email).exists()