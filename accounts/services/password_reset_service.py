from .password_reset_token_service import PasswordResetTokenService
from .email_service import EmailService


class PasswordResetService:

    def process_password_reset(self, email):
        token = PasswordResetTokenService.create_token(email)
        reset_url = self._generate_reset_url(token)
        EmailService.send_reset_email(email, reset_url)

    def _generate_reset_url(self, token):
        base_url = 'http://localhost:4200/auth/reset-password/'
        return f'{base_url}{token}'
