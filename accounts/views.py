from django.http import JsonResponse
from django.views import View
from rest_framework import generics
from .models import CustomUser
from .serializers import UserSerializer


class CreateUserView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer


class CheckEmailExistsView(View):
    def get(self, request, *args, **kwargs):
        email = request.GET.get('email', None)
        if email is None:
            return JsonResponse({'error': 'Email-Parameter fehlt'}, status=400)

        exists = CustomUser.objects.filter(email=email).exists()
        return JsonResponse({'exists': exists})


class CheckEmailExistsView(View):
    def get(self, request, *args, **kwargs):
        email = request.GET.get('email')
        if not email:
            return JsonResponse({'error': 'The email parameter is missing.'}, status=400)
        exists = CustomUser.objects.filter(email=email).exists()
        return JsonResponse({'exists': exists}, status=200)
