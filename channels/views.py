from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import ChannelSerializer
from accounts.models import CustomUser

class CreateChannelView(APIView):
    def post(self, request):
        channel_data = request.data
        
        # Hole den Creator als CustomUser Objekt
        creator = CustomUser.objects.get(id=channel_data['creator'])
        
        # Setze die ID des Creators in die channel_data
        channel_data['creator'] = creator.id  # Dies wird an das ForeignKey-Feld übergeben
        
        # Serialisiere die Channel-Daten
        serializer = ChannelSerializer(data=channel_data)
        
        if serializer.is_valid():
            # Speichere den Channel
            serializer.save()
            return Response({'data': serializer.data}, status=status.HTTP_201_CREATED)
        
        return Response({'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
