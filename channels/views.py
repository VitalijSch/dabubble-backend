from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import CustomChannel
from .serializers import ChannelSerializer
from accounts.models import CustomUser


class CreateChannelView(APIView):

    def post(self, request):
        try:
            serializer = self.serializer_channel(request.data)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def serializer_channel(self, request):
        channel_data = self.get_creator(request)
        serializer = ChannelSerializer(data=channel_data)
        if not serializer.is_valid():
            raise ValueError(serializer.errors)
        serializer.save()
        channels = self.get_all_channels()
        serializer =  ChannelSerializer(channels, many=True)
        return serializer
    
    @staticmethod
    def get_creator(request):
        creator = CustomUser.objects.get(id=request['creator'])
        request['creator'] = creator.id
        return request

    @staticmethod
    def get_all_channels():
        channels = CustomChannel.objects.all()
        return channels
    

class ChannelListView(APIView):

    def get(self, request):
        try:
            channels = CustomChannel.objects.all()
            serializer = ChannelSerializer(channels, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
