from time import sleep
from django.shortcuts import render

# Create your views here.


from rest_framework.views import APIView
from rest_framework.response import Response

from dplapp.serializers import MainRequestSerializer, HistorySerializer

from ipware import get_client_ip

from dplapp.models import TokensModel, HistoryModel, UsersModel

from argon2 import PasswordHasher

from django.utils import timezone

from django.conf import settings

from rest_framework import serializers

from django.http import HttpResponseServerError

from django.db import connection

import logging
logger = logging.getLogger()

class HealthCheckView(APIView):

    def get(self, request, format=None):

        raise Exception

        try:
            connection.ensure_connection()
            return Response({"status": "ok"}, status=200)
        except Exception as e:
            return Response({"status": "error", "details": str(e)}, status=500)


class CanLoginView(APIView):

    def get(self, request, uid, format=None):

        user = UsersModel.objects.filter(uuid = uid).first()

        if not user:
            return Response({'status': False})

        return Response({'status': user.can_login})


class MainRequestView(APIView):

    # authentication_classes = [authentication.TokenAuthentication]
    # permission_classes = [permissions.IsAdminUser]

    def post(self, request, format=None):

        # sleep(3)
        # raise Exception

        client_ip, _ = get_client_ip(request)

        serializer = MainRequestSerializer(data = request.data, context={'ip': client_ip})

        if not serializer.is_valid():

            HistoryModel.objects.create(
                token = TokensModel.objects.filter(pubkey = serializer.context.get('public_key', None)).first(),
                initial_data = serializer.initial_data,
                ip = client_ip,
                result = serializer.errors,
                msg = "ERR",
            )

            raise serializers.ValidationError(serializer.errors)

        token : TokensModel = serializer.save()

        ticket_data = serializer.create_ticket()

        HistoryModel.objects.create(
            token = token,
            initial_data = serializer.initial_data,
            ip = client_ip,
            result = "",
            msg = "SUCCESS",
        )

        history_queryset = HistoryModel.objects.filter(token = token).order_by("-datetime")[:5]

        history_items = HistorySerializer(history_queryset, many = True)

        # logger.warning(history_items.data)

        ticket_data.update({'history': history_items.data})

        return Response(ticket_data)