from time import sleep
from django.shortcuts import render

# Create your views here.

from rest_framework import mixins

from rest_framework.views import APIView
from rest_framework.response import Response

from dplapp.serializers import MainRequestSerializer, HistorySerializer

from ipware import get_client_ip

from dplapp.models import TokensModel, HistoryModel, UsersModel, AppSettingsModel

from argon2 import PasswordHasher

from django.utils import timezone

from django.conf import settings

from rest_framework import serializers

from django.http import HttpResponseServerError

from dplapp.serializers import TokenSerializer

from django.db import connection

import django_filters.rest_framework as filters

from dplapp.permissions import HasAdminPanelToken

import logging
logger = logging.getLogger()

from rest_framework import viewsets

from rest_framework.decorators import action

from rest_framework import status

from rest_framework import filters as drf_filters

from django.core.exceptions import ObjectDoesNotExist

import django_filters

class UpdateEnforcingModeView(APIView):

    permission_classes = [HasAdminPanelToken]  # опционально

    def get(self, request):
        settings_obj = AppSettingsModel.objects.get()
        return Response({"enforcing_mode": settings_obj.enforcing_mode})


    def post(self, request):
        mode = request.data.get('enforcing_mode')

        allowed_modes = ['of', 'on', 'gr']
        if mode not in allowed_modes:
            return Response(
                {"error": f"Invalid enforcing_mode. Allowed: {allowed_modes}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            settings_obj = AppSettingsModel.objects.get()
            settings_obj.enforcing_mode = mode
            settings_obj.save()
        except ObjectDoesNotExist:
            return Response(
                {"error": f"Settings not configured. Run setup_app!"},
                status=status.HTTP_400_BAD_REQUEST
            )

        return Response({"enforcing_mode": settings_obj.enforcing_mode}, status=200)









class TokenFilter(filters.FilterSet):
    has_user = django_filters.BooleanFilter(
        field_name='user',
        lookup_expr='isnull',
        exclude=True  # инвертирует: True → isnull=False (есть пользователь)
    )


    class Meta:
        model = TokensModel
        fields = {
            'is_active': ['exact'],
            'last_activated': ['lt', 'gt', 'exact'],
        }

class TokenViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    # mixins.DestroyModelMixin,
    viewsets.GenericViewSet
):
    queryset = TokensModel.objects.all()
    serializer_class = TokenSerializer
    filterset_class = TokenFilter
    http_method_names = ['get', 'patch', 'head', 'options', 'post', 'delete']
    permission_classes = [HasAdminPanelToken]

    filter_backends = [
        django_filters.rest_framework.DjangoFilterBackend,
        drf_filters.SearchFilter,
        drf_filters.OrderingFilter,
    ]
    search_fields = ['id', 'pubkey', 'user__uuid', 'user__additional_data']
    ordering_fields = ['last_activated', 'id']
    ordering = ['-id']

    @action(detail=False, methods=['post'], url_path='bulk-activate')
    def bulk_activate(self, request):
        ids = request.data.get('ids')
        new_value = request.data.get('is_active')

        if not isinstance(ids, list) or not isinstance(new_value, bool):
            return Response(
                {'error': 'Expected "ids": [..] and "is_active": true/false'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        existing_ids = set(TokensModel.objects.filter(id__in=ids).values_list('id', flat=True))
        requested_ids = set(ids)

        missing_ids = requested_ids - existing_ids
        if missing_ids:
            return Response(
                {'error': f'Tokens with the following IDs were not found: {list(missing_ids)}'},
                status=400
            )

        tokens = TokensModel.objects.filter(id__in=ids)
        to_update = [t.id for t in tokens if t.is_active != new_value]

        TokensModel.objects.filter(id__in=to_update).update(is_active=new_value)
        updated = len(to_update)

        return Response({'updated': updated}, status=200)


    @action(detail=False, methods=['delete'], url_path='delete-inactive')
    def delete_inactive(self, request):
        query = TokensModel.objects.filter(is_active=False)
        deleted_count = query.count()
        query.delete()
        return Response({'deleted': deleted_count}, status=status.HTTP_200_OK)

    @action(detail=False, methods=['delete'], url_path='delete-unlinked')
    def delete_unlinked(self, request):
        query = TokensModel.objects.filter(user__isnull=True)
        deleted_count = query.count()
        query.delete()
        return Response({'deleted': deleted_count}, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='count')
    def count_tokens(self, request):
        queryset = self.filter_queryset(self.get_queryset())
        count = queryset.count()
        return Response({'count': count}, status=status.HTTP_200_OK)



    # def update(self, request, *args, **kwargs):
    #     # Полный PUT-запрос — запрещён
    #     return Response({"detail": "PUT-запросы не поддерживаются."}, status=405)

# class ChangeEnforsingModeView(APIView):
#     def post(self, request, format=None):
#         request.data
#         pass

class HealthCheckView(APIView):

    def get(self, request, format=None):

        err_details = None

        try:
            connection.ensure_connection()
        except Exception as e:
            err_details = e
        
        if not (AppSettingsModel.objects.get_or_create()[0].public_key and AppSettingsModel.objects.get_or_create()[0].enforcing_mode):
            err_details = "No settings found, run setup_app"

        if not err_details:
            return Response({"status": "ok"}, status=200)
        else:
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