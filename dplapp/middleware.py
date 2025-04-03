from django.urls import resolve
from django.shortcuts import redirect
from django.contrib import messages

from ipware import get_client_ip

from django.http import HttpResponseForbidden

import os

import logging
logger = logging.getLogger()

class BlockPasswordChangeMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Проверка: текущий пользователь — определённый пользователь?
        if request.user.is_authenticated and request.path == '/admin/password_change/':
            if request.user.username == 'admin':  # Укажите имя пользователя
                messages.error(request, "You don't have permisson to change your password.")
                return HttpResponseForbidden("Forbidden")
                # return redirect('/admin/')  # Перенаправляем обратно на главную админки

        return self.get_response(request)
    

ALLOWED_OPEN_PATHS = [
    '/mainrequest/',
    '/health/',
    '/'
]

_raw = os.environ.get("ALLOWED_EXTERNAL_IPS", "")
ALLOWED_EXTERNAL_IPS = [ip.strip() for ip in _raw.split(",") if ip.strip()]

class RestrictIPMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path

        client_ip, is_routable = get_client_ip(request)

        # logger.warning(f"{client_ip}, {is_routable}, {ALLOWED_EXTERNAL_IPS}, {_raw}")

        if (path == '/'
            or any(path.startswith(p) for p in ALLOWED_OPEN_PATHS if p != '/')
            or is_routable == False):
            return self.get_response(request)

        if ALLOWED_EXTERNAL_IPS and client_ip not in ALLOWED_EXTERNAL_IPS:
            return HttpResponseForbidden(f"Access denied for IP: {client_ip}")

        return self.get_response(request)