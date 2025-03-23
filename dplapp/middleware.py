from django.urls import resolve
from django.shortcuts import redirect
from django.contrib import messages

from django.http import HttpResponseForbidden

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