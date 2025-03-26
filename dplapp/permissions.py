from rest_framework.permissions import BasePermission
from rest_framework.exceptions import PermissionDenied
from dplapp.models import AppSettingsModel

class HasAdminPanelToken(BasePermission):
    def has_permission(self, request, view):
        token_from_request = request.headers.get("X-Admin-Token")
        try:
            expected_token = AppSettingsModel.objects.get().admin_panel_token
        except AppSettingsModel.DoesNotExist:
            raise PermissionDenied("No settings found. Run setup_app!")

        if not expected_token:
            raise PermissionDenied("No token found in settings. Run setup_app!")

        if not token_from_request or str(token_from_request) != str(expected_token):
            raise PermissionDenied("Invalid token")
        
        return True
