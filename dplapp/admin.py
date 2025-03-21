from django.contrib import admin

# Register your models here.

from dplapp.models import TokensModel, UsersModel, AppSettingsModel, HistoryModel


# @admin.display(description="Str")
# def get_str(obj):
#     return str(obj)


@admin.register(TokensModel)
class TokenAdmin(admin.ModelAdmin):
    list_display = ["__str__", 'fingerprint', 'is_active', 'user']
    list_editable = ['is_active', 'user']
    readonly_fields = ['pubkey', 'pin', 'last_activated']
    search_fields = ["pubkey"]

    def has_add_permission(self, request):
        return False

    pass


@admin.register(UsersModel)
class UsersAdmin(admin.ModelAdmin):
    pass

@admin.register(HistoryModel)
class HistoryAdmin(admin.ModelAdmin):

    list_display = ["__str__", 'token', 'msg', 'result', 'ip', 'datetime']
    list_filter = ["token", 'msg']
    readonly_fields = ['token', 'msg', 'result', 'ip', 'initial_data']

    def has_add_permission(self, request):
        return False

    pass

@admin.register(AppSettingsModel)
class SettingsAdmin(admin.ModelAdmin):

    fields = ['ticket_expiry_period', 'enforcing_mode', 'activity_period', 'public_key'] # , 'admin_panel_token'
    readonly_fields = ['public_key'] # , 'admin_panel_token'

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    pass