from django.contrib import admin, messages

# Register your models here.

from dplapp.models import TokensModel, UsersModel, AppSettingsModel, HistoryModel

from dplapp.utils import setup_app_logic

from uuid import uuid4

from django.urls import reverse

from django.utils.html import format_html

# @admin.display(description="Str")
# def get_str(obj):
#     return str(obj)


@admin.register(TokensModel)
class TokenAdmin(admin.ModelAdmin):
    list_display = ["__str__", 'is_active', 'user', 'fingerprint'] # 
    list_editable = ['is_active', 'user']
    readonly_fields = ['pubkey', 'pin', 'last_activated', 'fingerprint'] #
    search_fields = ["pubkey"]

    def has_add_permission(self, request):
        return False

    pass


@admin.register(UsersModel)
class UsersAdmin(admin.ModelAdmin):

    readonly_fields = ['last_login']
    readonly_fields = ['last_login', 'linked_token']

    def linked_token(self, obj):
        if hasattr(obj, "tokensmodel"):
            url = reverse("admin:dplapp_tokensmodel_change", args=[obj.tokensmodel.id])
            return format_html('<a href="{}">{}</a>', url, obj.tokensmodel.fingerprint)
        return "-"


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
    actions = ['run_setup_app', 'run_flush_admin_token']

    def has_add_permission(self, request):
        # Разрешить добавление только если в таблице ещё нет записи
        return not AppSettingsModel.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False

    def run_setup_app(self, request, queryset):
        try:
            setup_app_logic(override=False)
            self.message_user(request, "Настройки успешно применены!", level=messages.SUCCESS)
        except Exception as e:
            self.message_user(request, f"Ошибка при выполнении: {e}", level=messages.ERROR)


    def run_flush_admin_token(self, request, queryset):
        try:
            sett = AppSettingsModel.objects.get()
            sett.admin_panel_token = uuid4()
            sett.save()
            # setup_app_logic(override=False)
            self.message_user(request, "Токен успешно сброшен!", level=messages.SUCCESS)
        except Exception as e:
            self.message_user(request, f"Ошибка при выполнении: {e}", level=messages.ERROR)


    def formfield_for_dbfield(self, db_field, **kwargs):
        formfield = super().formfield_for_dbfield(db_field, **kwargs)
        if db_field.name == 'enforcing_mode':
            formfield.empty_label = None  # Убирает "пустой" выбор в админке
            formfield.required = True     # Делаем поле обязательным

            choices = list(formfield.choices)
            formfield.choices = [(k, v) for k, v in choices if k not in ("", None)]

        elif db_field.name == 'ticket_expiry_period' or db_field.name == 'activity_period':
            formfield.required = True

        return formfield

    pass