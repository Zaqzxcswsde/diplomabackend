# custom_command to generate keypair

from django.core.management.base import BaseCommand, CommandError

from dplapp.models import AppSettingsModel

from django.core.exceptions import ImproperlyConfigured, ValidationError

import logging

logger = logging.getLogger()

class Command(BaseCommand):

    help = "Generates keypair, takes --override as an optional argument"

    def add_arguments(self, parser):

        allowed_modes_keys = [x.lower() for x in AppSettingsModel.ENFORCING_MODES.keys()]

        allowed_modes_values = list(AppSettingsModel.ENFORCING_MODES.values())

        parser.add_argument(
            'mode',
            type=str.lower,
            choices = allowed_modes_keys + allowed_modes_values,
            help=f"Enforcing mode. Allowed values (case insensitive): {', '.join(allowed_modes_keys + allowed_modes_values)}"
        )

    def handle(self, mode, *args, **options):
        sett = AppSettingsModel.objects.get_or_create()[0]

        allowed_modes_values = list(AppSettingsModel.ENFORCING_MODES.values())

        if mode in allowed_modes_values:
            mode = [key for key, value in AppSettingsModel.ENFORCING_MODES.items() if value == mode][0]

        sett.enforcing_mode = mode

        try:
            sett.save()
        except ValidationError as exc:
            raise CommandError('error in saving mode, value seems to be incorrect') from exc
        
        logger.info(f"changed mode to: {mode}")