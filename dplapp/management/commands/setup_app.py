# custom_command to generate keypair

from django.core.management.base import BaseCommand, CommandError

from dplapp.models import AppSettingsModel

from dplapp.utils import save_keypair_to_database, save_encryption_key_to_database

from datetime import timedelta

import uuid

import logging

logger = logging.getLogger()

class Command(BaseCommand):
    help = "Sets up all of the necessary settings which are required for the app to function, takes --override as an optional argument"

    def add_arguments(self, parser):
        parser.allow_abbrev = False
        parser.add_argument(
            "--override",
            action='store_true',
            help="Override existing arguments",
        )

    def handle(self, *args, **options):

        override = options["override"]


        save_keypair_to_database(override)
        save_encryption_key_to_database(override)

        sett = AppSettingsModel.objects.get_or_create()[0]


        default_values = {
            # "ticket_validity_period":   lambda: timedelta(days=3),
            "ticket_expiry_period":     lambda: timedelta(days=7),
            "enforcing_mode":           lambda: sett.ON,
            "activity_period":          lambda: timedelta(seconds=5),
            "admin_panel_token":        lambda: uuid.uuid4()
        }

        for attr_name, def_value in default_values.items():
            if override or not getattr(sett, attr_name):
                setattr(sett, attr_name, def_value())
                logger.info(f"Changed {attr_name}")
            else:
                logger.info(f"Not changing {attr_name}")

        sett.save()