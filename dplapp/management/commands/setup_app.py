# custom_command to generate keypair

from django.core.management.base import BaseCommand, CommandError


from dplapp.utils import setup_app_logic


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
        setup_app_logic(override)