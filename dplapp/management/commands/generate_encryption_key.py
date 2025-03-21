# custom_command to generate keypair

from django.core.management.base import BaseCommand, CommandError


from dplapp.utils import save_encryption_key_to_database

class Command(BaseCommand):
    help = "Generates ticket enctyption key, takes --override as an optional argument"

    def add_arguments(self, parser):
        parser.allow_abbrev = False
        parser.add_argument(
            "--override",
            action="store_true",
            help="Override existing keypair",
        )

    def handle(self, *args, **options):
        save_encryption_key_to_database(options["override"])
