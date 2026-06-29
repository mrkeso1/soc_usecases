from django.core.management.base import BaseCommand

from apps.sources.matching import resolve_event_sources, sync_usecase_sources
from apps.usecases.models import UseCase


class Command(BaseCommand):
    help = "Machea UseCase.device contra Fuentes de eventos y crea vinculos UseCaseSource."

    def add_arguments(self, parser):
        parser.add_argument("--create-missing", action="store_true", help="Crea fuentes minimas cuando no existe match.")
        parser.add_argument("--dry-run", action="store_true", help="Solo informa que haria; no escribe cambios.")

    def handle(self, *args, **options):
        create_missing = options["create_missing"]
        dry_run = options["dry_run"]
        checked = linked = created = unresolved_count = skipped = 0

        qs = UseCase.objects.exclude(device__isnull=True).exclude(device__exact="").order_by("name")
        for usecase in qs:
            checked += 1
            if dry_run:
                sources, created_count, unresolved = resolve_event_sources(
                    usecase.device,
                    create_missing=False,
                )
                if sources:
                    self.stdout.write(f"[MATCH] {usecase.pk} {usecase.name}: {usecase.device} -> {', '.join(s.display_name for s in sources)}")
                    linked += len(sources)
                elif create_missing:
                    self.stdout.write(f"[CREATE] {usecase.pk} {usecase.name}: crearia fuente '{usecase.device}'")
                    created += created_count or 1
                else:
                    self.stdout.write(self.style.WARNING(f"[PENDING] {usecase.pk} {usecase.name}: sin match para '{usecase.device}'"))
                    unresolved_count += len(unresolved) or 1
                continue

            result = sync_usecase_sources(
                usecase,
                usecase.device,
                create_missing=create_missing,
                defaults={"description": "Creada automaticamente desde migrate_usecase_sources."},
            )
            linked += result["linked"]
            created += result["created"]
            unresolved_count += len(result["unresolved"])
            if not result["linked"] and not result["created"]:
                skipped += 1
                self.stdout.write(self.style.WARNING(f"[PENDING] {usecase.pk} {usecase.name}: {usecase.device}"))

        self.stdout.write("")
        self.stdout.write(self.style.SUCCESS("Macheo de fuentes finalizado"))
        self.stdout.write(f"Casos revisados: {checked}")
        self.stdout.write(f"Vinculos encontrados/creados: {linked}")
        self.stdout.write(f"Fuentes creadas: {created}")
        self.stdout.write(f"Pendientes sin resolver: {unresolved_count}")
        self.stdout.write(f"Omitidos: {skipped}")
