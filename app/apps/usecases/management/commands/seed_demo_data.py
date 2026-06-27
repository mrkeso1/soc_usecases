from datetime import date, timedelta
from io import StringIO

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management import call_command
from django.core.management.base import BaseCommand

from apps.accounts.models import LDAPSettings
from apps.accounts.roles import ADMIN_GROUP, ANALYST_GROUP, READONLY_GROUP
from apps.dashboard.models import DashboardReportSettings
from apps.lifecycle.models import LifecycleReview, LifecycleSettings
from apps.mitre.models import CoverageOverride, D3Fend, MitreAttack, MitreAttackSyncSettings
from apps.sources.models import EventSource, UseCaseSource
from apps.usecases.models import (
    UseCase,
)


DEMO_PASSWORD = "Demo12345!"
DEMO_PREFIX = "Demo - "
DEMO_USERS = ("demo_admin", "demo_analyst", "demo_readonly", "demo_owner")


class Command(BaseCommand):
    help = "Carga datos demo para probar dashboard, PDF, matrices, permisos, lifecycle y admin."

    def add_arguments(self, parser):
        parser.add_argument("--reset", action="store_true", help="Borra primero los datos demo conocidos.")
        parser.add_argument("--password", default=DEMO_PASSWORD, help="Password para usuarios demo nuevos.")

    def handle(self, *args, **options):
        if options["reset"]:
            self._reset_demo_data()

        call_command("seed_groups", verbosity=0, stdout=StringIO())
        users = self._seed_users(options["password"])
        self._seed_settings()
        attacks = self._seed_attacks()
        d3fends = self._seed_d3fends(attacks)
        sources = self._seed_sources(users)
        usecases = self._seed_usecases(users, attacks)
        self._seed_usecase_sources(usecases, sources, users)
        self._seed_reviews(usecases, users)
        self._seed_overrides(users)

        self.stdout.write(self.style.SUCCESS("Datos demo cargados correctamente."))
        self.stdout.write(f"Usuarios demo: {', '.join(DEMO_USERS)}")
        self.stdout.write(f"Password default: {options['password']}")

    def _reset_demo_data(self):
        UseCase.objects.filter(name__startswith=DEMO_PREFIX).delete()
        UseCaseSource.objects.filter(source__code__startswith="DEMO-").delete()
        EventSource.objects.filter(code__startswith="DEMO-").delete()
        CoverageOverride.objects.filter(reason__icontains="[demo]").delete()
        LDAPSettings.objects.filter(name__startswith="Demo").delete()
        DashboardReportSettings.objects.filter(name__startswith="Demo").delete()
        LifecycleSettings.objects.filter(name__startswith="Demo").delete()
        MitreAttackSyncSettings.objects.filter(name__startswith="Demo").delete()
        get_user_model().objects.filter(username__in=DEMO_USERS).delete()
        self.stdout.write(self.style.WARNING("Datos demo previos eliminados."))

    def _seed_users(self, password):
        User = get_user_model()
        groups = {group.name: group for group in Group.objects.filter(name__in=[ADMIN_GROUP, ANALYST_GROUP, READONLY_GROUP])}
        specs = [
            ("demo_admin", "Demo Admin", ADMIN_GROUP, True, True),
            ("demo_analyst", "Demo Analyst", ANALYST_GROUP, False, False),
            ("demo_owner", "Demo Control Owner", ANALYST_GROUP, False, False),
            ("demo_readonly", "Demo ReadOnly", READONLY_GROUP, False, False),
        ]
        users = {}
        for username, display_name, group_name, is_staff, is_superuser in specs:
            user, created = User.objects.get_or_create(
                username=username,
                defaults={
                    "email": f"{username}@example.test",
                    "display_name": display_name,
                    "first_name": display_name.split()[0],
                    "last_name": " ".join(display_name.split()[1:]),
                    "is_staff": is_staff,
                    "is_superuser": is_superuser,
                    "is_active": True,
                },
            )
            if created:
                user.set_password(password)
            user.display_name = display_name
            user.is_staff = is_staff
            user.is_superuser = is_superuser
            user.is_active = True
            user.save()
            user.groups.set([groups[group_name]])
            users[username] = user
        return users

    def _seed_attacks(self):
        specs = [
            ("T1059", "Command and Scripting Interpreter", "Execution"),
            ("T1078", "Valid Accounts", "Defense Evasion, Initial Access, Persistence, Privilege Escalation"),
            ("T1110", "Brute Force", "Credential Access"),
            ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
            ("T1566", "Phishing", "Initial Access"),
            ("T1027", "Obfuscated Files or Information", "Defense Evasion"),
            ("T1003", "OS Credential Dumping", "Credential Access"),
            ("T1486", "Data Encrypted for Impact", "Impact"),
        ]
        attacks = {}
        for external_id, name, tactic in specs:
            attack, _ = MitreAttack.objects.update_or_create(
                external_id=external_id,
                defaults={"name": name, "tactic": tactic, "is_enabled": True},
            )
            attacks[external_id] = attack
        return attacks

    def _seed_d3fends(self, attacks):
        specs = [
            ("D3-PSA", "Process Spawn Analysis", "Process Analysis", ["T1059"]),
            ("D3-LAM", "Local Account Monitoring", "Identity and Access", ["T1078", "T1110"]),
            ("D3-NTA", "Network Traffic Analysis", "Network Monitoring", ["T1041", "T1566"]),
            ("D3-FTA", "File Traffic Analysis", "File Analysis", ["T1027", "T1486"]),
            ("D3-CDA", "Credential Dumping Detection", "Credential Protection", ["T1003"]),
        ]
        d3fends = {}
        for code, name, category, related_ids in specs:
            d3fend, _ = D3Fend.objects.update_or_create(
                code=code,
                defaults={
                    "name": name,
                    "category": category,
                    "description": f"[demo] Control defensivo para {category}.",
                    "is_enabled": True,
                },
            )
            d3fend.related_attacks.set(attacks[item] for item in related_ids)
            d3fends[code] = d3fend
        return d3fends

    def _seed_sources(self, users):
        analyst = users["demo_analyst"]
        specs = [
            ("DEMO-EDR", "Demo EDR", EventSource.TYPE_EDR, "Endpoint", "DemoSec", "Endpoint Sensor", "10.10.1.20", 443, "HTTPS"),
            ("DEMO-SIEM", "Demo SIEM", EventSource.TYPE_SIEM, "SIEM", "DemoSec", "Log Analytics", "10.10.2.10", 6514, "Syslog TLS"),
            ("DEMO-NDR", "Demo NDR", EventSource.TYPE_NETWORK, "Network", "DemoSec", "Network Sensor", "10.10.3.30", 443, "HTTPS"),
            ("DEMO-EMAIL", "Demo Email Security", EventSource.TYPE_OTHER, "Email", "DemoMail", "Mail Gateway", "10.10.4.25", 443, "HTTPS"),
            ("DEMO-CLOUD", "Demo Cloud Identity", EventSource.TYPE_CLOUD, "Cloud", "DemoCloud", "Identity Logs", "", None, "API HTTPS"),
        ]
        sources = {}
        for code, name, source_type, category, vendor, product, host, port, protocol in specs:
            source, _ = EventSource.objects.update_or_create(
                code=code,
                defaults={
                    "name": name,
                    "source_type": source_type,
                    "category": category,
                    "vendor": vendor,
                    "product": product,
                    "environment": "Demo",
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                    "status": EventSource.STATUS_ACTIVE,
                    "owner": analyst.username,
                    "description": "[demo] Fuente generada por seed_demo_data.",
                    "created_by": analyst,
                    "updated_by": analyst,
                },
            )
            sources[code] = source
        return sources

    def _seed_usecases(self, users, attacks):
        today = date.today()
        owner = users["demo_owner"]
        analyst = users["demo_analyst"]
        specs = [
            ("PowerShell suspicious execution", "EDR", "High", UseCase.STATUS_PRODUCTION, True, ["T1059"], today - timedelta(days=20), UseCase.VALIDATION_RESULT_OK),
            ("Valid accounts impossible travel", "SIEM", "Medium", UseCase.STATUS_PRODUCTION, True, ["T1078"], today - timedelta(days=140), UseCase.VALIDATION_RESULT_WARNING),
            ("Brute force escalation", "SIEM", "Critical", UseCase.STATUS_PRODUCTION, True, ["T1110"], today - timedelta(days=95), UseCase.VALIDATION_RESULT_WARNING),
            ("Exfiltration uncommon channel", "NDR", "Critical", UseCase.STATUS_PRODUCTION, True, ["T1041"], today - timedelta(days=15), UseCase.VALIDATION_RESULT_OK),
            ("Phishing attachment execution", "Email Security", "High", UseCase.STATUS_TEST, True, ["T1566", "T1027"], today - timedelta(days=8), UseCase.VALIDATION_RESULT_NONE),
            ("Ransomware encryption burst", "EDR", "Critical", UseCase.STATUS_PRODUCTION, False, ["T1486"], today - timedelta(days=180), UseCase.VALIDATION_RESULT_FAILED),
            ("Credential dumping attempt", "EDR", "Critical", UseCase.STATUS_PRODUCTION, True, ["T1003"], today - timedelta(days=45), UseCase.VALIDATION_RESULT_OK),
            ("Draft cloud identity monitoring", "Cloud", "Medium", UseCase.STATUS_DEVELOPMENT, True, ["T1078"], None, UseCase.VALIDATION_RESULT_NONE),
        ]
        usecases = {}
        for name, device, severity, status, enabled, attack_ids, checked_at, result in specs:
            production_date = today - timedelta(days=220) if status == UseCase.STATUS_PRODUCTION else None
            usecase, _ = UseCase.objects.update_or_create(
                name=f"{DEMO_PREFIX}{name}",
                defaults={
                    "group_name": "SOC Demo",
                    "device": device,
                    "case_type": "Correlation",
                    "objective": f"[demo] Detectar {name.lower()}.",
                    "blocking_type": "Manual",
                    "owner_name": analyst.username,
                    "lifecycle_control_owner": owner,
                    "monitoring": "24x7",
                    "status": status,
                    "production_date": production_date,
                    "severity": severity,
                    "escalation": "SOC",
                    "sent_to_ho": "No",
                    "last_validation_date": checked_at,
                    "validation_status": UseCase.VALIDATION_STATUS_FINISHED if result != UseCase.VALIDATION_RESULT_NONE else UseCase.VALIDATION_STATUS_NOT_DONE,
                    "validation_result": result,
                    "is_enabled": enabled,
                    "disabled_reason": "[demo] Caso pausado para simular baja operativa." if not enabled else "",
                    "comments": "[demo] Caso generado por seed_demo_data.",
                    "created_by": analyst,
                    "updated_by": analyst,
                },
            )
            usecase.mitre_attacks.set(attacks[item] for item in attack_ids)
            if checked_at:
                usecase.set_lifecycle_review_dates(checked_at)
                usecase.save(update_fields=["last_review_date", "next_review_date"])
            usecase.sync_d3fends_from_attacks()
            usecases[name] = usecase
        return usecases

    def _seed_usecase_sources(self, usecases, sources, users):
        analyst = users["demo_analyst"]
        mapping = {
            "PowerShell suspicious execution": ["DEMO-EDR", "DEMO-SIEM"],
            "Valid accounts impossible travel": ["DEMO-SIEM", "DEMO-CLOUD"],
            "Brute force escalation": ["DEMO-SIEM"],
            "Exfiltration uncommon channel": ["DEMO-NDR", "DEMO-SIEM"],
            "Phishing attachment execution": ["DEMO-EMAIL", "DEMO-EDR"],
            "Ransomware encryption burst": ["DEMO-EDR"],
            "Credential dumping attempt": ["DEMO-EDR", "DEMO-SIEM"],
            "Draft cloud identity monitoring": ["DEMO-CLOUD"],
        }
        for usecase_name, source_codes in mapping.items():
            usecase = usecases[usecase_name]
            selected_sources = [sources[code] for code in source_codes]
            usecase.source_links.exclude(source__in=selected_sources).delete()
            for source in selected_sources:
                UseCaseSource.objects.get_or_create(
                    use_case=usecase,
                    source=source,
                    defaults={
                        "role": UseCaseSource.ROLE_PRIMARY,
                        "is_required": True,
                        "notes": "[demo] Vinculo generado por seed_demo_data.",
                        "created_by": analyst,
                    },
                )

    def _seed_reviews(self, usecases, users):
        owner = users["demo_owner"]
        for key in ("PowerShell suspicious execution", "Valid accounts impossible travel", "Credential dumping attempt"):
            usecase = usecases[key]
            LifecycleReview.objects.update_or_create(
                use_case=usecase,
                checked_at=usecase.last_review_date or date.today(),
                defaults={
                    "control_owner": owner,
                    "completed_by": owner,
                    "status": UseCase.VALIDATION_STATUS_FINISHED,
                    "result": usecase.validation_result,
                    "notes": "[demo] Revision cargada por seed_demo_data.",
                    "next_review_date": usecase.next_review_date,
                },
            )

    def _seed_overrides(self, users):
        admin = users["demo_admin"]
        specs = [
            (CoverageOverride.FRAMEWORK_ATTACK, CoverageOverride.OBJECT_TACTIC, "Initial Access", "Initial Access", CoverageOverride.STATUS_FULFILLED, "[demo] Cubierto por controles perimetrales externos."),
            (CoverageOverride.FRAMEWORK_D3FEND, CoverageOverride.OBJECT_CATEGORY, "Network Monitoring", "Network Monitoring", CoverageOverride.STATUS_DISABLED, "[demo] No aplica en este entorno de prueba."),
        ]
        for framework, object_type, object_key, object_name, status, reason in specs:
            CoverageOverride.objects.update_or_create(
                framework=framework,
                object_type=object_type,
                object_key=object_key,
                defaults={
                    "object_name": object_name,
                    "status": status,
                    "reason": reason,
                    "updated_by": admin,
                },
            )

    def _seed_settings(self):
        active_lifecycle = LifecycleSettings.objects.filter(is_active=True).first()
        lifecycle_active = active_lifecycle is None or active_lifecycle.name == "Demo lifecycle"
        LifecycleSettings.objects.update_or_create(
            name="Demo lifecycle",
            defaults={"review_interval_days": 90, "is_active": lifecycle_active},
        )
        active_report = DashboardReportSettings.objects.filter(is_active=True).first()
        report_active = active_report is None or active_report.name == "Demo dashboard PDF"
        DashboardReportSettings.objects.update_or_create(
            name="Demo dashboard PDF",
            defaults={
                "is_active": report_active,
                "report_title": "Reporte ejecutivo SOC Demo",
                "report_subtitle": "Cobertura ATT&CK y D3FEND con datos demo",
                "footer_text": "SOC Use Cases Manager - Demo",
            },
        )
        active_sync = MitreAttackSyncSettings.objects.filter(is_active=True).first()
        sync_active = active_sync is None or active_sync.name == "Demo MITRE sync"
        MitreAttackSyncSettings.objects.update_or_create(
            name="Demo MITRE sync",
            defaults={
                "is_active": sync_active,
                "interval_value": 24,
                "interval_unit": MitreAttackSyncSettings.UNIT_HOURS,
            },
        )
        LDAPSettings.objects.update_or_create(
            name="Demo LDAP inactive",
            defaults={
                "is_enabled": False,
                "auth_mode": LDAPSettings.AUTH_MODE_LOCAL_ONLY,
                "server_uri": "ldap://ldap.demo.local:389",
                "use_ssl": False,
                "user_search_filter": "(sAMAccountName={username})",
            },
        )
