from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase


class VisibleTextEncodingTests(SimpleTestCase):
    mojibake_markers = (chr(0x00C3), chr(0x00C2), chr(0xFFFD))
    scanned_suffixes = {
        ".css",
        ".html",
        ".js",
        ".json",
        ".md",
        ".py",
        ".toml",
        ".txt",
        ".yaml",
        ".yml",
    }
    excluded_parts = {
        ".git",
        ".pytest_cache",
        "__pycache__",
        "migrations",
        "media",
        "staticfiles",
        "logs",
        "soc-control-manager-django-master",
    }

    def test_visible_project_text_has_no_mojibake_markers(self):
        project_root = settings.BASE_DIR.parent
        roots = [
            settings.BASE_DIR / "apps",
            settings.BASE_DIR / "config",
            settings.BASE_DIR / "static",
            settings.BASE_DIR / "templates",
            project_root / "docs",
            project_root / "README.md",
        ]
        offenders = []

        for root in roots:
            if root.is_file():
                candidates = [root]
            elif root.exists():
                candidates = [path for path in root.rglob("*") if path.is_file()]
            else:
                candidates = []

            for path in candidates:
                if path.suffix.lower() not in self.scanned_suffixes:
                    continue
                if any(part in self.excluded_parts for part in path.parts):
                    continue

                content = path.read_text(encoding="utf-8")
                line_hits = [
                    str(index)
                    for index, line in enumerate(content.splitlines(), start=1)
                    if any(marker in line for marker in self.mojibake_markers)
                ]
                if line_hits:
                    offenders.append(f"{path.relative_to(project_root)}:{','.join(line_hits)}")

        self.assertEqual(offenders, [], "Mojibake visible encontrado en archivos activos.")
