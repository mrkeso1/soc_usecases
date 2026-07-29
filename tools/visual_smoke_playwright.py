"""Playwright smoke checks for critical UI pages.

Usage:
    VISUAL_USER=demo_admin VISUAL_PASSWORD=demo python tools/visual_smoke_playwright.py

Optional env vars:
    BASE_URL=http://localhost:8000
    VISUAL_ARTIFACT_DIR=visual-artifacts
"""

import os
from pathlib import Path

from playwright.sync_api import Error, expect, sync_playwright


BASE_URL = os.getenv("BASE_URL", "http://localhost:8000").rstrip("/")
USERNAME = os.getenv("VISUAL_USER", "demo_admin")
PASSWORD = os.getenv("VISUAL_PASSWORD", "Demo12345!")
ARTIFACT_DIR = Path(os.getenv("VISUAL_ARTIFACT_DIR", "visual-artifacts"))

PAGES = [
    ("dashboard", "/dashboard/", ".ops-dashboard"),
    ("dashboard-mitre", "/dashboard/mitre/", ".page-title"),
    ("inventory", "/usecases/", ".data-table"),
    ("sources", "/sources/", ".data-table"),
    ("lifecycle", "/lifecycle/", ".lifecycle-page"),
    ("reports", "/reports/", ".report-grid"),
    ("audit", "/audit/", ".data-table"),
    ("sigma", "/sigma/epl-to-sigma/", "form"),
    ("server-heatmap", "/servers/", ".heatmap-shell"),
    ("server-administration", "/servers/administration/", ".admin-grid"),
    ("server-rules", "/servers/administration/filters/", ".filter-table-shell"),
]


def login(page):
    page.goto(f"{BASE_URL}/login/", wait_until="domcontentloaded")
    if "/login/" not in page.url:
        return
    page.fill("input[name='username']", USERNAME)
    page.fill("input[name='password']", PASSWORD)
    page.click("button[type='submit']")
    page.wait_for_load_state("networkidle")


def assert_title_readable(page, slug):
    title = page.locator(".page-title, .ops-title, h1").first
    expect(title).to_be_visible(timeout=10_000)
    box = title.bounding_box()
    if not box:
        raise AssertionError(f"{slug}: no se pudo medir el titulo")
    if box["height"] > 96:
        raise AssertionError(f"{slug}: titulo demasiado alto ({box['height']:.1f}px)")
    if box["width"] < 120:
        raise AssertionError(f"{slug}: titulo demasiado angosto ({box['width']:.1f}px)")


def main():
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    console_errors = []
    failed = []

    with sync_playwright() as p:
        browser = p.chromium.launch()
        context = browser.new_context(viewport={"width": 1440, "height": 960})
        page = context.new_page()
        page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)

        login(page)

        for slug, path, selector in PAGES:
            try:
                page.goto(f"{BASE_URL}{path}", wait_until="networkidle")
                if "/login/" in page.url:
                    raise AssertionError("redirigio a login; revisar credenciales VISUAL_USER/VISUAL_PASSWORD")
                expect(page.locator(selector).first).to_be_visible(timeout=10_000)
                assert_title_readable(page, slug)
                page.screenshot(path=str(ARTIFACT_DIR / f"{slug}.png"), full_page=True)
            except (AssertionError, Error) as exc:
                failed.append(f"{slug}: {exc}")

        browser.close()

    if console_errors:
        failed.append("Errores de consola:\n" + "\n".join(console_errors[:20]))
    if failed:
        raise SystemExit("\n\n".join(failed))

    print(f"OK visual smoke. Screenshots en {ARTIFACT_DIR}")


if __name__ == "__main__":
    main()
