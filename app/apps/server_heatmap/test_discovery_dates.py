from django.test import TestCase

from apps.server_heatmap.connectors.base import InventoryRecord
from apps.server_heatmap.models import InventorySyncRun, ServerAsset
from apps.server_heatmap.reconciliation import synchronize_inventory


class InventoryFirstSeenTests(TestCase):
    class Connector:
        def __init__(self, records):
            self.records = records

        def collect(self):
            return self.records

    def test_first_seen_dates_are_set_once_per_source(self):
        ad_record = InventoryRecord(
            external_id="first-seen-01.ardp.local",
            hostname="first-seen-01",
            fqdn="first-seen-01.ardp.local",
            environment="PROD",
        )
        siem_record = InventoryRecord(
            external_id="first-seen-01",
            hostname="first-seen-01",
            fqdn="first-seen-01.ardp.local",
        )

        synchronize_inventory(
            InventorySyncRun.SOURCE_AD,
            self.Connector([ad_record]),
        )
        asset = ServerAsset.objects.get(hostname="first-seen-01")
        original_ad_first_seen = asset.ad_first_seen_at
        self.assertIsNotNone(original_ad_first_seen)

        synchronize_inventory(
            InventorySyncRun.SOURCE_AD,
            self.Connector([ad_record]),
        )
        asset.refresh_from_db()
        self.assertEqual(asset.ad_first_seen_at, original_ad_first_seen)

        synchronize_inventory(
            InventorySyncRun.SOURCE_SIEM,
            self.Connector([siem_record]),
        )
        asset.refresh_from_db()
        original_siem_first_seen = asset.siem_first_seen_at
        self.assertIsNotNone(original_siem_first_seen)

        synchronize_inventory(
            InventorySyncRun.SOURCE_SIEM,
            self.Connector([siem_record]),
        )
        asset.refresh_from_db()
        self.assertEqual(asset.siem_first_seen_at, original_siem_first_seen)
