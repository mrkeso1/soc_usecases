from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True)
class InventoryRecord:
    external_id: str
    hostname: str = ""
    fqdn: str = ""
    ip_address: str | None = None
    os_name: str = ""
    organizational_unit: str = ""
    environment: str = ""
    groups: str = ""
    server_type_hint: str = ""
    observed_at: datetime | None = None
    raw_data: dict = field(default_factory=dict)
