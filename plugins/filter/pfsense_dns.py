"""Produce stable, editable declarations from API readback."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "module_utils"))
from dns_state import canonical, identity  # noqa: E402


class FilterModule:
    def filters(self):
        return {
            "pfsense_dns_normalize": lambda records: sorted(
                [canonical(r) for r in records], key=identity
            )
        }
