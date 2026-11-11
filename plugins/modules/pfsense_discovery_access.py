#!/usr/bin/python
"""Enroll discovery access over SSH without invoking the DNS bootstrap."""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import subprocess
from typing import Any

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.discovery_access import OWNER, PRIVILEGES, USERNAME, EnrollmentError, enroll

DOCUMENTATION = r"""
module: pfsense_discovery_access
short_description: Enroll a dedicated read-only pfSense discovery account
description:
  - Uses the installed pfrest PHP models through verified SSH.
  - Preserves all existing accounts, keys, API settings and DNS/DHCP configuration.
  - The calling task must use no_log because pending enrollment returns a secret.
options:
  adapter:
    type: str
    required: true
    description: Trusted PHP adapter supplied by the discovery access role.
  credential_exists:
    type: bool
    required: true
    description: Whether the discovery credential exists in AAP.
  commit:
    type: bool
    default: false
    description: Complete enrollment only after a successful AAP inventory sync.
author: Justin Batchelor
"""
EXAMPLES = r"""
- name: Prepare dedicated discovery access
  pfsense_discovery_access:
    adapter: "{{ lookup('file', 'discovery-access.php') }}"
    credential_exists: false
  no_log: true
"""
RETURN = r"""
enrollment_required:
  description: Whether the pending key still needs verified delivery to AAP.
  type: bool
  returned: always
api_key:
  description: Sensitive pending key; returned only during enrollment, under no_log.
  type: str
  returned: when pending outside check mode
"""


class Backend:
    """Invoke the installed pfrest model adapter without exposing its diagnostics."""

    def __init__(self, adapter: str) -> None:
        self.adapter = adapter.removeprefix("<?php").strip()

    def call(self, operation: str, api_key: str = "") -> dict[str, Any]:
        """Execute one adapter operation, with all sensitive data on stdin."""
        payload = {"operation": operation, "owner": OWNER, "username": USERNAME,
                   "privileges": PRIVILEGES, "api_key": api_key}
        result = subprocess.run(["/usr/local/bin/php", "-r", self.adapter],
                                input=json.dumps(payload), text=True, capture_output=True, timeout=60)
        if result.returncode:
            raise EnrollmentError("Discovery PHP adapter failed; inspect protected appliance diagnostics")
        data = json.loads(result.stdout)
        if data.get("failed"):
            raise EnrollmentError("Discovery model operation failed; no automatic retry or key rotation")
        return data

    def inspect(self, api_key: str) -> dict[str, Any]:
        """Read account identity, privileges and key metadata."""
        return self.call("inspect", api_key)

    def create_user(self) -> None:
        """Create only the independently owned read-only account."""
        self.call("create_user")

    def create_key(self) -> dict[str, Any]:
        """Create one owned key; enrollment retains it until AAP validation."""
        return self.call("create_key")


def main() -> None:
    """Validate the installed platform and execute serialized enrollment."""
    module = AnsibleModule(argument_spec={
        "adapter": {"type": "str", "required": True},
        "credential_exists": {"type": "bool", "required": True},
        "commit": {"type": "bool", "default": False},
    }, supports_check_mode=True)
    lock = None
    try:
        if Path("/etc/version").read_text().strip() not in ("2.8.1-RELEASE", "2.9.0-RELEASE"):
            raise EnrollmentError("Unsupported pfSense version for discovery enrollment")
        package = subprocess.run(["pkg", "query", "%v", "pfSense-pkg-RESTAPI"],
                                 text=True, capture_output=True, timeout=30)
        if package.returncode or package.stdout.strip() != "2.10_2":
            raise EnrollmentError("Discovery enrollment requires the existing pfrest 2.10_2 package")
        # Check mode creates neither a lock file nor enrollment state.
        if not module.check_mode:
            lock = os.open("/conf/aap-pfsense-discovery.lock", os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = enroll(Backend(module.params["adapter"]),
                        Path("/conf/aap-pfsense-discovery-enrollment.json"),
                        module.params["credential_exists"], module.check_mode, module.params["commit"])
    except EnrollmentError as exc:
        module.fail_json(msg=str(exc))
    except Exception as exc:
        module.fail_json(msg=f"Discovery enrollment failed ({type(exc).__name__}); secret details suppressed")
    finally:
        if lock is not None:
            os.close(lock)
    module.exit_json(**result)


if __name__ == "__main__":
    main()
