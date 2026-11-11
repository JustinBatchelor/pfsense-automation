"""Recoverable enrollment for a separately owned, read-only pfrest account."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any

OWNER = "aap-pfsense-discovery-v1"
USERNAME = "aap-discovery"
PRIVILEGES = sorted([
    "api-v2-services-dns-resolver-host-overrides-get",
    "api-v2-services-dns-resolver-settings-get",
    "api-v2-services-dns-resolver-domain-overrides-get",
    "api-v2-services-dhcp-servers-get",
])


class EnrollmentError(ValueError):
    """A safe diagnostic without raw API data or credentials."""


def save_state(path: Path, state: dict[str, Any]) -> None:
    """Atomically persist enrollment state with owner-only permissions."""
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(state, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def enroll(backend: Any, path: Path, credential_exists: bool,
           check: bool = False, commit: bool = False) -> dict[str, Any]:
    """Prepare or commit enrollment; callers serialize writes and verify AAP sync.

    :param backend: Adapter exposing inspect, create_user and create_key methods.
    :param path: Private appliance enrollment record, separate from DNS bootstrap.
    :param credential_exists: Whether the named AAP credential already exists.
    :param check: Inspect and predict without mutating files or the appliance.
    :param commit: Clear escrow only after a successful AAP inventory update.
    :returns: Change status and, only while pending, a key for no_log enrollment.
    """
    state = json.loads(path.read_text()) if path.exists() else None
    if state is not None and (state.get("owner") != OWNER or state.get("status") not in ("pending", "enrolled")):
        raise EnrollmentError("Discovery enrollment ownership or state is invalid")
    observed = backend.inspect((state or {}).get("api_key", ""))
    user, keys = observed["user"], observed["keys"]
    if user:
        if not state or user["owner"] != OWNER:
            raise EnrollmentError("Refusing to take over an existing discovery account")
        if (sorted(user["privileges"]) != PRIVILEGES or user["disabled"] or user["groups"]):
            raise EnrollmentError("Discovery account privileges or membership drifted; review explicitly")
    elif state and state["status"] == "enrolled":
        raise EnrollmentError("Enrolled discovery account is missing; explicit recovery required")
    if state and state["status"] == "enrolled":
        if not credential_exists:
            raise EnrollmentError("Enrolled discovery credential is missing in AAP; refusing automatic key rotation")
        if len(keys) != 1 or keys[0]["fingerprint"] != state.get("key_fingerprint") or keys[0]["owner"] != OWNER:
            raise EnrollmentError("Enrolled discovery key changed; explicit recovery required")
        return {"changed": False, "enrollment_required": False}
    if not state and credential_exists:
        raise EnrollmentError("AAP discovery credential already exists without enrollment ownership")
    pending_key = (state or {}).get("api_key")
    if pending_key:
        if (not user or len(keys) != 1 or keys[0]["owner"] != OWNER
                or keys[0]["fingerprint"] != state.get("key_fingerprint")
                or observed.get("valid_key_fingerprint") != state.get("key_fingerprint")):
            raise EnrollmentError("Pending discovery key does not match the owned account")
    elif keys:
        raise EnrollmentError("Discovery key exists without escrow; explicit recovery required")
    if commit:
        if not pending_key or not credential_exists:
            raise EnrollmentError("Cannot complete enrollment without escrow and its AAP credential")
        if not check:
            save_state(path, {"owner": OWNER, "status": "enrolled", "key_fingerprint": state["key_fingerprint"]})
        return {"changed": True, "enrollment_required": False}
    if check:
        return {"changed": not bool(pending_key), "enrollment_required": True}
    changed = False
    if not state:
        state = {"owner": OWNER, "status": "pending"}
        save_state(path, state)
        changed = True
    if not user:
        backend.create_user()
        changed = True
    if not pending_key:
        created = backend.create_key()
        state.update(api_key=created["api_key"], key_fingerprint=created["key_fingerprint"])
        save_state(path, state)
        changed = True
    return {"changed": changed, "enrollment_required": True, "api_key": state["api_key"]}
