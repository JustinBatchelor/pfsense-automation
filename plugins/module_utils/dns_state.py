"""Pure, conservative DNS override planning; shared by action plugins and tests."""

from __future__ import annotations

import ipaddress
import re
from copy import deepcopy


class InvalidState(ValueError):
    """Unsafe or ambiguous desired/existing state."""


def name(value, *, empty=False):
    if not isinstance(value, str):
        raise InvalidState("DNS names must be strings")
    value = value.rstrip(".").lower()
    if empty and not value:
        return value
    if (
        not value
        or len(value) > 253
        or any(
            not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", label)
            for label in value.split(".")
        )
    ):
        raise InvalidState(f"Invalid DNS name: {value!r}")
    return value


def identity(record):
    return name(record.get("host", ""), empty=True), name(record.get("domain"))


def fqdn(record):
    host, domain = identity(record)
    result = f"{host}.{domain}" if host else domain
    if len(result) > 253:
        raise InvalidState("Combined DNS name exceeds 253 characters")
    return result


def canonical(record, *, desired=False):
    if not isinstance(record, dict):
        raise InvalidState("Each record must be a mapping")
    if desired and set(record) - {"host", "domain", "ip", "descr", "aliases", "state"}:
        raise InvalidState("Unknown record fields")
    host, domain = identity(record)
    fqdn(record)
    state = record.get("state", "present")
    if state not in ("present", "absent"):
        raise InvalidState("state must be present or absent")
    result = {"host": host, "domain": domain}
    if desired and state == "absent":
        return {**result, "state": state}
    ips = record.get("ip", [])
    if not isinstance(ips, list) or not ips:
        raise InvalidState("Present records require a nonempty ip list")
    try:
        result["ip"] = sorted({str(ipaddress.ip_address(ip)) for ip in ips})
    except ValueError as exc:
        raise InvalidState("Invalid IPv4 or IPv6 address") from exc
    result["descr"] = record.get("descr") or ""
    if not isinstance(result["descr"], str):
        raise InvalidState("descr must be a string")
    aliases = record.get("aliases") or []
    if not isinstance(aliases, list):
        raise InvalidState("aliases must be a list")
    normalized = []
    for alias in aliases:
        if not isinstance(alias, dict):
            raise InvalidState("Each alias must be a mapping")
        if desired and set(alias) - {"host", "domain", "descr"}:
            raise InvalidState("Unknown alias fields")
        ahost, adomain = identity(alias)
        fqdn(alias)
        descr = alias.get("descr") or ""
        if not isinstance(descr, str):
            raise InvalidState("Alias descr must be a string")
        normalized.append({"host": ahost, "domain": adomain, "descr": descr})
    result["aliases"] = sorted(normalized, key=identity)
    if desired:
        result["state"] = state
    return result


def index(records):
    result = {}
    for record in records:
        key = identity(record)
        if key in result:
            raise InvalidState(f"Ambiguous duplicate override: {fqdn(record)}")
        result[key] = record
    return result


def snapshot(records):
    return {key: canonical(value) for key, value in index(records).items()}


def plan(desired, existing):
    if not isinstance(desired, list) or not isinstance(existing, list):
        raise InvalidState("Records must be lists")
    desired = [canonical(item, desired=True) for item in desired]
    desired_index = index(desired)
    current = index(existing)
    final = snapshot(existing)
    operations = []
    for key, record in desired_index.items():
        before = current.get(key)
        after = (
            None
            if record["state"] == "absent"
            else {k: v for k, v in record.items() if k != "state"}
        )
        if after is None:
            final.pop(key, None)
        else:
            final[key] = after
        if (canonical(before) if before else None) != after:
            operations.append(
                {"key": list(key), "before": deepcopy(before), "after": after}
            )
    # A final configuration may not bind the same name through multiple records/aliases.
    owners = {}
    for key, record in final.items():
        for entry in [record, *record["aliases"]]:
            label = fqdn(entry)
            if label in owners:
                raise InvalidState(f"Conflicting host/alias name: {label}")
            owners[label] = key
    # Deletions precede writes so alias/name transfers do not temporarily collide.
    operations.sort(key=lambda op: (op["after"] is not None, op["key"]))
    return operations


def expected_snapshot(existing, operations):
    result = snapshot(existing)
    for operation in operations:
        key = tuple(operation["key"])
        if operation["after"] is None:
            result.pop(key, None)
        else:
            result[key] = canonical(operation["after"])
    return result
