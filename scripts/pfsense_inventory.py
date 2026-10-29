#!/usr/bin/env python3
"""Read-only pfrest inventory: observed configuration, never desired state."""

import argparse
import ipaddress
import json
import os
import re
import sys

import requests


class DiscoveryError(ValueError):
    """A diagnostic containing neither secrets nor raw API responses."""


def selected(data, fields):
    return {key: data[key] for key in fields if key in data}


def records(data):
    result = []
    for item in data:
        record = selected(item, ("host", "domain", "ip", "descr"))
        record["aliases"] = [selected(alias, ("host", "domain", "descr")) for alias in item.get("aliases") or []]
        result.append(record)
    return result


class Client:
    def __init__(self, env, session=None):
        host = env.get("PFSENSE_API_HOST", "pfsense.batchelor.live")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", host):
            raise DiscoveryError("PFSENSE_API_HOST must be a certificate-matching hostname without a URL or credentials")
        try:
            port = int(env.get("PFSENSE_API_PORT", "443"))
        except ValueError:
            raise DiscoveryError("PFSENSE_API_PORT must be an integer") from None
        if not 1 <= port <= 65535:
            raise DiscoveryError("PFSENSE_API_PORT is outside the valid range")
        key = env.get("PFSENSE_API_KEY")
        if not key:
            raise DiscoveryError("PFSENSE_API_KEY must be injected at runtime")
        self.base = f"https://{host}:{port}/api/v2/"
        self.session = session or requests.Session()
        self.session.headers.update({"X-API-Key": key, "Accept": "application/json"})
        self.verify = env.get("REQUESTS_CA_BUNDLE") or True

    def get(self, path, expected_type):
        try:
            response = self.session.get(
                self.base + path, params={"limit": 0}, timeout=(5, 30),
                verify=self.verify, allow_redirects=False,
            )
        except requests.RequestException:
            raise DiscoveryError(f"Verified HTTPS read failed for {path}; check connectivity and CA trust") from None
        if response.status_code != 200:
            raise DiscoveryError(f"Read of {path} failed with HTTP {response.status_code}; check API read privileges")
        try:
            body = response.json()
        except ValueError:
            raise DiscoveryError(f"Invalid JSON from {path}") from None
        if not isinstance(body, dict) or body.get("code") != 200 or not isinstance(body.get("data"), expected_type):
            raise DiscoveryError(f"Invalid API response schema for {path}")
        return body["data"]


def discover(client):
    hosts = client.get("services/dns_resolver/host_overrides", list)
    settings = client.get("services/dns_resolver/settings", dict)
    domains = client.get("services/dns_resolver/domain_overrides", list)
    servers = client.get("services/dhcp_servers", list)
    # Allowlisted fields keep custom snippets and credential-bearing options out
    # of persisted AAP inventory. Native API field names/types are retained.
    settings_fields = (
        "enable", "port", "tlsport", "active_interface", "outgoing_interface",
        "dnssec", "regdhcp", "regdhcpstatic", "regovpnclients", "forwarding",
        "forward_tls_upstream", "hideidentity", "hideversion", "strictout", "enablessl",
    )
    mapping_fields = (
        "mac", "ipaddr", "cid", "hostname", "domain", "domainsearchlist", "descr",
        "defaultleasetime", "maxleasetime", "gateway", "dnsserver", "winsserver",
        "ntpserver", "arp_table_static_entry",
    )
    ipv4 = {}
    for server in servers:
        interface = server.get("id")
        if not isinstance(interface, str) or not interface or interface in ipv4:
            raise DiscoveryError("DHCP servers must have unique interface IDs")
        mappings = server.get("staticmap")
        if not isinstance(mappings, list):
            raise DiscoveryError("DHCP server response is missing its staticmap list")
        ipv4[interface] = {
            "settings": selected(server, (
                "interface", "enable", "range_from", "range_to", "domain",
                "domainsearchlist", "gateway", "dnsserver", "winsserver", "ntpserver",
            )),
            "reservations": [selected(mapping, mapping_fields) for mapping in mappings],
        }
    return {
        "schema_version": 1,
        "capabilities": {"dhcp_ipv6": False},
        "dns": {"resolver": {
            "host_overrides": records(hosts),
            "settings": selected(settings, settings_fields),
            "domain_overrides": [selected(item, ("domain", "ip", "descr", "tls_hostname")) for item in domains],
        }},
        "dhcp": {"ipv4": ipv4},
    }


def inventory(snapshot, address):
    try:
        ipaddress.ip_address(address)
    except ValueError:
        raise DiscoveryError("PFSENSE_ADDRESS must be the appliance IP address") from None
    if sys.prefix == sys.base_prefix:
        raise DiscoveryError("Run inventory with the project .tools environment or the /opt/venv execution image")
    return {
        "_meta": {"hostvars": {
            "pfsense": {"ansible_host": address},
            "localhost": {"ansible_connection": "local",
                          "ansible_python_interpreter": os.path.join(sys.prefix, "bin", "python")},
        }},
        "all": {"children": ["pfsense_discovery"]},
        "pfsense_discovery": {
            "hosts": ["pfsense", "localhost"],
            "vars": {"pfsense_discovered": snapshot},
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--list", action="store_true")
    mode.add_argument("--host")
    args = parser.parse_args()
    if args.host and args.host not in ("localhost", "pfsense"):
        print("{}")
        return
    try:
        snapshot = discover(Client(os.environ))
        result = inventory(snapshot, os.environ.get("PFSENSE_ADDRESS", "10.45.45.1"))
        if args.host:
            result = {**result["_meta"]["hostvars"][args.host], "pfsense_discovered": snapshot}
        print(json.dumps(result, sort_keys=True))
    except DiscoveryError as exc:
        print(f"pfSense inventory: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
    except (TypeError, KeyError, AttributeError, ValueError):
        print("pfSense inventory: malformed discovery data", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
