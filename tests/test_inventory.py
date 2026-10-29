"""Exercise the executable inventory through verified HTTPS and Ansible."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("pfsense_inventory", ROOT / "scripts/pfsense_inventory.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@pytest.fixture
def api(tmp_path):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost",
    ], check=True, capture_output=True)
    state = {"calls": [], "forbidden": False, "redirect": False}
    data = {
        "/api/v2/services/dns_resolver/host_overrides": [
            {"id": 0, "host": "server", "domain": "home.arpa", "ip": ["192.0.2.1"], "descr": "",
             "aliases": [{"id": 2, "host": "alias", "domain": "home.arpa", "descr": ""}]},
        ],
        "/api/v2/services/dns_resolver/settings": {"enable": True, "custom_options": "secret-custom-content"},
        "/api/v2/services/dns_resolver/domain_overrides": [],
        "/api/v2/services/dhcp_servers": [
            {"id": "lan", "interface": "lan", "enable": True, "range_from": "192.0.2.100",
             "range_to": "192.0.2.200", "secret": "must-not-export", "staticmap": [
                 {"id": 5, "mac": "02:00:00:00:00:01", "ipaddr": "192.0.2.1", "hostname": "server",
                  "ddnsdomainkey": "must-not-export", "descr": "Reserved"},
             ]},
            {"id": "opt1", "interface": "opt1", "staticmap": []},
        ],
    }
    state["data"] = data

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            path = urlparse(self.path).path
            state["calls"].append((self.command, path))
            if state["redirect"]:
                self.send_response(302)
                self.send_header("Location", "/redirected")
                self.end_headers()
                return
            status = 403 if state["forbidden"] or self.headers.get("X-API-Key") != "test-inventory-key" else 200
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"code": status, "data": data.get(path),
                                        "message": "test-inventory-key must never enter diagnostics"}).encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env = {**os.environ, "PFSENSE_API_HOST": "localhost", "PFSENSE_API_PORT": str(server.server_address[1]),
           "PFSENSE_API_KEY": "test-inventory-key", "REQUESTS_CA_BUNDLE": str(cert),
           "NO_PROXY": "*", "no_proxy": "*", "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible-tmp"),
           "PATH": str(ROOT / ".tools/bin") + os.pathsep + os.environ["PATH"],
           "ANSIBLE_INVENTORY_ANY_UNPARSED_IS_FAILED": "true"}
    yield state, env
    server.shutdown()
    thread.join()
    server.server_close()


def invoke(env, *args):
    return subprocess.run([str(ROOT / ".tools/bin/python"), str(ROOT / "scripts/pfsense_inventory.py"), *args],
                          env=env, cwd=ROOT, text=True, capture_output=True)


def test_inventory_available_to_ansible_without_becoming_desired_state(api):
    state, env = api
    before = copy.deepcopy(state["data"])
    p = subprocess.run([str(ROOT / ".tools/bin/ansible-inventory"), "-i", "scripts/pfsense_inventory.py", "--list"],
                       cwd=ROOT, env=env, text=True, capture_output=True)
    assert p.returncode == 0, p.stderr
    result = json.loads(p.stdout)
    assert result["_meta"]["hostvars"]["localhost"]["ansible_python_interpreter"] == str(ROOT / ".tools/bin/python")
    for host in ("localhost", "pfsense"):
        variables = result["_meta"]["hostvars"][host]
        observed = variables["pfsense_discovered"]
        assert len(observed["dns"]["resolver"]["host_overrides"]) == 1
        assert observed["dhcp"]["ipv4"]["lan"]["reservations"][0]["mac"] == "02:00:00:00:00:01"
        assert observed["dhcp"]["ipv4"]["opt1"]["reservations"] == []
        assert "pfsense_dns_records" not in variables
        assert observed["capabilities"]["dhcp_ipv6"] is False
    assert "test-inventory-key" not in p.stdout + p.stderr
    assert "must-not-export" not in p.stdout and "secret-custom-content" not in p.stdout
    assert state["data"] == before and len(state["calls"]) == 4
    assert all(method == "GET" for method, _ in state["calls"])
    state["calls"].clear()
    again = invoke(env, "--list")
    assert again.returncode == 0 and len(state["calls"]) == 4
    one = invoke(env, "--host", "pfsense")
    assert json.loads(one.stdout)["pfsense_discovered"] == observed


@pytest.mark.parametrize("failure", ["forbidden", "redirect", "untrusted", "malformed"])
def test_inventory_fails_closed_without_leaking_api_key(api, failure):
    state, env = api
    if failure == "untrusted":
        env = {k: v for k, v in env.items() if k != "REQUESTS_CA_BUNDLE"}
    elif failure == "malformed":
        state["data"]["/api/v2/services/dhcp_servers"][0].pop("staticmap")
    else:
        state[failure] = True
    p = invoke(env, "--list")
    assert p.returncode != 0 and not p.stdout
    assert "test-inventory-key" not in p.stderr
    assert not any(path == "/redirected" for _, path in state["calls"])


def test_missing_credential_and_invalid_host_fail_before_network():
    with pytest.raises(MODULE.DiscoveryError, match="runtime"):
        MODULE.Client({})
    with pytest.raises(MODULE.DiscoveryError, match="hostname"):
        MODULE.Client({"PFSENSE_API_KEY": "test", "PFSENSE_API_HOST": "https://user:secret@example.com"})
