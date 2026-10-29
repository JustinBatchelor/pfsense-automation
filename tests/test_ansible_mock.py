"""Exercise the real collection against an HTTP fake; no firewall required."""

import copy
import json
import os
from pathlib import Path
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def api():
    state = {
        "records": [],
        "calls": [],
        "applied": True,
        "fail_host": None,
        "forbidden": False,
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, data, code=200):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "code": code,
                        "status": "ok" if code == 200 else "error",
                        "response_id": "SUCCESS" if code == 200 else "ERROR",
                        "message": "mock response",
                        "data": data,
                    }
                ).encode()
            )

        def handle_request(self):
            path = urlparse(self.path)
            state["calls"].append((self.command, path.path))
            if state["forbidden"] or self.headers.get("X-API-Key") != "test-key":
                return self.reply({}, 403)
            body = json.loads(
                self.rfile.read(int(self.headers.get("Content-Length", 0))) or "{}"
            )
            if path.path.endswith("/apply"):
                if self.command == "POST":
                    state["applied"] = True
                return self.reply({"applied": state["applied"]})
            if self.command == "GET":
                records = copy.deepcopy(state["records"])
                query = {key: values[0] for key, values in parse_qs(path.query).items()}
                query.update(body or {})
                for key, value in query.items():
                    if key in ("host", "domain"):
                        records = [r for r in records if r[key] == value]
                return self.reply(records)
            if state["fail_host"] and body.get("host") == state["fail_host"]:
                return self.reply({}, 500)
            if self.command == "POST":
                obj = {
                    k: v
                    for k, v in body.items()
                    if k not in ("apply", "async", "dry_run")
                }
                obj["id"] = max([r["id"] for r in state["records"]] + [-1]) + 1
                state["records"].append(obj)
            elif self.command == "PATCH":
                obj = next(r for r in state["records"] if r["id"] == body["id"])
                obj.update(
                    {
                        k: v
                        for k, v in body.items()
                        if k not in ("apply", "async", "dry_run")
                    }
                )
            elif self.command == "DELETE":
                state["records"] = [
                    r for r in state["records"] if r["id"] != body["id"]
                ]
                obj = {}
            else:
                return self.reply({}, 405)
            state["applied"] = False
            return self.reply(obj)

        do_GET = handle_request
        do_POST = handle_request
        do_PATCH = handle_request
        do_DELETE = handle_request

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield state, server.server_address[1]
    server.shutdown()
    thread.join()
    server.server_close()


def run(tmp_path, api, records, *, check=False, survey=None):
    _, port = api
    play = [
        {
            "name": "Mock integration",
            "hosts": "localhost",
            "gather_facts": False,
            "tasks": [
                {
                    "name": "Reconcile",
                    "pfsense_dns_reconcile": {
                        "api_host": "127.0.0.1",
                        "api_port": port,
                        "api_protocol": "http",
                        "api_key": "test-key",
                        "records": records,
                        "survey": survey,
                    },
                }
            ],
        }
    ]
    path = tmp_path / "play.json"
    path.write_text(json.dumps(play))
    env = {
        **os.environ,
        "ANSIBLE_CONFIG": str(ROOT / "ansible.cfg"),
        "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible-tmp"),
        "ANSIBLE_ROLES_PATH": str(ROOT / "roles"),
        "ANSIBLE_ACTION_PLUGINS": str(ROOT / "plugins/action"),
        "ANSIBLE_MODULE_UTILS": str(ROOT / "plugins/module_utils"),
        "ANSIBLE_LIBRARY": str(ROOT / "plugins/modules"),
        "ANSIBLE_COLLECTIONS_PATH": str(ROOT / ".collections"),
    }
    args = [
        str(ROOT / ".tools/bin/ansible-playbook"),
        "-i",
        str(ROOT / "inventory.yml"),
        str(path),
    ]
    if check:
        args.append("--check")
    result = subprocess.run(args, cwd=ROOT, env=env, text=True, capture_output=True)
    return result


def rec(host="new", **kwargs):
    return {
        "host": host,
        "domain": "automation.test",
        "ip": ["192.0.2.1"],
        "aliases": [],
        "descr": "",
        **kwargs,
    }


def writes(state):
    return [c for c in state["calls"] if c[0] != "GET"]


def test_create_repeat_update_delete_and_both_input_styles(tmp_path, api):
    state, _ = api
    state["records"] = [dict(rec("pfsense"), id=0)]
    original = copy.deepcopy(state["records"])
    result = run(tmp_path, api, [rec()])
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(writes(state)) == 2  # create plus one apply
    assert state["records"][0] == original[0]
    state["calls"].clear()
    result = run(tmp_path, api, [rec("pfsense"), rec()])
    assert result.returncode == 0, result.stdout + result.stderr
    assert not writes(state)
    state["calls"].clear()
    result = run(tmp_path, api, [rec(ip=["192.0.2.2"])])
    assert result.returncode == 0, result.stdout + result.stderr
    assert writes(state) == [
        ("PATCH", "/api/v2/services/dns_resolver/host_override"),
        ("POST", "/api/v2/services/dns_resolver/apply"),
    ]
    assert next(r for r in state["records"] if r["host"] == "new")["ip"] == ["192.0.2.2"]
    result = run(tmp_path, api, [rec(state="absent")])
    assert result.returncode == 0, result.stdout + result.stderr
    assert state["records"] == original
    state["calls"].clear()
    result = run(
        tmp_path, api, [{"host": "new", "domain": "automation.test", "state": "absent"}]
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert not writes(state)


def test_check_mode_never_issues_writes(tmp_path, api):
    state, _ = api
    result = run(tmp_path, api, [rec()], check=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not writes(state) and not state["records"]


def test_partial_failure_rolls_back_only_own_records(tmp_path, api):
    state, _ = api
    state["fail_host"] = "z-fail"
    state["records"] = [dict(rec("untouched"), id=0)]
    original = copy.deepcopy(state["records"])
    result = run(tmp_path, api, [rec("a-created"), rec("z-fail")])
    assert result.returncode != 0
    assert state["records"] == original and state["applied"]


@pytest.mark.parametrize("reason", ["pending", "auth"])
def test_preflight_failures_issue_no_writes(tmp_path, api, reason):
    state, _ = api
    if reason == "pending":
        state["applied"] = False
    else:
        state["forbidden"] = True
    result = run(tmp_path, api, [rec()])
    assert result.returncode != 0 and not writes(state)


@pytest.mark.parametrize("kind,address,kept", [
    ("A", "192.0.2.99", "2001:db8::1"),
    ("AAAA", "2001:db8::99", "192.0.2.1"),
])
def test_survey_patches_existing_family_and_preserves_other_data(tmp_path, api, kind, address, kept):
    state, _ = api
    existing = dict(rec(ip=["192.0.2.1", "2001:db8::1"], descr="keep", aliases=[
        {"host": "alias", "domain": "automation.test", "descr": "preserve"},
    ]), id=7)
    unrelated = dict(rec("untouched"), id=2)
    state["records"] = [copy.deepcopy(unrelated), copy.deepcopy(existing)]
    survey = {"host": "new", "domain": "automation.test", "type": kind, "address": address}
    result = run(tmp_path, api, [], survey=survey, check=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not writes(state) and state["records"] == [unrelated, existing]
    result = run(tmp_path, api, [], survey=survey)
    assert result.returncode == 0, result.stdout + result.stderr
    assert writes(state) == [
        ("PATCH", "/api/v2/services/dns_resolver/host_override"),
        ("POST", "/api/v2/services/dns_resolver/apply"),
    ]
    assert state["records"][0] == unrelated
    after = state["records"][1]
    assert after["id"] == 7 and set(after["ip"]) == {address, kept}
    assert after["aliases"] == existing["aliases"] and after["descr"] == "keep"
    state["calls"].clear()
    result = run(tmp_path, api, [], survey=survey)
    assert result.returncode == 0, result.stdout + result.stderr
    assert not writes(state)


def test_survey_address_family_mismatch_never_writes(tmp_path, api):
    state, _ = api
    result = run(tmp_path, api, [], survey={
        "host": "new", "domain": "automation.test", "type": "AAAA", "address": "192.0.2.1",
    })
    assert result.returncode != 0 and not writes(state)
