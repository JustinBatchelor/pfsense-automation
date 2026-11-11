"""Run real controller inventory tasks against an isolated stateful HTTP API."""

import json
import os
from pathlib import Path
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(
    not (ROOT / ".collections/ansible_collections/ansible/controller/MANIFEST.json").exists(),
    reason="Licensed ansible.controller collection required for controller integration",
)


@pytest.fixture
def controller():
    state = {"organizations": [{"id": 1, "name": "Default"}], "inventories": [],
             "hosts": [], "inventory_sources": [], "credentials": [], "writes": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def reply(self, data, code=200):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-API-Product-Name", "Red Hat Ansible Automation Platform")
            self.send_header("X-API-Product-Version", "4.8.12")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())

        def handle_request(self):
            parsed = urlparse(self.path)
            parts = parsed.path.split("/v2/")[-1].strip("/").split("/")
            endpoint = parts[0]
            if endpoint == "me":
                return self.reply({"count": 1, "results": [{"id": 1}], "next": None})
            if endpoint not in state or endpoint == "writes":
                return self.reply({"detail": "Unexpected endpoint"}, 404)
            objects = state[endpoint]
            if self.command == "GET":
                if len(parts) > 1:
                    return self.reply(next(x for x in objects if x["id"] == int(parts[1])))
                query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                for key, value in query.items():
                    if key == "organization__name":
                        objects = [x for x in objects if x.get("organization") == 1 and value == "Default"]
                    elif key == "name__in":
                        objects = [x for x in objects if x.get("name") in value.split(",")]
                    elif key in ("name", "inventory", "organization"):
                        objects = [x for x in objects if str(x.get(key)) == value]
                return self.reply({"count": len(objects), "results": objects, "next": None})
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["writes"].append((self.command, endpoint))
            if self.command == "POST":
                obj = {"id": len(objects) + 1, "kind": "", "variables": "{}", **body}
                obj["url"] = f"/api/v2/{endpoint}/{obj['id']}/"
                objects.append(obj)
                return self.reply(obj, 201)
            obj = next(x for x in objects if x["id"] == int(parts[1]))
            obj.update(body)
            return self.reply(obj)

        do_GET = do_POST = do_PATCH = handle_request

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield state, f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    thread.join()
    server.server_close()


def run_play(tmp_path, url, play, *args):
    path = tmp_path / "play.yml"
    path.write_text(yaml.safe_dump(play))
    env = {k: v for k, v in os.environ.items() if not k.startswith(("CONTROLLER_", "TOWER_", "AAP_"))}
    env.update(CONTROLLER_HOST=url, CONTROLLER_USERNAME="test", CONTROLLER_PASSWORD="test",
               ANSIBLE_LOCAL_TEMP=str(tmp_path / "ansible"), ANSIBLE_NOCOLOR="1")
    p = subprocess.run([str(ROOT / ".tools/bin/ansible-playbook"), str(path), *args],
                       cwd=ROOT, env=env, text=True, capture_output=True, timeout=120)
    assert p.returncode == 0, p.stdout + p.stderr
    return p.stdout


def test_restore_inventory_preserves_manual_variables_and_declarations(controller, tmp_path):
    state, url = controller
    play = [{"name": "Test inventory restoration", "hosts": "localhost", "gather_facts": False,
             "vars_files": [str(ROOT / "vars/defaults.yml")],
             "tasks": [{"name": "Restore inventory", "ansible.builtin.include_role": {
                 "name": "aap_deploy", "tasks_from": "inventory.yml"},
                 "vars": {"aap_inventory_discovery_enabled": False, "aap_inventory_manage_dns_records": False}}]}]
    run_play(tmp_path, url, play)
    assert len(state["inventories"]) == 1 and len(state["hosts"]) == 2
    existing = json.loads(state["inventories"][0]["variables"])
    existing.update(operator_note="preserve", pfsense_dns_records=[{"host": "desired", "domain": "home.arpa"}])
    state["inventories"][0]["variables"] = json.dumps(existing)
    for host in state["hosts"]:
        variables = json.loads(host["variables"])
        variables["operator_note"] = host["name"]
        host["variables"] = json.dumps(variables)
    state["writes"].clear()
    output = run_play(tmp_path, url, play)
    assert "changed=0" in output and state["writes"] == []
    assert json.loads(state["inventories"][0]["variables"]) == existing
    assert all(json.loads(h["variables"])["operator_note"] == h["name"] for h in state["hosts"])


def test_fresh_recovery_check_mode_never_writes_or_launches_jobs(controller, tmp_path):
    state, url = controller
    play = [{"name": "Test fresh recovery preview", "hosts": "localhost", "gather_facts": False,
             "vars_files": [str(ROOT / "vars/defaults.yml")],
             "tasks": [{"name": "Preview recovery", "ansible.builtin.include_role": {
                 "name": "aap_deploy", "tasks_from": "restore_inventory.yml"}, "vars": {
                     "aap_project_url": "https://example.com/repo.git", "aap_project_revision": "a" * 40,
                     "aap_ee_image": "example.com/ee@sha256:" + "b" * 64}}]}]
    run_play(tmp_path, url, play, "--check")
    assert state["writes"] == [] and state["inventories"] == []
