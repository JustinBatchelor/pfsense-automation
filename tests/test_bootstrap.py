"""Bootstrap boundary tests: no writes before platform/ownership validation."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "bootstrap", ROOT / "plugins/modules/pfsense_api_bootstrap.py"
)
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class Finished(BaseException):
    def __init__(self, data):
        self.data = data


def invoke(
    monkeypatch,
    tmp_path,
    *,
    installed=None,
    owner=None,
    key="",
    check=False,
    version="2.8.1-RELEASE",
    php=None
):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/version").write_text(version)
    (tmp_path / "conf").mkdir()
    if owner:
        (tmp_path / "conf/aap-pfsense-dns-ownership.json").write_text(json.dumps(owner))
    params = {
        "adapter": "<?php // adapter",
        "releases": {
            "2.8.1-RELEASE/amd64": {
                "version": "2.10.2",
                "package_version": "2.10_2",
                "url": "https://example.invalid/pinned.pkg",
                "sha256": "invalid",
            }
        },
        "owner": "aap-pfsense-dns-v1",
        "username": "aap-dns",
        "interfaces": ["lan"],
        "api_key": key,
        "commit": False,
    }

    class Module:
        def __init__(self, **kwargs):
            self.params = params
            self.check_mode = check

        def exit_json(self, **data):
            raise Finished(data)

        def fail_json(self, **data):
            raise Finished({"failed": True, **data})

    calls = []

    def command(args, **kwargs):
        calls.append(args)
        if args == ["uname", "-m"]:
            return "amd64\n"
        if args[0] == "/usr/local/bin/php":
            return json.dumps(php or {"changed": False, "api_key": key})
        raise AssertionError("Unexpected mutation command")

    monkeypatch.setattr(bootstrap, "AnsibleModule", Module)
    monkeypatch.setattr(
        bootstrap, "Path", lambda path: tmp_path / str(path).lstrip("/")
    )
    monkeypatch.setattr(bootstrap, "command", command)
    monkeypatch.setattr(
        bootstrap.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(
            returncode=0 if installed else 1, stdout=installed or ""
        ),
    )
    with pytest.raises(Finished) as finish:
        bootstrap.main()
    return finish.value.data, calls


def test_missing_package_preview_does_not_claim_ownership(monkeypatch, tmp_path):
    result, calls = invoke(monkeypatch, tmp_path, check=True)
    assert result["changed"] and result["package_required"]
    assert not list((tmp_path / "conf").iterdir())
    assert calls == [["uname", "-m"]]


def test_external_install_requires_supplied_credential_before_any_mutation(
    monkeypatch, tmp_path
):
    result, calls = invoke(monkeypatch, tmp_path, installed="2.10_2")
    assert result["failed"] and "Externally installed" in result["msg"]
    assert calls == [["uname", "-m"]]


def test_external_install_uses_existing_credential(monkeypatch, tmp_path):
    result, _ = invoke(monkeypatch, tmp_path, installed="2.10_2", key="existing-key")
    assert not result["changed"] and not result["managed"]
    assert (
        "api_key" not in result
    )  # Input secrets must not be returned through Ansible redaction.


def test_pending_enrollment_can_return_new_key_without_redaction(monkeypatch, tmp_path):
    result, _ = invoke(
        monkeypatch,
        tmp_path,
        installed="2.10_2",
        owner={"owner": "aap-pfsense-dns-v1", "status": "pending"},
        php={
            "changed": False,
            "api_key": "pending-test-key",
            "enrollment_required": True,
        },
    )
    assert result["api_key"] == "pending-test-key" and result["enrollment_required"]
    assert not result["changed"] and result["managed"]


@pytest.mark.parametrize(
    "kwargs,reason",
    [
        ({"version": "9.9-RELEASE"}, "Unsupported"),
        ({"installed": "2.11_1", "key": "key"}, "differs"),
        (
            {"installed": "2.10_2", "owner": {"owner": "someone-else"}},
            "another automation owner",
        ),
    ],
)
def test_incompatible_state_fails_without_mutation(
    monkeypatch, tmp_path, kwargs, reason
):
    result, calls = invoke(monkeypatch, tmp_path, **kwargs)
    assert result["failed"] and reason in result["msg"]
    assert calls == [["uname", "-m"]]
