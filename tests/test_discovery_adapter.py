"""Check the PHP/Python enrollment response contract without real appliance writes."""

import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

import discovery_access

ROOT = Path(__file__).resolve().parents[1]
sys.modules["ansible.module_utils.discovery_access"] = discovery_access
SPEC = importlib.util.spec_from_file_location("discovery_adapter", ROOT / "plugins/modules/pfsense_discovery_access.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


@pytest.mark.parametrize("response", ["[]", "null", '"test-secret"'])
def test_non_object_response_is_rejected_without_exposing_output(monkeypatch, response):
    monkeypatch.setattr(MODULE.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout=response))
    with pytest.raises(discovery_access.EnrollmentError, match="invalid response object") as exc:
        MODULE.Backend("<?php").create_user()
    assert "test-secret" not in str(exc.value)


def test_empty_success_object_is_accepted(monkeypatch):
    monkeypatch.setattr(MODULE.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout="{}"))
    assert MODULE.Backend("<?php").create_user() is None


def test_php_create_user_returns_an_object_using_mock_models():
    executable = os.environ.get("PHP_TEST_BIN") or shutil.which("php")
    if not executable:
        pytest.skip("PHP CLI required for adapter fixture test")
    # These classes replace the pfrest models entirely: no appliance files, APIs,
    # users or keys are accessed, even when using a remote PHP interpreter.
    stubs = r"""
namespace RESTAPI\Core { class Auth {} }
namespace RESTAPI\Models {
    class User {
        public function __construct(public array $data = []) {}
        public static function query($filter) {
            return new class { public function exists() { return false; } };
        }
        public function create() {
            if ($this->data['name'] !== 'aap-discovery' || count($this->data['priv']) !== 4) {
                throw new \Exception('Invalid test account');
            }
        }
    }
    class RESTAPIKey {
        public static function query($filter) { return (object)['model_objects' => []]; }
    }
}
"""
    adapter = (ROOT / "roles/pfsense_discovery_access/files/discovery-access.php").read_text()
    adapter = adapter.removeprefix("<?php").replace("require_once 'RESTAPI/autoloader.inc';", "")
    code = stubs + "\nnamespace {\n" + adapter + "\n}"
    payload = {"operation": "create_user", "username": discovery_access.USERNAME,
               "owner": discovery_access.OWNER, "privileges": discovery_access.PRIVILEGES, "api_key": ""}
    command = [executable] + shlex.split(os.environ.get("PHP_TEST_ARGS", ""))
    result = subprocess.run(command + ["-r", code], input=json.dumps(payload),
                            text=True, capture_output=True, check=True)
    assert json.loads(result.stdout) == {}
