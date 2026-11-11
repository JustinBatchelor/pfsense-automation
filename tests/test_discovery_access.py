"""Exercise enrollment recovery with a stateful, independently implemented backend."""

import copy
import json
import stat

import pytest

from discovery_access import OWNER, PRIVILEGES, EnrollmentError, enroll


class Appliance:
    def __init__(self):
        self.user = None
        self.keys = []
        self.calls = []
        self.unrelated = {"dns": ["server.home.arpa"], "dhcp": ["reservation"],
                          "accounts": ["admin", "aap-dns"], "settings": {"read_only": False}}

    def inspect(self, key):
        return {"user": copy.deepcopy(self.user), "keys": copy.deepcopy(self.keys),
                "valid_key_id": 7 if key == "test-secret-key" and self.keys else None}

    def create_user(self):
        self.calls.append("create_user")
        self.user = {"owner": OWNER, "privileges": PRIVILEGES.copy(), "disabled": False, "groups": []}

    def create_key(self):
        self.calls.append("create_key")
        self.keys = [{"id": 7, "owner": OWNER}]
        return {"api_key": "test-secret-key", "key_id": 7}


def test_fresh_enrollment_delivery_retry_commit_and_unchanged_rerun(tmp_path):
    appliance = Appliance()
    before = copy.deepcopy(appliance.unrelated)
    path = tmp_path / "enrollment.json"
    result = enroll(appliance, path, False)
    assert result == {"changed": True, "enrollment_required": True, "api_key": "test-secret-key"}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    for credential_exists in (False, True):
        retry = enroll(appliance, path, credential_exists)
        assert not retry["changed"] and retry["api_key"] == result["api_key"]
    assert enroll(appliance, path, True, commit=True)["changed"]
    assert "test-secret-key" not in path.read_text()
    assert enroll(appliance, path, True) == {"changed": False, "enrollment_required": False}
    assert enroll(appliance, path, True, commit=True)["changed"] is False
    assert appliance.calls == ["create_user", "create_key"]
    assert appliance.unrelated == before


def test_fresh_and_pending_check_mode_never_write_or_return_secrets(tmp_path):
    appliance = Appliance()
    path = tmp_path / "enrollment.json"
    assert enroll(appliance, path, False, check=True)["changed"]
    assert not path.exists() and not appliance.calls
    enroll(appliance, path, False)
    before = path.read_bytes()
    calls = appliance.calls.copy()
    result = enroll(appliance, path, True, check=True, commit=True)
    assert "api_key" not in result and result["changed"]
    assert path.read_bytes() == before and appliance.calls == calls


@pytest.mark.parametrize("credential_exists", [False, True])
def test_account_collision_never_takes_over_user(tmp_path, credential_exists):
    appliance = Appliance()
    appliance.create_user()
    appliance.calls.clear()
    with pytest.raises(EnrollmentError, match="take over"):
        enroll(appliance, tmp_path / "enrollment.json", credential_exists)
    assert not appliance.calls and not list(tmp_path.iterdir())


def test_existing_controller_credential_without_ownership_fails_closed(tmp_path):
    appliance = Appliance()
    with pytest.raises(EnrollmentError, match="without enrollment ownership"):
        enroll(appliance, tmp_path / "enrollment.json", True)
    assert not appliance.calls and not list(tmp_path.iterdir())


def test_missing_enrolled_credential_never_rotates_key(tmp_path):
    appliance = Appliance()
    path = tmp_path / "enrollment.json"
    enroll(appliance, path, False)
    enroll(appliance, path, True, commit=True)
    before = path.read_bytes()
    with pytest.raises(EnrollmentError, match="refusing automatic key rotation"):
        enroll(appliance, path, False)
    assert appliance.calls == ["create_user", "create_key"] and path.read_bytes() == before


@pytest.mark.parametrize("boundary", ["intent", "user"])
def test_interrupted_creation_resumes_without_duplicate_user(tmp_path, boundary):
    appliance = Appliance()
    path = tmp_path / "enrollment.json"
    path.write_text(json.dumps({"owner": OWNER, "status": "pending"}))
    if boundary == "user":
        appliance.create_user()
    enroll(appliance, path, False)
    assert appliance.calls == ["create_user", "create_key"]


def test_key_creation_without_escrow_requires_explicit_recovery(tmp_path):
    appliance = Appliance()
    path = tmp_path / "enrollment.json"
    path.write_text(json.dumps({"owner": OWNER, "status": "pending"}))
    appliance.create_user()
    appliance.create_key()
    with pytest.raises(EnrollmentError, match="without escrow"):
        enroll(appliance, path, False)
    assert appliance.calls == ["create_user", "create_key"]


@pytest.mark.parametrize("drift", ["privileges", "disabled", "groups", "key", "owner"])
def test_pending_drift_never_mutates_or_exposes_key(tmp_path, drift):
    appliance = Appliance()
    path = tmp_path / "enrollment.json"
    enroll(appliance, path, False)
    if drift == "key":
        appliance.keys = []
    elif drift == "owner":
        appliance.user["owner"] = "other"
    elif drift == "privileges":
        appliance.user["privileges"].append("page-all")
    elif drift == "disabled":
        appliance.user["disabled"] = True
    else:
        appliance.user["groups"] = ["admins"]
    before = path.read_bytes()
    with pytest.raises(EnrollmentError) as exc:
        enroll(appliance, path, True)
    assert "test-secret-key" not in str(exc.value)
    assert path.read_bytes() == before and appliance.calls == ["create_user", "create_key"]


def test_commit_requires_controller_delivery(tmp_path):
    appliance = Appliance()
    path = tmp_path / "enrollment.json"
    enroll(appliance, path, False)
    before = path.read_bytes()
    with pytest.raises(EnrollmentError, match="Cannot complete"):
        enroll(appliance, path, False, commit=True)
    assert path.read_bytes() == before
