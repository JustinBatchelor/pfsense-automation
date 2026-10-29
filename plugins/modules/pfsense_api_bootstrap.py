#!/usr/bin/python
"""Bootstrap pfrest through local pfSense PHP APIs, independently of HTTP availability."""

from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from ansible.module_utils.basic import AnsibleModule


def command(args, **kwargs):
    return subprocess.run(
        args, text=True, capture_output=True, check=True, **kwargs
    ).stdout


def main():
    module = AnsibleModule(
        argument_spec={
            "adapter": {"type": "str", "required": True},
            "releases": {"type": "dict", "required": True},
            "owner": {"type": "str", "required": True},
            "username": {"type": "str", "required": True},
            "interfaces": {"type": "list", "elements": "str", "required": True},
            "api_key": {"type": "str", "default": "", "no_log": True},
            "commit": {"type": "bool", "default": False},
        },
        supports_check_mode=True,
    )
    params = module.params
    marker = Path("/conf/aap-pfsense-dns-ownership.json")
    try:
        version = Path("/etc/version").read_text().strip()
        arch = command(["uname", "-m"]).strip()
        release = params["releases"].get(version + "/" + arch)
        if not release:
            module.fail_json(
                msg=f"Unsupported pfSense platform: {version}/{arch}; add a tested release mapping"
            )
        probe = subprocess.run(
            ["pkg", "query", "%v", "pfSense-pkg-RESTAPI"],
            text=True,
            capture_output=True,
        )
        installed = probe.stdout.strip() if probe.returncode == 0 else None
        ownership = json.loads(marker.read_text()) if marker.exists() else None
        if ownership and ownership.get("owner") != params["owner"]:
            module.fail_json(
                msg="Appliance bootstrap belongs to another automation owner"
            )
        if installed and installed != release["package_version"]:
            module.fail_json(
                msg=f"Installed pfrest {installed} differs from tested pin {release['version']}; migrate explicitly"
            )
        managed = ownership is not None or installed is None
        if installed and not managed and not params["api_key"]:
            module.fail_json(
                msg="Externally installed pfrest requires PFSENSE_API_KEY; no credentials were changed"
            )
        payload = {
            "owner": params["owner"],
            "username": params["username"],
            "interfaces": params["interfaces"],
            "api_key": params["api_key"],
            "managed": managed,
            "check": module.check_mode,
            "commit": params["commit"],
        }
        package_changed = False
        if not installed:
            if module.check_mode:
                module.exit_json(
                    changed=True,
                    managed=True,
                    package_required=True,
                    enrollment_required=True,
                )
            # Intent precedes package installation so retries retain ownership after interruption.
            if not marker.exists():
                fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as handle:
                    json.dump({"owner": params["owner"], "status": "pending"}, handle)
            backup = Path("/conf/backup") / f"aap-before-restapi-{time.time_ns()}.xml"
            shutil.copyfile("/conf/config.xml", backup)
            os.chmod(backup, 0o600)
            fd, package = tempfile.mkstemp(suffix=".pkg")
            os.close(fd)
            try:
                command(["/usr/bin/fetch", "-o", package, release["url"]])
                if (
                    hashlib.sha256(Path(package).read_bytes()).hexdigest()
                    != release["sha256"]
                ):
                    raise ValueError("pfrest package checksum mismatch")
                command(["/usr/local/sbin/pkg-static", "add", package])
                package_changed = True
            finally:
                os.unlink(package)
        code = params["adapter"].removeprefix("<?php").strip()
        output = command(["/usr/local/bin/php", "-r", code], input=json.dumps(payload))
        result = json.loads(output)
        if result.get("failed"):
            module.fail_json(msg=result.get("msg", "Bootstrap adapter failed"))
        # The calling task is no_log. Do not add newly generated output to
        # no_log_values: Ansible would replace it before enrollment can use it.
        # Supplied input secrets are already masked by Ansible, so omit them.
        if params["api_key"]:
            result.pop("api_key", None)
        module.exit_json(
            **{
                **result,
                "changed": package_changed or result.get("changed", False),
                "managed": managed,
            }
        )
    except Exception as exc:
        # Never expose subprocess stdin or generated key material.
        module.fail_json(msg=f"Bootstrap failed ({type(exc).__name__}): {str(exc)}")


if __name__ == "__main__":
    main()
