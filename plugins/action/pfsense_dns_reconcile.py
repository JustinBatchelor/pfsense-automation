"""Execute an explicitly planned, per-record pfrest transaction.

Read-only check mode is enforced here rather than delegated to dependencies.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from ansible.plugins.action import ActionBase
from ansible.errors import AnsibleActionFail

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "module_utils"))
from dns_state import (
    canonical,
    expected_snapshot,
    identity,
    index,
    plan,
    snapshot,
)  # noqa: E402


class ActionModule(ActionBase):
    TRANSFERS_FILES = False

    def run(self, tmp=None, task_vars=None):
        result = super().run(tmp, task_vars)
        self.task_vars = task_vars
        args = self._task.args.copy()
        desired = args.pop("records", [])
        verify_only = args.pop("verify_only", False)
        dns_server = args.pop("dns_server", None)
        self.api = args
        # The collection's default password is the literal "pfsense". Even with
        # key auth, Ansible redacts matching hostnames in returned DNS data.
        self.api.update(api_username="", api_password="")
        self.calls = 0
        try:
            existing = self.read()
            changes = plan(desired, existing)
            pending = self.call("services_dns_resolver_apply_info")["data"]
            if not pending.get("applied", False):
                raise ValueError(
                    "Unrelated or interrupted pending resolver changes exist; recover before running"
                )
            summary = [
                {
                    "name": ".".join(filter(None, op["key"])),
                    "operation": (
                        "delete"
                        if op["after"] is None
                        else "create" if op["before"] is None else "update"
                    ),
                }
                for op in changes
            ]
            result.update(changed=bool(changes), planned_changes=summary, apply_count=0)
            if verify_only:
                if changes:
                    raise ValueError("Saved overrides differ from declared state")
                return result
            if self._play_context.check_mode or not changes:
                return result
            attempted = []
            try:
                for operation in changes:
                    # Check the entire snapshot before each write to detect intervening edits.
                    if snapshot(self.read()) != expected_snapshot(existing, attempted):
                        raise ValueError(
                            "Concurrent configuration change detected; stopped before next write"
                        )
                    attempted.append(operation)
                    self.write(operation)
                if snapshot(self.read()) != expected_snapshot(existing, changes):
                    raise ValueError(
                        "Configuration readback did not match the planned transaction"
                    )
                self.call("services_dns_resolver_apply")
                self.wait_applied()
                result["apply_count"] = 1
                if dns_server:
                    for attempt in range(6):
                        verified = self._execute_module(
                            module_name="pfsense_dns_verify",
                            module_args={"records": desired, "server": dns_server},
                            task_vars=self.task_vars,
                        )
                        if not verified.get("failed"):
                            break
                        if attempt == 5:
                            raise ValueError(
                                "Live DNS verification failed after apply: "
                                + verified.get("msg", "unknown error")
                            )
                        time.sleep(2)
                return result
            except Exception as exc:
                rollback_errors = []
                restored = 0
                for operation in reversed(attempted):
                    try:
                        present = index(self.read()).get(tuple(operation["key"]))
                        actual = canonical(present) if present else None
                        before = (
                            canonical(operation["before"])
                            if operation["before"]
                            else None
                        )
                        if actual == before:
                            continue
                        if actual != operation["after"]:
                            raise ValueError(
                                "Current record no longer matches this job's write"
                            )
                        self.write(
                            {
                                "key": operation["key"],
                                "before": present,
                                "after": before,
                            }
                        )
                        restored += 1
                    except Exception as rollback_exc:
                        rollback_errors.append(str(rollback_exc))
                try:
                    # Never apply another writer's changes, including changes to unrelated records.
                    if snapshot(self.read()) != snapshot(existing):
                        raise ValueError(
                            "Snapshot differs from before-state; manual recovery required"
                        )
                    if attempted:
                        self.call("services_dns_resolver_apply")
                        self.wait_applied()
                except Exception as rollback_exc:
                    rollback_errors.append(str(rollback_exc))
                result.update(
                    failed=True,
                    changed=bool(attempted),
                    msg=str(exc),
                    attempted=len(attempted),
                    restored=restored,
                    rollback_errors=rollback_errors,
                )
                return result
        except Exception as exc:
            result.update(failed=True, changed=False, msg=str(exc))
            return result

    def call(self, module, extra=None):
        response = self._execute_module(
            module_name="pfrest.pfsense." + module,
            module_args={**self.api, **(extra or {})},
            task_vars=self.task_vars,
        )
        if response.get("failed"):
            # Do not return module invocation/credentials or raw server response to job output.
            raise AnsibleActionFail(
                f"pfrest {module} failed: {response.get('msg', 'request failed')}"
            )
        return response

    def read(self):
        return self.call("services_dns_resolver_host_overrides_info").get("data", [])

    def wait_applied(self):
        for attempt in range(30):
            if self.call("services_dns_resolver_apply_info")["data"].get("applied"):
                return
            time.sleep(1)
        raise ValueError("Resolver apply did not complete within the polling window")

    def write(self, operation):
        before, after = operation["before"], operation["after"]
        record = dict(after or canonical(before))
        # pfrest lookup is case-sensitive; preserve existing wire identity when updating.
        if before:
            record.update(host=before["host"], domain=before["domain"])
        self.call(
            "services_dns_resolver_host_override",
            {
                **record,
                "lookup_fields": ["host", "domain"],
                "state": "present" if after else "absent",
            },
        )
