#!/usr/bin/python
"""Manage a schedule by its job-template ID using the pinned controller client."""

from ansible_collections.ansible.controller.plugins.module_utils.controller_api import (
    ControllerAPIModule,
)

DOCUMENTATION = r"""
module: aap_job_schedule
short_description: Reconcile a schedule for an explicitly resolved job template
description:
  - Uses the pinned controller collection's authentication and idempotent API helpers.
  - Avoids the name-only unified-template lookup in ansible.controller.schedule 4.8.12.
  - Does not launch jobs or alter credentials.
options:
  job_template_id:
    type: int
    required: true
    description: Resolved job template ID, never an inventory source or workflow ID.
  name:
    type: str
    required: true
    description: Stable schedule name within this template.
  rrule:
    type: str
    required: true
    description: AAP recurrence rule with a fixed DTSTART anchor and timezone.
  enabled:
    type: bool
    default: true
    description: Whether AAP should run the schedule.
  create_if_missing:
    type: bool
    default: true
    description: Set false to reconcile existing schedules without creating one.
extends_documentation_fragment: ansible.controller.auth
author: Justin Batchelor
"""

EXAMPLES = r"""
- name: Schedule read-only reporting
  aap_job_schedule:
    job_template_id: "{{ report_template.id }}"
    name: pfSense Snort Daily Report
    enabled: true
    rrule: 'DTSTART:20261104T111500Z RRULE:FREQ=DAILY;INTERVAL=1'
"""

RETURN = r"""
id:
  description: Schedule ID when it exists.
  type: int
  returned: when present
changed:
  description: Whether schedule creation or reconciliation was needed.
  type: bool
  returned: always
"""


def main():
    module = ControllerAPIModule(argument_spec={
        "job_template_id": {"type": "int", "required": True},
        "name": {"type": "str", "required": True},
        "rrule": {"type": "str", "required": True},
        "enabled": {"type": "bool", "default": True},
        "create_if_missing": {"type": "bool", "default": True},
    })
    source_id = module.params["job_template_id"]
    if source_id <= 0:
        module.fail_json(msg="job_template_id must be positive")
    if not module.verify_ssl:
        module.fail_json(msg="Controller TLS verification must remain enabled")
    source = module.get_endpoint(f"job_templates/{source_id}/")
    if source["status_code"] != 200 or source.get("json", {}).get("id") != source_id:
        module.fail_json(msg="The resolved job template does not exist or is inaccessible")
    existing = module.get_one(
        "schedules",
        data={"name": module.params["name"], "unified_job_template": source_id},
    )
    if not existing and not module.params["create_if_missing"]:
        module.exit_json(changed=False)
    module.create_or_update_if_needed(
        existing,
        {"name": module.params["name"], "rrule": module.params["rrule"],
         "enabled": module.params["enabled"], "unified_job_template": source_id},
        endpoint="schedules", item_type="job template schedule",
    )


if __name__ == "__main__":
    main()
