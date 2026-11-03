#!/usr/bin/python
"""Documentation for the controller-side Snort action plugin."""
DOCUMENTATION = r'''
module: pfsense_snort_report
short_description: Collect and summarize Snort alerts over verified SSH
description:
  - Runs locally through an action plugin, using read-only PHP over SSH.
  - Returns a report even on failure so callers can publish diagnostics before failing.
author: Justin Batchelor
options:
  host:
    type: str
    required: true
    description: Verified SSH target hostname or address.
  user:
    type: str
    default: admin
    description: SSH account.
  known_hosts:
    type: path
    description: Verified trust file, defaults to PFSENSE_KNOWN_HOSTS_FILE.
  private_key_file:
    type: path
    description: Optional local SSH key, otherwise uses Ansible Machine credential or agent.
  end_epoch:
    type: int
    default: 0
    description: Reproducible UTC window end; zero uses the firewall clock.
  max_bytes:
    type: int
    default: 67108864
    description: Maximum uncompressed alert input bytes.
  min_count:
    type: int
    default: 20
    description: Minimum signature count for a volume candidate.
  multiplier:
    type: float
    default: 5
    description: Ratio to retained daily baseline for a volume candidate.
  scan_threshold:
    type: int
    default: 20
    description: Distinct alert destinations or ports within ten minutes.
  max_groups:
    type: int
    default: 100
    description: Maximum structured finding groups, up to 500.
attributes:
  check_mode:
    support: full
    description: Collection is read-only in both modes.
'''
EXAMPLES = r'''
- name: Collect read-only Snort report
  pfsense_snort_report:
    host: firewall.home.arpa
  register: snort
'''
RETURN = r'''
report:
  description: Versioned report with collection_ok, summary, findings and coverage limitations.
  returned: always
  type: dict
'''
