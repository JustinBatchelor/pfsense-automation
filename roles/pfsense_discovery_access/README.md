# Read-only discovery access

This role creates only `aap-discovery`, owned by `aap-pfsense-discovery-v1`,
with four GET privileges for DNS Resolver host overrides/settings/domain overrides
and DHCPv4 servers. It never manages DNS/DHCP data, existing users, API settings,
packages, or the DNS bootstrap ownership marker.

Use through `playbooks/deploy_inventory.yml` with
`aap_inventory_enroll_readonly: true`, a separate
`aap_inventory_api_credential_name`, and the initial schedule disabled. The
controller-side runtime is Python 3.12 / ansible-core 2.19.9 with
ansible.controller 4.8.12. The verified SSH target must already have pfSense
2.8.1 or 2.9.0, Python 3.11 and pfrest package 2.10_2. Existing API settings must
allow key authentication over verified HTTPS from AAP.

The role takes boolean `pfsense_discovery_access_credential_exists` and optional
`pfsense_discovery_access_commit` (false). Its private registered result contains
`changed`, `enrollment_required` and, only during enrollment, `api_key`.
Every caller must suppress that result with `no_log`. It delegates to the
`pfsense` execution host configured by the recovery entry point.

Preparation records intent before creating the account. The generated key is
stored atomically with mode 0600 in
`/conf/aap-pfsense-discovery-enrollment.json`. AAP stores it without overwriting
an existing secret. Only successful inventory synchronization using that AAP
credential permits commit, which replaces the escrow with non-secret ownership
and key metadata. Normal reruns never generate or replace keys. A local lock
serializes enrollment operations; it does not lock GUI edits by other operators.

An interrupted delivery reuses the pending key. Failure between API key creation
and escrow persistence deliberately requires operator recovery rather than
issuing another key. Account collisions, privilege/group drift, mismatched
escrow, and an enrolled account whose AAP credential disappeared fail closed.
Never delete ownership files to bypass these checks. Recovery requires identifying
the owned account/key and explicitly supplying or replacing its credential.
Check mode performs only reads and returns no key; it does not create lock/state
files. Rollback disables scheduling first, then removes only newly created AAP
objects and the owned discovery account/key after confirming no other consumers.

The PHP adapter is necessary because the existing administrative API credential
is unavailable. Public pfrest user/key modules require API credentials; they
cannot perform this verified SSH enrollment. It uses installed model APIs and
never edits `config.xml` directly. State transitions are tested with an independent
mock backend; live acceptance covers the installed PHP adapter and AAP import.
