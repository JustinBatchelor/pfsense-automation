# Restore pfSense inventory discovery

`playbooks/deploy_inventory.yml` restores discovery and its AAP prerequisites.
It does not invoke the DNS bootstrap, launch firewall jobs, install packages,
build images, or restore Snort reporting. Discovery still exports DNS Resolver
configuration and DHCPv4 reservations under `pfsense_discovered` for `pfsense`
and `localhost`. It does not create client hosts or discover active leases/DHCPv6.

## Inputs and execution

Use Python 3.12 in `.tools`, `requirements-dev.txt`, and the pinned collections
from the README. Keep the interpreter installation outside temporary directories;
for example, configure `UV_PYTHON_INSTALL_DIR="$PWD/.tooling/python"` before
creating `.tools`. Existing licensed collections can be retained in `.collections`.
Provide controller authentication through the existing environment interface.

Create ignored `deployment.yml` with the existing organization/resource names,
verified pfSense SSH key/known-hosts paths, API hostname and these recovery values:

```yaml
---
aap_project_url: https://github.com/JustinBatchelor/pfsense-automation.git
aap_project_revision: REPLACE_WITH_REVIEWED_FULL_COMMIT
aap_ee_image: REPLACE_WITH_EXISTING_REGISTRY_IMAGE_AT_SHA256_DIGEST
aap_inventory_api_credential_name: pfSense Discovery API
aap_inventory_enroll_readonly: true
aap_inventory_manage_dns_records: false
aap_inventory_schedule_enabled: false
```

The image must already contain the tested `/opt/venv` runtime and licensed
controller collection. The initial schedule must be disabled. The dedicated
`aap-discovery` account receives only GET privileges for resolver host overrides,
settings, domain overrides and DHCP servers. Existing pfrest settings must allow
key authentication and AAP HTTPS connectivity. Existing accounts and keys remain
untouched, including the older DNS automation account.

```sh
export PATH="$PWD/.tools/bin:$PATH"
export ANSIBLE_LOCAL_TEMP="$PWD/.ansible/tmp"
.tools/bin/ansible-playbook playbooks/deploy_inventory.yml -e @deployment.yml --check
.tools/bin/ansible-playbook playbooks/deploy_inventory.yml -e @deployment.yml
.tools/bin/ansible-playbook playbooks/discover_aap.yml -e @deployment.yml
```

Check mode validates immutable inputs, credential identity and firewall account
ownership without writes. It deliberately reports a dependency-graph preview,
not a complete controller diff when referenced objects are missing. Initial
apply creates AAP dependencies, syncs the pinned project, creates the inventory
source and disabled schedule, then verifies enrollment with an actual inventory
update. Only that success permits removal of secret escrow. Subsequent applies
preserve credentials and do not automatically launch inventory updates.

For an already enrolled credential, set `aap_inventory_enroll_readonly: false`.
An existing named AAP credential is reused. If absent, supply `PFSENSE_API_KEY`
securely in the environment; never put it in deployment YAML or command arguments.

## Acceptance and scheduling

Inspect **pfSense DNS → Sources → pfSense Live Discovery** for a successful
update. Its source is `scripts/pfsense_inventory.py`, with the pinned project,
execution image and selected API credential. Verify `pfsense_discovery` group
variables and inherited host data against independent read-only pfSense results.
Observed data must not populate `pfsense_dns_records`. Inventory and host
reconciliation preserve unrelated variables; full DNS deployment can still
explicitly manage declarative records.

Repeat discovery and deployment. Resource IDs must remain stable, deployment
must report zero changes, and no credentials may be rotated. Test preservation
of an unrelated variable and an existing desired DNS declaration. Confirm the
firewall's DNS/DHCP settings, existing users/keys, group memberships and global
API settings remain unchanged.

After acceptance, change `aap_inventory_schedule_enabled` to `true` in the
deployment file and rerun deployment. Confirm the schedule refers to the source
ID, runs at 06:00 America/New_York, and uses the existing fixed DTSTART anchor.
The source retains refresh-before-job with a 300-second cache and both overwrite
flags false. Verify a scheduled execution separately; next-run calculation alone
is not proof that it ran.

## Failure and recovery

Enrollment state is separate from DNS bootstrap. See the
[access role contract](../roles/pfsense_discovery_access/README.md) for escrow,
locking and interruption behavior. Failed inventory import leaves the key in
root-only escrow and the initial schedule disabled; fix the reported issue and
rerun the same configuration. Do not delete state files or overwrite credentials
to force enrollment. Loss of a completed credential requires explicit recovery.

Record created AAP IDs before rollback. Disable the managed schedule first;
remove only newly created source/inventory/project/EE/credential objects after
checking consumers. Revoke only the new discovery key/account if abandoning the
restoration. Preserve the existing image and all previous firewall identities.
Never restore an entire firewall backup for this repair.

## Scoped engineering exceptions

Shared guidance §§10.1–10.2: retain `ansible.controller` 4.8.12 modules and the
existing source-ID schedule adapter rather than migrate this repair to
`infra.aap_configuration`. Shared YAML definitions, dependency ordering,
production lint, integration acceptance and unchanged reruns validate this
bounded approach. The adapter avoids ambiguous schedule name lookup.

§10.8: recovery uses the existing authorized operator execution path because its
target AAP resources are absent. Code is versioned and validated before rollout;
the current public CI runs unit/mock tests and YAML checks. It does not receive
production credentials or become a newly privileged deployment pipeline.

§§4.1.7, 8.8, 12.3: retain this repository's local-role/module layout and tested
AnsibleModule scaffolding. The enrollment state machine uses pytest with an
independent backend; installed PHP behavior is checked on the approved appliance.
Container-only Molecule cannot represent pfSense's PHP/configuration subsystem.
No destructive enrollment cases run against the live firewall.
