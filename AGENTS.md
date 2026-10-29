# Working in this repository

Read this file and README.md before modifying the project. This automation manages
a real firewall. Preserve unrelated DNS records, resolver settings, API users, and
credentials. Never replace the complete host-override list or edit generated
Unbound files. DNS mutations must use the pinned pfrest.pfsense collection.

## Development environment

- Use a project-local Python 3.12 virtual environment (`.tools` for development).
  Install `requirements-dev.txt` into it. Never use system pip or global Ansible.
- Install `collections/requirements.yml` into `.collections`. The licensed
  `ansible.controller` collection requires an authorized Automation Hub source.
- Run tools as `.tools/bin/python`, `.tools/bin/pytest`,
  `.tools/bin/ansible-playbook`, `.tools/bin/ansible-lint`, and
  `.tools/bin/yamllint`, or activate `.tools` explicitly.
- Container/Execution Environment Python dependencies belong in `/opt/venv`.
  Container tests and AAP jobs must use that interpreter and the same image.
- Keep downloaded toolchains, collections, artifacts and local configuration out
  of Git. `.gitignore` documents their locations.

## Architecture

- `plugins/module_utils/dns_state.py`: pure validation, normalization and diff.
- `plugins/action/pfsense_dns_reconcile.py`: collection-backed reconciliation,
  explicit read-only preview, conflict detection and conditional rollback.
- `plugins/modules`: independent DNS verification and SSH bootstrap module.
- `roles/pfrest_bootstrap`: pfrest package/configuration and enrollment adapter.
- `roles/pfsense_dns`: reusable reconciliation and verification interface.
- `playbooks`: local/AAP entry points, deployment and live acceptance.
- `tests`: pure logic and mock API/Ansible integration tests.

## Invariants

1. Omitted records remain unchanged. Deletions require `state: absent`.
2. Match host overrides by normalized host/domain, never by list position or IP.
3. Check mode must not issue mutation requests, including API dry-run POSTs.
4. Reject preexisting pending resolver changes. Apply once after changes and
   never on an unchanged run. Report apply/readback/rollback failures truthfully.
5. Rollback only records still matching this job's writes. Never overwrite
   intervening operator changes or apply another writer's pending configuration.
6. Externally installed pfrest requires a supplied API key. Only owned enrollment
   can create credentials; healthy credentials must survive repeated deployment.
7. Runtime keys come from `PFSENSE_API_KEY`, normally injected by AAP. Never bake
   secrets into images, commit them, print them, or expose module invocation data.
8. Keep TLS verification and SSH host verification enabled. Use a certificate-
   matching API hostname and configured CA trust. Do not add insecure fallbacks.
9. Pin and test dependencies and package checksums. Unsupported platforms fail
   explicitly; never upgrade the firewall operating system automatically.

## Verification and live work

Run unit/mock tests, YAML lint, Ansible lint, syntax checks, and the execution
image smoke checks appropriate to the change. Do not weaken tests to mask a
failure. Document any validation that could not be completed.

Live changes require authorization in the active task. Use unique names beneath
`automation.test`, capture before-state, and guarantee cleanup. Test both a
single-record declaration and all-existing-plus-test declarations. Re-run to
prove zero changes. Validate UDP and TCP DNS and unrelated records. Do not
delete all overrides, reset pfrest, or restore a complete firewall backup as a
routine test. Destructive bootstrap-state scenarios belong in a mock or lab.

Serialize production mutations through the AAP workflow. Keep credentials and
controller access scoped to their tasks. Report the exact tests run and any
remaining deployment limitations. Do not claim AAP or live acceptance passed
unless those jobs were actually observed to succeed.
