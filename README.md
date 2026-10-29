# pfSense automation

Automate pfSense CE with Ansible, starting with DNS Resolver host overrides, and deploy the project
into Ansible Automation Platform (AAP). The project uses `pfrest.pfsense` for DNS
mutations, SSH for API bootstrap, and independent UDP/TCP DNS verification.

Read [AGENTS.md](AGENTS.md) before modifying the code.

## Supported baseline

- pfSense CE **2.8.1-RELEASE / amd64**.
- pfrest API **2.10.2**, FreeBSD package version **2.10_2**, with a pinned SHA-256.
- `pfrest.pfsense` **0.1.0** and `ansible.controller` **4.8.12**.
- Python **3.12**, Ansible Core **2.19.9**; AAP controller **4.8.12** was used for implementation.
- An existing AAP installation and OpenShift build/registry access. This project
  does not install AAP or upgrade the pfSense operating system.

The target defaults to `10.45.45.1`; the API defaults to
`https://pfsense.batchelor.live:443` to match the appliance's existing certificate.
Set `pfsense_api_host` to a resolvable name with a matching trusted certificate.
For private CAs, supply a complete trusted CA bundle through `REQUESTS_CA_BUNDLE`
at runtime (including AAP credential file injection), or install your public CA
in the execution image. Certificate verification is always enabled.

## Python isolation

Create a project-local environment; do not install project packages into system Python:

```sh
python3.12 -m venv .tools
.tools/bin/python -m pip install -r requirements-dev.txt
.tools/bin/ansible-galaxy collection install -r collections/requirements.yml -p .collections
```

The `ansible.controller` collection is licensed Automation Hub content, not a
public Galaxy collection. Configure your authorized Hub source before installing
it locally with
`.tools/bin/ansible-galaxy collection install ansible.controller:==4.8.12 -p .collections`,
or use the collection supplied by your licensed supported execution image.
The pinned execution image already contains that collection. AAP automatically
installs `collections/requirements.yml` during Git synchronization, so that file
contains only public dependencies; it must not request the licensed collection
from public Galaxy.

All container Python packages and Ansible executables run from **`/opt/venv`**.
The image build verifies the interpreter prefix and required modules. The same
immutable image is used for execution tests and AAP jobs. No API key is part of
the image. `ee/Containerfile` supports OpenShift builds;
`execution-environment.yml` also supports Ansible Builder.

On macOS, if needed for local Ansible process creation:

```sh
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
```

## Declare records

```yaml
pfsense_dns_records:
  - host: example
    domain: home.arpa
    ip: [10.45.45.20, 'fd00::20']
    aliases:
      - host: example-admin
        domain: home.arpa
        descr: Administration alias
    descr: Example host
    state: present
```

Each listed record is a complete declaration: omitted `aliases` means `[]`,
omitted `descr` means an empty string, and omitted `state` means `present`.
Omitted **records** are preserved. To remove a record, declare only its `host`,
`domain`, and `state: absent`. An empty host represents the domain apex.
TXT, SRV, independently managed CNAMEs, DNS Forwarder records, and domain
forwarding are outside this role's scope.

You can supply just a new record or the complete existing declarations plus the
new record. Both produce the same result. Names match case-insensitively;
addresses and aliases are normalized before comparison. Duplicate identities or
conflicting final aliases fail before any write. API exports should be converted
with the `pfsense_dns_normalize` filter to remove read-only IDs.

For local runs, supply `PFSENSE_API_KEY` securely in the environment (or through
an encrypted Ansible variable). Do not put it on a shell command line:

```sh
.tools/bin/ansible-playbook playbooks/dns.yml -e @records.yml --check
.tools/bin/ansible-playbook playbooks/dns.yml -e @records.yml
.tools/bin/ansible-playbook playbooks/verify.yml -e @records.yml
```

Preview executes reads only, even though upstream 0.1.0 offers API dry-run writes.
The role bypasses upstream mutation modules in check mode. On a changed run it
applies Unbound once, polls completion, and verifies actual DNS. An unchanged run
does not apply or reload the resolver. Upstream's unused default password is
explicitly cleared to prevent Ansible from redacting legitimate `pfsense` DNS
names from API readback.

## Optional A/AAAA survey

The **pfSense DNS Deploy** workflow and the **Preview**, **Reconcile**, and
**Verify** templates have an optional survey. Choose `inventory` (the default)
to use `pfsense_dns_records`, or choose `survey` and supply the host, domain,
record type (`A` or `AAAA`), address, and optional description. Domain and address
are validated before upsert writes when survey mode is selected; an empty host represents
the domain apex. A type/address-family mismatch fails without changes.

The default `upsert` action replaces the selected address family for that host/domain, preserving
the other family, aliases, and the description when the description field is empty.
Existing records are patched in place; unchanged input causes no write or apply.
Full YAML declarations retain their existing complete-record semantics, including
explicit deletion via `state: absent`. Use Preview first and the serialized Deploy
workflow for mutations. Direct mutation templates remain administrator-only.

To delete through the survey, select `survey` and choose either `delete_type`
(remove all addresses of the selected A/AAAA family while preserving the other
family and aliases) or `delete_host` (remove the entire host override and its
aliases). Removing the last address family also removes the override. Supply
host and domain; the address and description fields are ignored for deletion,
and record type is ignored for `delete_host`. A missing record or missing selected
family is a no-op. Preview the same survey values before launching Deploy.

## Read-only dynamic inventory

`scripts/pfsense_inventory.py` queries pfrest over verified HTTPS and exposes one
`pfsense_discovered` structure to the existing `pfsense` and `localhost` hosts:

```yaml
pfsense_discovered:
  schema_version: 1
  capabilities:
    dhcp_ipv6: false
  dns:
    resolver:
      settings: {}                  # Allowlisted resolver settings
      host_overrides: []             # host, domain, ip, aliases, descr
      domain_overrides: []
  dhcp:
    ipv4:
      lan:
        settings: {}                # Interface, range, domain, DNS/gateway options
        reservations: []            # MAC, IPv4 address, hostname, options, etc.
```

For example, use `pfsense_discovered.dns.resolver.host_overrides` and
`pfsense_discovered.dhcp.ipv4.lan.reservations` directly in a playbook. Discovery
does not generate a host for every client and does not populate
`pfsense_dns_records`. Observed configuration never becomes desired configuration
automatically. DHCP management is not implemented.

The pinned API exposes DHCPv4 servers and their nested static mappings. DHCPv6
reservations are not exposed by this inventory; `dhcp_ipv6: false` describes that
limitation rather than claiming the firewall has no IPv6 reservations. Backend
selection is also not inferred. API IDs, arbitrary custom configuration snippets,
DDNS keys, and credentials are excluded from the exported data. Native API field
names and value types are retained for the allowlisted fields.

Locally, inject the existing key securely and use the project environment:

```sh
export PATH="$PWD/.tools/bin:$PATH"
# PFSENSE_API_KEY must already be supplied securely in the environment.
.tools/bin/ansible-inventory -i scripts/pfsense_inventory.py --list
.tools/bin/ansible-playbook -i scripts/pfsense_inventory.py playbooks/discovery.yml
```

Optional environment overrides are `PFSENSE_API_HOST`, `PFSENSE_API_PORT`,
`PFSENSE_ADDRESS`, and `REQUESTS_CA_BUNDLE`. HTTP, insecure TLS, and redirects are
not supported. A failed API request fails discovery; there is no stale-data or SSH
fallback. Inventory output contains network configuration, so keep saved snapshots
under the ignored `artifacts/` directory.

Deployment provisions the **pfSense Live Discovery** SCM inventory source using
the existing **pfSense DNS API** credential and immutable execution image. Refresh
it in AAP under **pfSense DNS → Sources**, or run:

```sh
.tools/bin/ansible-playbook playbooks/discover_aap.yml -e @deployment.yml
```

The source refreshes before jobs with a five-minute cache and merges only the
discovery data and connection hints; it preserves manually managed inventory
variables, hosts, and declarative records. The `pfsense_discovery` group's
Variables view holds the full data structure.

The existing API key inherits its service account's permissions. Bootstrap adds
GET access for resolver settings, resolver domain overrides, and DHCP servers;
it does not rotate the key or grant DHCP write privileges. When upgrading an
existing DNS-only deployment, run Bootstrap through the existing workflow before
enabling its new inventory source, so discovery does not precede the permission
update:

```sh
.tools/bin/ansible-playbook playbooks/deploy.yml -e @deployment.yml \
  -e '{"aap_inventory_discovery_enabled":false,"aap_launch":true}'
.tools/bin/ansible-playbook playbooks/deploy.yml -e @deployment.yml \
  -e '{"aap_inventory_discovery_enabled":true,"aap_launch":false}'
.tools/bin/ansible-playbook playbooks/discover_aap.yml -e @deployment.yml
```

## Deploy AAP resources from configuration

Copy `deployment.example.yml` to the ignored `deployment.yml`. Configure the
public Git URL/revision, target address, verified SSH known-hosts file, AAP
organization/resource names, instance group and OpenShift build namespace.
Provide these controller credentials through the environment:

- `CONTROLLER_HOST` — AAP base URL, including the gateway URL on modern AAP.
- `CONTROLLER_OAUTH_TOKEN`, or `CONTROLLER_USERNAME` and `CONTROLLER_PASSWORD`.
- Optional `PFSENSE_API_KEY` for a pfrest installation managed outside this project.

The deployment operator must be able to manage the listed AAP resources, build
images in the configured OpenShift namespace, and SSH to the firewall for initial
bootstrap. The namespace's build service account must be able to pull the
licensed base image. AAP execution pods need image-pull access to the built image.

```sh
.tools/bin/ansible-playbook playbooks/deploy.yml -e @deployment.yml
```

The playbook builds/publishes an image only when its definition changes, enrolls
the API if needed, reconciles AAP resources, and launches the serialized
Bootstrap → Reconcile → Verify workflow. Set `aap_launch: false` to configure
resources without launching the workflow. Configuration preview skips image
build and controller mutations; DNS preview is the dedicated Preview template.

The controller stores the key in a **pfSense REST API** credential and injects
`PFSENSE_API_KEY` at job launch. Bootstrap receives a separate Machine credential
and verified SSH known-hosts credential. Operators receive workflow execution
only; controller administrators can still bypass workflow serialization and must
not run mutation templates or edit the firewall concurrently.

First enrollment uses the local deployment operator's controller access. Subsequent
workflow bootstrap runs use the injected existing key and need no controller
administration credential. Existing secrets are preserved on redeployment;
credential rotation is an explicit administrative operation.

## Bootstrap and recovery

Bootstrap checks the installed package and ownership before mutating anything.
Missing packages are installed only from the pinned, checksum-verified release.
An incompatible installed package stops with a migration diagnostic. A supported
existing installation is reconciled without replacing unrelated users or keys.

For a new installation, bootstrap records intent, creates a restricted `aap-dns`
account and API key, and retains a root-only pending key on the appliance until
the AAP credential is saved. Only then is enrollment marked complete and the
pending copy removed. Retrying interrupted enrollment reuses that pending key.
A previously external installation requires its operator's existing key and is
not taken over. The managed account has host-override and resolver-apply privileges plus read-only
resolver settings, domain overrides, and DHCP server discovery. It has no DHCP
write, SSH, or general firewall administration permission.

The API ownership marker is `/conf/aap-pfsense-dns-ownership.json`; the transient
escrow is `/conf/aap-pfsense-dns-pending.json`. Never print either secret escrow
or the controller credential. A missing key on an enrolled installation fails
instead of silently creating another. Restore the correct credential or perform
an explicit restricted-key rotation. If first enrollment was interrupted after
key creation but before escrow was written, inspect and remove only the orphan
key belonging to this automation account before retrying.

pfSense OS updates can remove unofficial packages. The managed ownership marker
and pfrest's backup setting support reinstallation; rerun bootstrap with the
existing credential. An OS version outside the compatibility map requires a
tested package mapping before proceeding.

Before DNS mutations, the action captures the entire override snapshot in memory
and rejects preexisting pending resolver changes. It rechecks state between
writes, restores only touched records that still match its writes on failure,
and verifies rollback. It never deliberately applies a detected concurrent
writer's changes. The API does not provide a transaction/CAS lock: do not edit
resolver configuration in the GUI during a deployment.

If a worker dies or the API becomes unreachable midway, the next run refuses to
apply pending state. Inspect the AAP error and pfSense configuration history,
restore only the affected overrides, then apply and verify. Do not restore a
complete firewall backup or clear unrelated pending changes automatically.
Before first bootstrap, keep a protected full appliance backup; package bootstrap
also saves one under `/conf/backup/aap-before-restapi-*.xml`.

## Tests

```sh
.tools/bin/pytest -q
.tools/bin/yamllint .
.tools/bin/ansible-lint --offline
.tools/bin/ansible-playbook playbooks/deploy.yml --syntax-check
.tools/bin/ansible-playbook playbooks/acceptance.yml
.tools/bin/ansible-playbook playbooks/acceptance_aap.yml
```

The pytest suite runs the real collection against a local mock HTTP API and
checks semantic diffing, no-write preview, preservation, repeated runs,
authentication failures, pending-change rejection and partial-write rollback.
Bootstrap boundary tests exercise unsupported versions, external installations,
ownership conflicts, preview and interrupted enrollment.

`acceptance.yml` is a live test: it allocates a unique name under `automation.test`,
tests both input styles, IPv4/IPv6 and aliases, repeats operations to prove no
changes, and removes the record in an `always` block. It checks all original
overrides and DNS answers after cleanup. Deletion is verified through API
readback; an absent override is not assumed to imply NXDOMAIN.

Run live acceptance only on an authorized target and serialize it with all other
mutations. A hard process termination can prevent `always` cleanup; inspect any
remaining `aap-test-*` record by its exact name rather than deleting by wildcard.
The Acceptance template is administrator-only and checks `/opt/venv` isolation
inside the execution container. Launch and polling are separate operations so a
transient controller connection failure retries waiting on the same job instead
of launching another live test. `scripts/check.sh` runs the complete local suite.
