# Daily Snort report

The report is read-only. It collects Snort CSV alert metadata and selected configuration
through verified SSH, analyzes the last 24 elapsed hours, and stores a readable summary
in AAP output plus `snort_report` JSON in job artifacts. It does not configure Snort,
block hosts, restart services, remove logs, or send telemetry to an external model.

## Deploy and validate

Use the Python 3.12 `.tools` environment and pinned collections described in the README.
Reporting uses the existing organization, immutable execution environment, Machine
credential, SSH Trust credential, and instance group. The supplied Machine credential
can have administrative access to the firewall; this collector only executes its
checked-in read-only PHP script. Do not grant general report-template administration to
untrusted users. Credentials remain in AAP and are never part of project files.

Set `aap_project_url` and pin `aap_snort_project_revision` to the reviewed Git commit.
The dedicated **pfSense Snort Reporting** project and static inventory are separate from
DNS discovery and deployment. Changing their revision does not change the DNS project.

```sh
.tools/bin/ansible-playbook playbooks/deploy_snort.yml -e @deployment.yml \
  -e '{"aap_snort_schedule_enabled":false}'
```

Synchronize the reporting project, then manually launch **pfSense Snort Daily Report**.
Inspect both output and its job artifacts. A successful collection has
`snort_report.collection_ok: true`, a completion marker, and matching configuration
checksums. Independently compare alert counts for the exact reported start/end window.
Findings do not fail the job; incomplete collection does. The play publishes diagnostic
artifacts before failing. Do not enable a schedule after an unexplained collection failure.

Once validated, set `aap_snort_schedule_enabled: true` in the ignored deployment
configuration and reconcile again. The schedule runs at **11:15 UTC**, or 06:15 Eastern
in winter and 07:15 in summer. Its fixed anchor is November 4, 2026. Reconciliation
never launches a report or DNS workflow. Report runs cannot overlap in AAP.

Set `aap_snort_schedule_enabled: false` to disable the managed schedule. Setting
`aap_snort_enabled: false` also disables an existing managed schedule without deleting
its project, inventory, template, or historical results. Unrelated schedules are not
modified. Stable names identify managed resources. Full deployment includes these same
tasks; retain your reporting revision and schedule settings in deployment configuration.

When a tested feature commit is merged, explicitly change the reporting project's
revision to the desired merged commit and repeat manual acceptance. This is not an
implicit instruction to merge a PR or change an existing project's branch.

## Local execution and report interface

Local invocation uses the same playbook and collector. Supply existing trusted key paths
without copying keys into this repository:

```sh
.tools/bin/ansible-playbook -i localhost, playbooks/snort_report.yml \
  -e '{"pfsense_address":"firewall.home.arpa","pfsense_ssh_user":"admin", "snort_known_hosts_file":"~/.ssh/known_hosts", "snort_private_key_file":"~/.ssh/firewall"}'
```

Check mode performs the same read-only collection. `snort_end_epoch` optionally fixes
an end timestamp for reproducing a report; omit it for scheduled runs. Each window is
`[end - 86400, end)`, using the firewall clock. Daily scheduling is not a backfill
mechanism: delays, failed jobs, log deletion, and scheduler outages can leave gaps.
Review failed jobs and run explicit historical windows while logs remain available.

Schema version 1 includes:

- `window`, `collection_ok`, `issues`, input counters, and before/after configuration hashes.
- `configuration`: allowlisted settings, generated network variables, active suppression
  directives, configured rule categories, and process counts. No full config export.
- `total_alerts`, `signature_count`, `top_signatures`, and baseline counts/limitations.
- `findings`: interface, generator/signature ID, revisions, endpoints, destination port,
  protocol, counts, first/last bounds, classification, action/disposition counts, and
  reasons for review. Source ports are parsed but not part of aggregation identity.
- `possible_scans`, `tuning_candidates`, and explicit counts of omitted finding groups.

Defaults are 20 minimum alerts and a fivefold increase over the retained daily baseline,
20 distinct destinations or destination ports within ten minutes for scan candidates,
100 structured groups, and 30 groups in readable output. Override `snort_min_count`,
`snort_multiplier`, `snort_scan_threshold`, and `snort_max_groups` in deployment config.
Priority 1/2 alerts remain visible; novelty and volume are triage leads, not verdicts.

The baseline covers seven preceding 24-hour buckets. Volume comparisons require at
least 72 hours of observed history, use its actual observed span rather than assuming
seven full days, and are qualified by retention and tuning changes. Zero-count buckets
are not proof that monitoring was continuously active. Newness means absent from the
retained baseline, not first-ever activity. No durable baseline service is required.

A 180-second SSH timeout and at most 64 MiB of uncompressed input bound collection.
Current files are read to their initial size. Rotations, oversized/partial records,
unsupported formats, missing logs, and input limits are explicit failures. Older files
whose filesystem modification time predates the baseline are skipped. Supported input
is the configured Snort `alert_csv` field list; binary/fast formats fail explicitly.
The collector reads plain and single-member gzip `alert`/`alert.<epoch>` files, checking
gzip CRC and length. Concatenated gzip members fail explicitly.

CSV timestamps are interpreted in the firewall's timezone. Legacy US names such as
`EST5EDT` map to IANA zones. A repeated DST-hour timestamp is counted only when both
possible offsets agree on the report window and baseline bucket. Its first/last times
are bounds, and it is excluded from ten-minute scan checks. Boundary ambiguity and
nonexistent local timestamps fail collection rather than being silently assigned.

AAP retains reports according to its existing job-retention policy. Reports contain
network metadata and should be accessible only to intended administrators. Local saved
reports belong in ignored `artifacts/` with restricted permissions, never in Git.

## Tuning review

Start with the current report and active configuration, not an old noise ranking.

1. Preserve narrow existing STUN suppressions when they match verified expected devices.
   Suppression removes evidence for that signature/source; it does not establish safety.
2. Investigate dominant HTTP preprocessor signatures such as `120:3` and `120:18` against
   endpoint/proxy behavior and observation asymmetry before proposing narrow filtering.
3. Classify connectivity tests, package downloads, and developer tunnels against actual
   expected use. Avoid device-wide exemptions and blanket policy-category suppression.
4. Retain rare SSH, suspicious-domain, and long-DNS-label alerts for endpoint correlation.
   Signature titles, Snort `Allow` disposition, and absent firewall blocks do not prove
   an exploit, successful connection, or benign outcome.
5. Review enabled rule categories and HOME_NET/EXTERNAL_NET against intended coverage.
   Public DNS servers, WAN addresses, and VPN networks can be part of pfSense defaults;
   do not remove them simply because they are public. LAN-only inspection, encrypted
   traffic, same-subnet switching, and shared/NAT addresses limit attribution.
6. Verify successful feed updates and effective retention separately from configured
   schedules. Retained historical alert sizes may exceed today's rotation setting.
   Keep detection-only operation while evaluating proposed changes and their rollback.

An event filter reduces logged events; suppression can eliminate matching events. In
Snort 2, `event_filter` supersedes standalone `threshold`. A `track by_src` event filter
tracks each source separately but is not an allowlist restricting the filter to one
chosen source. Do not label such a filter source-specific in that stronger sense.

References: [Netgate interface settings](https://docs.netgate.com/pfsense/en/latest/packages/snort/interface-settings.html),
[Netgate suppression lists](https://docs.netgate.com/pfsense/en/latest/packages/snort/suppress-list.html),
and [Snort filter semantics](https://www.snort.org/document/readme-filters).

## Testing

The normal project checks include synthetic timestamp, baseline, anomaly, SSH-failure,
redaction, real-Ansible-playbook, and schedule-identity tests. Collector fixture tests
also require PHP CLI with SimpleXML, ctype, and zlib. Set `PHP_TEST_BIN` and optional
`PHP_TEST_ARGS` for an isolated runtime; otherwise they use `php` on PATH and explicitly
skip if unavailable. Run them before deploying collector changes:

```sh
PHP_TEST_BIN=/path/to/php scripts/check.sh
```

The reporting playbook must also pass inside the same immutable image used by AAP.
A successful local test alone is not evidence of successful AAP deployment.
