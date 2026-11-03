"""Read-only Snort transport, timestamp normalization, and explainable triage."""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import time
from zoneinfo import ZoneInfo

DAY = 86400
# pfSense still stores these legacy US tzdb names, removed by some newer tzdb builds.
ZONE_ALIASES = {'EST5EDT': 'America/New_York', 'CST6CDT': 'America/Chicago',
                'MST7MDT': 'America/Denver', 'PST8PDT': 'America/Los_Angeles'}
DEFAULT_COLUMNS = 'timestamp sig_generator sig_id sig_rev msg proto src srcport dst dstport classification priority action disposition'.split()


class AmbiguousTimestamp(ValueError):
    def __init__(self, candidates):
        super().__init__('Ambiguous local alert timestamp')
        self.candidates = sorted(candidates)


def timestamp(value, end, tz):
    """Reject DST ambiguity instead of silently assigning an event to the wrong window."""
    value = value.strip()
    zone = ZoneInfo(ZONE_ALIASES.get(tz, tz))
    local_end = datetime.fromtimestamp(end, zone)
    date_part = value.split('-')[0]
    formats = ['%m/%d/%y-%H:%M:%S', '%m/%d/%Y-%H:%M:%S'] if date_part.count('/') == 2 else ['%Y/%m/%d-%H:%M:%S']
    candidates = []
    for fmt in formats:
        for year in ([local_end.year - 1, local_end.year, local_end.year + 1] if date_part.count('/') == 1 else [None]):
            text = f'{year}/{value}' if year is not None else value
            try:
                naive = datetime.strptime(text, fmt + ('.%f' if '.' in text else ''))
            except ValueError:
                continue
            stamps = set()
            for fold in (0, 1):
                aware = naive.replace(tzinfo=zone, fold=fold)
                if datetime.fromtimestamp(aware.timestamp(), zone).replace(tzinfo=None) == naive:
                    stamps.add(aware.timestamp())
            if not stamps:
                raise ValueError('Nonexistent local alert timestamp')
            if len(stamps) > 1:
                raise AmbiguousTimestamp(stamps)
            candidates.extend(stamps)
    if not candidates:
        raise ValueError('Unsupported alert timestamp')
    # For yearless records, choose the nearest year to the collector clock.
    return min(candidates, key=lambda t: abs(t - end))


def collect(script, host, user, known_hosts, key_file=None, end=0, max_bytes=64 * 1024 * 1024, timeout=180):
    """Bound stdout/stderr and elapsed time; never include SSH diagnostics in results."""
    if not re.fullmatch(r'[A-Za-z0-9_.:-]+', host) or host.startswith('-'):
        raise ValueError('Invalid SSH hostname')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', user) or user.startswith('-'):
        raise ValueError('Invalid SSH username')
    if not Path(known_hosts).is_file():
        raise ValueError('Verified SSH known_hosts file is required')
    if not 0 <= int(end) or not 1024 <= int(max_bytes) <= 64 * 1024 * 1024 or not 1 <= timeout <= 180:
        raise ValueError('Invalid collection bounds')
    code = Path(script).read_text().replace('__REPORT_END__', str(int(end))).replace('__MAX_BYTES__', str(int(max_bytes)))
    argv = ['ssh', '-F', '/dev/null', '-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', f'UserKnownHostsFile={known_hosts}', '-o', 'ConnectTimeout=10',
            '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2']
    if key_file:
        argv += ['-o', 'IdentitiesOnly=yes', '-i', str(Path(key_file).expanduser())]
    argv += [f'{user}@{host}', 'php -d display_errors=stderr /dev/stdin']
    messages, pending, output_bytes = [], b'', 0
    with subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
        try:
            proc.stdin.write(code.encode())
            proc.stdin.close()
            deadline = time.monotonic() + timeout
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                selector.register(proc.stderr, selectors.EVENT_READ)
                while selector.get_map():
                    if time.monotonic() >= deadline:
                        raise ValueError('SSH collection timed out')
                    for entry, _ in selector.select(min(1, max(0, deadline-time.monotonic()))):
                        chunk = os.read(entry.fd, 65536)
                        if not chunk:
                            selector.unregister(entry.fileobj)
                            continue
                        output_bytes += len(chunk)
                        if output_bytes > max_bytes * 4 + 1024 * 1024:
                            raise ValueError('SSH collection output limit exceeded')
                        if entry.fileobj is proc.stderr:
                            continue
                        pending += chunk
                        lines = pending.split(b'\n')
                        pending = lines.pop()
                        if len(pending) > 256 * 1024:
                            raise ValueError('Oversized collector record')
                        for line in lines:
                            messages.append(json.loads(line))
            if proc.wait(timeout=max(0.1, deadline-time.monotonic())) != 0:
                messages.append({'type': 'issue', 'message': 'SSH collector failed; check target access and PHP availability'})
            if pending:
                messages.append({'type': 'issue', 'message': 'Incomplete collector output'})
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            proc.kill()
            proc.wait()
            messages.append({'type': 'issue', 'message': str(exc) if isinstance(exc, ValueError) and not isinstance(exc, json.JSONDecodeError)
                             else 'SSH transport or collector output failed'})
    return messages


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).isoformat()


def clean(value):
    return ''.join(c for c in str(value)[:500] if c.isprintable())


def analyze(messages, min_count=20, multiplier=5, scan_threshold=20, max_groups=100):
    if min_count < 1 or multiplier < 1 or scan_threshold < 2 or not 1 <= max_groups <= 500:
        raise ValueError('Invalid analysis thresholds')
    metas = [m for m in messages if m.get('type') == 'metadata']
    complete = [m for m in messages if m.get('type') == 'complete']
    issues = sorted(set(clean(m.get('message', 'Collector failure')) for m in messages if m.get('type') == 'issue'))
    if len(metas) != 1 or len(complete) != 1:
        issues.append('Missing or duplicate collector metadata/completion marker')
    if not metas:
        return {'schema_version': 1, 'collection_ok': False, 'issues': issues,
                'summary': 'Snort report unavailable: collection failed.', 'findings': []}
    meta = metas[0]
    end = meta['end']; start = end - DAY; oldest = start - 7 * DAY
    zone = meta['timezone']
    # Validate once; map pfSense legacy US timezone names to their IANA equivalents.
    ZoneInfo(ZONE_ALIASES.get(zone, zone))
    history, events = [], []
    failures = 0
    ambiguous = 0
    for row in messages:
        if row.get('type') != 'event':
            continue
        try:
            uncertain = False
            try:
                t = latest = timestamp(row['timestamp'], end, zone)
            except AmbiguousTimestamp as exc:
                ambiguous += 1
                t, latest = exc.candidates[0], exc.candidates[-1]
                def bucket(stamp):
                    if start <= stamp < end:
                        return 'current'
                    if oldest <= stamp < start:
                        return int((start-stamp-0.000001)//DAY)
                    return 'outside'
                if bucket(t) != bucket(latest):
                    raise ValueError('DST ambiguity crosses a reporting boundary') from exc
                uncertain = True
            sid = f"{int(row['sig_generator'])}:{int(row['sig_id'])}"
            src = str(ipaddress.ip_address(row['src'])); dst = str(ipaddress.ip_address(row['dst']))
            priority = int(row['priority']); revision = int(row['sig_rev'])
            ports = []
            for name in ('srcport', 'dstport'):
                port = int(row[name]) if row[name] else None
                if port is not None and not 0 <= port <= 65535:
                    raise ValueError('Invalid port')
                ports.append(port)
            item = {'time': t, 'time_latest': latest, 'timestamp_uncertain': uncertain, 'interface': clean(row['interface']), 'signature': sid, 'revision': revision,
                    'source': src, 'destination': dst, 'source_port': ports[0], 'destination_port': ports[1],
                    'priority': priority, 'protocol': clean(row['proto']), 'message': clean(row['msg']),
                    'classification': clean(row['classification']), 'action': clean(row['action']),
                    'disposition': clean(row['disposition'])}
            if oldest <= t < start:
                history.append(item)
            elif start <= t < end:
                events.append(item)
        except (KeyError, ValueError, TypeError):
            failures += 1
    if failures:
        issues.append(f'{failures} unparseable or ambiguous alert records')
    events.sort(key=lambda e: e['time'])
    hist_counts = Counter((e['interface'], e['signature']) for e in history)
    hist_pairs = {(e['interface'], e['signature'], e['source']) for e in history}
    first = min((e['time_latest'] for e in history), default=None)
    span = start-first if first is not None else 0
    # Divide by the available observed span; never dilute a partial history over seven days.
    baseline_days = min(7, span/DAY)
    baseline_ready = baseline_days >= 3
    groups = {}; totals = Counter(); current_counts = Counter((e['interface'], e['signature']) for e in events)
    for e in events:
        key = tuple(e[n] for n in ('interface', 'signature', 'source', 'destination', 'protocol', 'destination_port'))
        totals[e['signature']] += 1
        if key not in groups:
            groups[key] = {k: v for k, v in e.items() if k not in ('time', 'time_latest', 'timestamp_uncertain', 'revision', 'source_port', 'action', 'disposition')}
            groups[key].update(count=0, first=iso(e['time']), last=iso(e['time']), revisions=set(), actions=Counter(), reasons=[], ambiguous_timestamps=0)
        g = groups[key]; g['count'] += 1; g['last'] = max(g['last'], iso(e['time_latest'])); g['ambiguous_timestamps'] += int(e['timestamp_uncertain']); g['revisions'].add(e['revision'])
        g['priority'] = min(g['priority'], e['priority'])
        g['actions'][e['action']+'/'+e['disposition']] += 1
    for g in groups.values():
        sigkey = (g['interface'], g['signature'])
        if g['priority'] == 1:
            g['reasons'].append('Priority 1 signature: investigate; not proof of compromise')
        elif g['priority'] == 2:
            g['reasons'].append('Priority 2 signature: review context')
        if history and sigkey not in hist_counts:
            g['reasons'].append('Signature not seen in retained baseline')
        elif history and (*sigkey, g['source']) not in hist_pairs:
            g['reasons'].append('Signature/source pair not seen in retained baseline')
        avg = hist_counts[sigkey]/baseline_days if baseline_ready else None
        if avg is not None and current_counts[sigkey] >= min_count and current_counts[sigkey] >= multiplier*avg:
            g['reasons'].append(f'Signature volume {current_counts[sigkey]} vs retained daily average {avg:.1f}')
        g['revisions'] = sorted(g['revisions']); g['actions'] = dict(g['actions'])
    windows = defaultdict(lambda: (deque(), Counter(), Counter()))
    scans = {}
    for e in events:
        if e['timestamp_uncertain']:
            continue
        key = (e['interface'], e['source'])
        queue, host_counts, port_counts = windows[key]
        queue.append(e)
        host_counts[e['destination']] += 1
        if e['destination_port'] is not None:
            port_counts[e['destination_port']] += 1
        while queue and queue[0]['time'] < e['time']-600:
            expired = queue.popleft()
            host_counts[expired['destination']] -= 1
            if not host_counts[expired['destination']]:
                del host_counts[expired['destination']]
            if expired['destination_port'] is not None:
                port_counts[expired['destination_port']] -= 1
                if not port_counts[expired['destination_port']]:
                    del port_counts[expired['destination_port']]
        hosts, ports = len(host_counts), len(port_counts)
        if max(hosts, ports) >= scan_threshold:
            scans[key] = {'interface': key[0], 'source': key[1], 'destination_hosts': hosts,
                          'destination_ports': ports, 'window_start': iso(queue[0]['time']), 'window_end': iso(e['time']),
                          'reason': 'Possible scanning based on alert fanout; server replies can also cause this pattern. Verify flow roles.'}
    ordered = sorted(groups.values(), key=lambda g: (not bool(g['reasons']), g['priority'], -g['count'], g['signature'], g['source']))
    baseline_buckets = [0]*7
    for e in history:
        baseline_buckets[min(6, int((start-e['time']-0.000001)//DAY))] += 1
    limitations = ['Counts are rule matches, not attacks or unique connections.',
                  'Retained logs cannot establish uninterrupted coverage; absent alerts do not prove safety.',
                  'Baseline may span rule updates or tuning changes; suppressed events are not observable.',
                  'Shared/NAT addresses cannot identify individual endpoints. Encrypted and same-subnet traffic may be invisible.',
                  'Snort disposition does not establish firewall passage or successful exploitation.']
    if ambiguous:
        limitations.append(f'{ambiguous} timestamps fall in a repeated DST hour. Counted only where both offsets agree on window/bucket; first/last are bounds and ambiguous records are excluded from ten-minute scan checks.')
    if not baseline_ready:
        limitations.append('Less than 72 hours of observed history: volume comparisons disabled.')
    if complete and meta.get('config_sha256_before') != complete[0].get('config_sha256_after'):
        issues.append('Configuration checksum changed during collection')
    report = {'schema_version': 1, 'window': {'start': iso(start), 'end': iso(end), 'seconds': DAY},
              'collection_ok': not issues, 'issues': issues, 'parse_failures': failures, 'ambiguous_timestamps': ambiguous,
              'collection': complete[0] if complete else {}, 'configuration': meta,
              'total_alerts': len(events), 'signature_count': len(totals),
              'top_signatures': [{'signature': s, 'count': n} for s, n in totals.most_common(20)],
              'baseline': {'start': iso(oldest), 'end': iso(start), 'events': len(history),
                           'observed_days': round(baseline_days, 3), 'volume_comparison_enabled': baseline_ready,
                           'daily_buckets_newest_first': baseline_buckets},
              'findings': ordered[:max_groups], 'omitted_groups': max(0, len(ordered)-max_groups),
              'possible_scans': list(scans.values())[:max_groups], 'omitted_scan_sources': max(0, len(scans)-max_groups),
              'limitations': limitations, 'tuning_candidates': tuning(meta, totals, len(events))}
    report['summary'] = render(report)
    return report


def tuning(meta, totals, total):
    candidates = []
    http = totals['120:3']+totals['120:18']
    if http:
        candidates.append(f'HTTP inspection 120:3/120:18 accounts for {http}/{total} alerts. Correlate endpoint/proxy behavior before narrowly filtering.')
    for instance in meta.get('instances', []):
        candidates.append(f"{instance['interface']}: review enabled categories and HOME_NET/EXTERNAL_NET against intended coverage; retain current detection mode.")
        if instance.get('suppressions'):
            candidates.append(f"{instance['interface']}: existing suppression/filter directives are included in configuration; preserve their narrow scope and account for baseline changes.")
    candidates.append('Review informational connectivity/developer signatures as expected activity; retain rare DNS and SSH anomalies for endpoint investigation.')
    candidates.append('Verify effective log retention and rule-update success; configured schedules alone do not prove successful updates.')
    return candidates


def render(r):
    lines = [f"Snort daily report: {r['window']['start']} to {r['window']['end']} (end exclusive)",
             f"Collection: {'complete without detected errors' if r['collection_ok'] else 'INCOMPLETE / FAILED'}",
             f"{r['total_alerts']} alerts across {r['signature_count']} signatures; {r['baseline']['events']} baseline alerts."]
    lines += ['Collection issue: '+x for x in r['issues']]
    for g in r['findings'][:30]:
        reasons = '; '.join(g['reasons']) or 'Informational/context; no configured heuristic triggered'
        lines.append(f"{g['interface']} {g['signature']} priority={g['priority']} count={g['count']} "
                     f"{g['source']} -> {g['destination']}:{g['destination_port']} {g['protocol']} | {g['message']} | {reasons}")
    lines.append(f"Additional groups outside summary: {max(0, len(r['findings'])-30)}; outside structured report: {r['omitted_groups']}")
    lines += ['Possible scan: '+json.dumps(s, sort_keys=True) for s in r['possible_scans'][:10]]
    lines += ['Tuning: '+x for x in r['tuning_candidates']]
    lines += ['Limit: '+x for x in r['limitations']]
    return '\n'.join(lines)
