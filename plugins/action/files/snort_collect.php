<?php
// Read-only, stdin-fed collector. No pfSense includes that could save configuration.
// Parameters are numeric constants substituted by the trusted action plugin.
$end = __REPORT_END__; if (!$end) $end = time();
$old = $end - 8 * 86400;
$limit = __MAX_BYTES__;
$started = microtime(true);
$runtime_warning = false;
set_error_handler(function() use (&$runtime_warning) { $runtime_warning = true; return true; });
function emit($value) { echo json_encode($value, JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES)."\n"; }
function pick($node, $names) {
    $out = []; foreach (explode(' ', $names) as $name) if (isset($node->$name)) $out[$name] = (string)$node->$name;
    return $out;
}
function issue($message) { emit(['type'=>'issue', 'message'=>$message]); }
$before = hash_file('sha256', '/conf/config.xml');
$x = simplexml_load_file('/conf/config.xml', 'SimpleXMLElement', LIBXML_NONET);
if ($x === false) { issue('Cannot read firewall configuration'); exit(1); }
$s = $x->installedpackages->snortglobal;
$meta = ['type'=>'metadata', 'schema_version'=>1, 'end'=>$end, 'timezone'=>(string)$x->system->timezone,
    'config_sha256_before'=>$before, 'version'=>trim(file_get_contents('/etc/version')),
    'global'=>pick($s, 'snortdownload snortcommunityrules emergingthreats emergingthreats_pro enable_feodo_botnet_c2_rules autorulesupdate7 rule_update_starttime enable_log_mgmt alert_log_limit_size alert_log_retention'),
    'instances'=>[], 'snort_processes'=>count(array_filter(explode("\n", trim(shell_exec('/usr/bin/pgrep -x snort') ?? ''))))];
$update_log = '/var/log/snort/snort_rules_update.log';
$meta['rule_update_log'] = ['available'=>is_readable($update_log),
    'mtime'=>is_readable($update_log) ? filemtime($update_log) : null,
    'note'=>'Log modification time is not proof of update success; review updater status separately.'];
$files = [];
foreach ($s->rule as $r) {
    if ((string)$r->enable !== 'on') continue;
    $name = (string)$r->interface; $uuid = (string)$r->uuid;
    $dev = (string)$x->interfaces->$name->if;
    if (!preg_match('/^[a-zA-Z0-9_]+$/', $name) || !preg_match('/^[a-zA-Z0-9_.]+$/', $dev) || !ctype_digit($uuid)) {
        issue('Unsupported Snort instance identity'); continue;
    }
    $dir = '/usr/local/etc/snort/snort_'.$uuid.'_'.$dev;
    $conf = $dir.'/snort.conf';
    $instance = pick($r, 'interface uuid ips_mode blockoffenders7 homelistname externallistname suppresslistname rulesets');
    $instance['runtime'] = []; $instance['suppressions'] = []; $instance['columns'] = [];
    $instance['config_mtime'] = is_file($conf) ? filemtime($conf) : null;
    if (!is_readable($conf)) { issue('Missing generated configuration for '.$name); }
    else foreach (file($conf) as $line) {
        $line = trim($line);
        if (preg_match('/^ipvar (HOME_NET|EXTERNAL_NET)\s+/', $line)) $instance['runtime'][] = $line;
        if (preg_match('/^output alert_csv:\s+alert\s+(\S+)/', $line, $m)) $instance['columns'] = explode(',', $m[1]);
        if (preg_match('/^include\s+(.+)/', $line, $m)) {
            $path = realpath(trim($m[1]));
            if ($path && str_starts_with($path, $dir.'/') && str_starts_with(basename($path), 'supp') && is_readable($path))
                foreach (file($path) as $directive)
                    if (preg_match('/^\s*(suppress|event_filter|threshold)\s+gen_id\b/', $directive))
                        $instance['suppressions'][] = trim(explode('#', $directive, 2)[0]);
        }
    }
    $required = ['timestamp','sig_generator','sig_id','sig_rev','msg','proto','src','srcport','dst','dstport','classification','priority','action','disposition'];
    $valid = !array_diff($required, $instance['columns']);
    if (!$valid) issue('Unsupported or missing CSV output columns for '.$name);
    $meta['instances'][] = $instance;
    if (!$valid) continue;
    $paths = glob('/var/log/snort/snort_'.$dev.$uuid.'/alert*');
    if (!$paths) issue('No retained alert files for '.$name);
    foreach ($paths as $path) {
        if (!preg_match('/^alert(?:\.\d+)?(?:\.gz)?$/', basename($path))) {
            issue('Unsupported alert rotation for '.$name); continue;
        }
        if (is_link($path) || !is_file($path)) { issue('Unexpected alert file type for '.$name); continue; }
        $stat = stat($path);
        if ($stat['mtime'] < $old) continue;
        $files[] = ['path'=>$path,'interface'=>$name,'columns'=>$instance['columns'],'size'=>$stat['size'],'ino'=>$stat['ino']];
    }
}
emit($meta);
if (!$meta['instances']) issue('No enabled Snort instances');
if ($meta['snort_processes'] < count($meta['instances'])) issue('Fewer Snort processes than enabled instances');
// Read newest files first so a bounded run retains the daily report before older history.
usort($files, fn($a,$b)=>filemtime($b['path']) <=> filemtime($a['path']));
$bytes = 0; $records = 0; $seen = [];
foreach ($files as $f) {
    $path = $f['path']; clearstatcache(true, $path);
    if (!is_readable($path) || fileinode($path) !== $f['ino']) { issue('Alert file changed or became unreadable during discovery'); continue; }
    if (isset($seen[$f['ino']])) continue;
    $seen[$f['ino']] = true;
    $gz = str_ends_with($path, '.gz');
    $h = $gz ? gzopen($path, 'rb') : fopen($path, 'rb');
    if (!$h) { issue('Cannot open alert file'); continue; }
    $consumed = 0; $crc = $gz ? hash_init('crc32b') : null;
    while ($gz ? !gzeof($h) : $consumed < $f['size']) {
        if ($bytes >= $limit || microtime(true)-$started > 165) { issue('Collection input or time limit reached'); break 2; }
        $read_length = min(65537, $limit-$bytes+1);
        $line = $gz ? gzgets($h, $read_length) : fgets($h, min($read_length, $f['size']-$consumed+1));
        if ($line === false) {
            if (!$gz || !gzeof($h)) issue('Unexpected end or decompression error in alert file');
            break;
        }
        $n = strlen($line); $bytes += $n; $consumed += $n;
        if ($gz) hash_update($crc, $line);
        if (!str_ends_with($line, "\n")) {
            issue($bytes >= $limit ? 'Collection input limit reached' : 'Partial or oversized alert record'); break;
        }
        $v = str_getcsv(trim($line), ',', '"', '\\');
        if (count($v) !== count($f['columns'])) { issue('Malformed CSV record'); continue; }
        $v = array_combine($f['columns'], array_map('trim', $v));
        $safe = ['type'=>'event','interface'=>$f['interface']];
        foreach ($required as $key) $safe[$key] = $v[$key];
        emit($safe); $records++;
    }
    if ($gz) {
        gzclose($h);
        $raw = fopen($path, 'rb'); $trailer = false;
        if ($raw) {
            if (fseek($raw, -8, SEEK_END) === 0) $trailer = unpack('Vcrc/Vsize', fread($raw, 8));
            fclose($raw);
        }
        if (!$trailer || sprintf('%08x', $trailer['crc']) !== hash_final($crc) || $trailer['size'] !== $consumed % 4294967296)
            issue('Gzip checksum/length mismatch or unsupported concatenated gzip members');
    } else fclose($h);
    clearstatcache(true, $path);
    if (!is_file($path) || fileinode($path) !== $f['ino'] || filesize($path) < $f['size']) issue('Alert rotation or truncation during collection');
}
if ($runtime_warning) issue('PHP reported a read or decoding warning during collection');
$after = hash_file('sha256', '/conf/config.xml');
if ($after !== $before) issue('Firewall configuration changed during collection; repeat for a consistent snapshot');
emit(['type'=>'complete','bytes_read'=>$bytes,'records_read'=>$records,'files_considered'=>count($files),'config_sha256_after'=>$after]);
