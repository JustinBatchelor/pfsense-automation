"""Synthetic records only: no household telemetry or credentials in fixtures."""
import copy
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import types

import pytest

from snort_report import analyze, collect, timestamp, DAY

ROOT = Path(__file__).resolve().parents[1]
END = int(datetime(2026, 11, 3, 11, 15, tzinfo=timezone.utc).timestamp())


def event(t=END-60, sid='10', priority='3', src='192.0.2.10', dst='198.51.100.20', port='443'):
    return dict(type='event', interface='lan', timestamp=datetime.fromtimestamp(t, timezone.utc).strftime('%m/%d/%y-%H:%M:%S.%f')+' ',
                sig_generator='1', sig_id=sid, sig_rev='1', msg='Synthetic, quoted alert', proto='TCP',
                src=src, srcport='42000', dst=dst, dstport=port, classification='Misc activity',
                priority=priority, action='alert', disposition='Allow')


def envelope(events=()):
    return [dict(type='metadata', schema_version=1, end=END, timezone='UTC', config_sha256_before='same',
                 instances=[dict(interface='lan', suppressions=[])])] + list(events) + [dict(type='complete', config_sha256_after='same')]


def test_exact_half_open_window_and_empty_vs_unavailable():
    r=analyze(envelope([event(END-DAY-0.001), event(END-DAY), event(END-0.001), event(END)]))
    assert r['total_alerts'] == 2 and r['baseline']['events'] == 1
    assert r['collection_ok'] and r['window']['seconds'] == 86400
    assert analyze(envelope())['total_alerts'] == 0
    assert not analyze([])['collection_ok']
    assert not analyze(envelope()+[{'type':'issue','message':'No retained alert files'}])['collection_ok']


def test_year_rollover_timezone_and_dst():
    end = datetime(2027,1,1,3,tzinfo=timezone.utc).timestamp()
    assert timestamp('12/31-22:00:00.000001 ',end,'UTC') < end
    assert timestamp('01/01/2027-00:00:00',end,'UTC') == end-10800
    assert timestamp('11/03/26-06:15:00',END,'EST5EDT') == END
    with pytest.raises(ValueError, match='Ambiguous'):
        timestamp('11/01/26-01:30:00.000000',END,'America/New_York')
    with pytest.raises(ValueError, match='Nonexistent'):
        timestamp('03/08/26-02:30:00',END,'America/New_York')


def test_ipv6_icmp_quoted_message_and_malformed_metadata():
    e=event(src='2001:db8::1',dst='2001:db8::2',port=''); e.update(srcport='',proto='ICMP6')
    r=analyze(envelope([e])); assert r['collection_ok']
    assert r['findings'][0]['destination_port'] is None
    bad=copy.deepcopy(e);bad['src']='not-an-address'
    r=analyze(envelope([bad])); assert not r['collection_ok'] and r['parse_failures']==1
    assert 'not-an-address' not in json.dumps(r)


def test_priority_novelty_volume_baseline_shortage_and_revisions():
    history=[event(END-i*DAY, sid='10') for i in (2,3,4,5,6,7)]
    current=[event(sid='10') for _ in range(30)]+[event(sid='20',priority='1')]
    current[0]['sig_rev']='2'
    r=analyze(envelope(history+current))
    assert r['baseline']['volume_comparison_enabled']
    high=r['findings'][0]; assert high['signature']=='1:20'
    assert any('Priority 1' in x for x in high['reasons'])
    assert any('not seen' in x for x in high['reasons'])
    volume=next(g for g in r['findings'] if g['signature']=='1:10')
    assert volume['revisions']==[1,2] and any('volume' in x for x in volume['reasons'])
    r=analyze(envelope([event(END-2*DAY)]+current))
    assert not r['baseline']['volume_comparison_enabled']
    assert not any('volume' in x for g in r['findings'] for x in g['reasons'])


def test_scan_rolling_ten_minutes_and_output_caps():
    rows=[event(END-100+i,dst=f'198.51.100.{i+1}') for i in range(20)]
    r=analyze(envelope(rows),max_groups=5)
    assert len(r['possible_scans'])==1 and r['possible_scans'][0]['destination_hosts']==20
    assert len(r['findings'])==5 and r['omitted_groups']==15
    rows[0]=event(END-1000,dst='198.51.100.1')
    assert not analyze(envelope(rows))['possible_scans']


def test_missing_completion_checksum_drift_and_sanitized_text():
    assert not analyze(envelope()[:-1])['collection_ok']
    rows=envelope();rows[-1]['config_sha256_after']='different'
    assert not analyze(rows)['collection_ok']
    e=event();e['msg']='hello\x1b\nworld'
    r=analyze(envelope([e]))
    assert r['findings'][0]['message']=='helloworld'


@pytest.fixture
def fake_ssh(tmp_path,monkeypatch):
    bindir=tmp_path/'bin';bindir.mkdir()
    fixture=tmp_path/'messages.jsonl'
    fixture.write_text('\n'.join(json.dumps(m) for m in envelope([event(priority='2')]))+'\n')
    ssh=bindir/'ssh'
    ssh.write_text('#!'+sys.executable+'\n'+'''import os,sys,time
args=sys.argv[1:]
assert 'StrictHostKeyChecking=yes' in args and 'BatchMode=yes' in args
assert '-F' in args and '/dev/null' in args
script=sys.stdin.read()
assert '__REPORT_END__' not in script and '__MAX_BYTES__' not in script
assert 'write_config' not in script and 'file_put_contents' not in script
if os.environ.get('MOCK_SLEEP'): time.sleep(3)
print(open(os.environ['MOCK_MESSAGES']).read(),end='')
sys.stderr.write('private-diagnostic-marker')
sys.exit(int(os.environ.get('MOCK_EXIT','0')))
''')
    ssh.chmod(0o755)
    known=tmp_path/'known_hosts';known.write_text('synthetic trust')
    monkeypatch.setenv('PATH',str(bindir)+os.pathsep+os.environ['PATH'])
    monkeypatch.setenv('MOCK_MESSAGES',str(fixture))
    return known,fixture


def test_ssh_transport_is_read_only_bounded_and_redacts_diagnostics(fake_ssh,monkeypatch):
    known,_=fake_ssh
    kwargs=dict(script=ROOT/'plugins/action/files/snort_collect.php',host='firewall.example',user='admin',known_hosts=known)
    r=analyze(collect(**kwargs))
    assert r['collection_ok'] and r['total_alerts']==1
    monkeypatch.setenv('MOCK_EXIT','255')
    r=analyze(collect(**kwargs));assert not r['collection_ok']
    assert 'private-diagnostic-marker' not in json.dumps(r)
    monkeypatch.setenv('MOCK_SLEEP','1')
    r=analyze(collect(**kwargs,timeout=1));assert not r['collection_ok']
    with pytest.raises(ValueError,match='hostname'):
        collect(**{**kwargs,'host':'-oProxyCommand=bad'})


def test_real_ansible_report_playbook_and_failure_publishes_diagnostics(fake_ssh,tmp_path):
    known,fixture=fake_ssh
    env={**os.environ,'ANSIBLE_LOCAL_TEMP':str(tmp_path/'ansible'),'PFSENSE_KNOWN_HOSTS_FILE':str(known)}
    cmd=[str(ROOT/'.tools/bin/ansible-playbook'),'-i','localhost,','playbooks/snort_report.yml',
         '-e',json.dumps({'pfsense_address':'firewall.example','ansible_connection':'local'})]
    p=subprocess.run(cmd,cwd=ROOT,env=env,text=True,capture_output=True)
    assert p.returncode==0,p.stdout+p.stderr
    assert '1 alerts across 1 signatures' in p.stdout and 'changed=0' in p.stdout
    assert 'private-diagnostic-marker' not in p.stdout+p.stderr
    with fixture.open('a') as f:f.write(json.dumps({'type':'issue','message':'Synthetic rotation gap'})+'\n')
    p=subprocess.run(cmd+['--check'],cwd=ROOT,env=env,text=True,capture_output=True)
    assert p.returncode!=0 and 'Synthetic rotation gap' in p.stdout
    assert 'Publish structured report' in p.stdout and 'INCOMPLETE' in p.stdout


def test_schedule_uses_verified_typed_template_and_handles_disable(monkeypatch):
    calls=[]
    class Done(Exception): pass
    class Fake:
        params={'job_template_id':123,'name':'daily','rrule':'fixed','enabled':False,'create_if_missing':False}
        verify_ssl=True
        def __init__(self,**kwargs):pass
        def get_endpoint(self,path):calls.append(path);return {'status_code':200,'json':{'id':123}}
        def get_one(self,resource,data):calls.append((resource,data));return None
        def exit_json(self,**kwargs):calls.append(kwargs);raise Done()
        def fail_json(self,**kwargs):raise AssertionError(kwargs)
        def create_or_update_if_needed(self,*args,**kwargs):calls.append((args,kwargs))
    module=types.ModuleType('controller_api');module.ControllerAPIModule=Fake
    monkeypatch.setitem(sys.modules,'ansible_collections.ansible.controller.plugins.module_utils.controller_api',module)
    spec=importlib.util.spec_from_file_location('job_schedule',ROOT/'plugins/modules/aap_job_schedule.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    with pytest.raises(Done):mod.main()
    assert calls[0]=='job_templates/123/'
    assert calls[1][1]['unified_job_template']==123
    assert calls[-1]=={'changed':False}
    Fake.params={**Fake.params,'create_if_missing':True,'enabled':True}
    mod.main()
    assert calls[-1][0][1]['unified_job_template']==123
    assert calls[-1][0][1]['enabled'] is True
    Fake.verify_ssl=False
    with pytest.raises(AssertionError,match='TLS'):mod.main()


def test_dst_ambiguity_counted_only_with_unambiguous_window_membership():
    rows=envelope([event()])
    rows[0]['timezone']='America/New_York'
    rows[1]['timestamp']='11/01/26-01:30:00.000000'
    r=analyze(rows)
    assert r['collection_ok'] and r['ambiguous_timestamps']==1
    assert r['baseline']['events']==1
    assert any('repeated DST' in x for x in r['limitations'])
    rows[0]['end']=int(datetime(2026,11,1,5,45,tzinfo=timezone.utc).timestamp())
    r=analyze(rows)
    assert not r['collection_ok'] and r['parse_failures']==1


@pytest.fixture
def php():
    """Use PHP_TEST_BIN/ARGS in CI or an available native PHP CLI."""
    import shlex
    import shutil
    executable=os.environ.get('PHP_TEST_BIN') or shutil.which('php')
    if not executable:
        pytest.skip('PHP CLI required for collector fixture tests; set PHP_TEST_BIN')
    return [executable]+shlex.split(os.environ.get('PHP_TEST_ARGS',''))


def php_fixture(tmp_path, php, rows, *, compressed=False, partial=False, max_bytes=67108864, columns=None, corrupt=False):
    import csv
    import gzip
    import io
    cols=columns or 'timestamp,sig_generator,sig_id,sig_rev,msg,proto,src,srcport,dst,dstport,classification,priority,action,disposition'.split(',')
    config=tmp_path/'config.xml'
    config.write_text('''<pfsense><system><timezone>UTC</timezone></system><interfaces><lan><if>test0</if></lan></interfaces>
<installedpackages><snortglobal><secret>must-not-export</secret><rule><interface>lan</interface><uuid>123</uuid><enable>on</enable></rule></snortglobal></installedpackages></pfsense>''')
    confdir=tmp_path/'etc/snort_123_test0';confdir.mkdir(parents=True)
    (confdir/'snort.conf').write_text('output alert_csv: alert '+','.join(cols)+' 500K\n')
    logdir=tmp_path/'log/snort_test0123';logdir.mkdir(parents=True)
    stream=io.StringIO();writer=csv.writer(stream,lineterminator='\n')
    for row in rows:writer.writerow([row.get(c,'') for c in cols])
    data=stream.getvalue().encode()
    if partial:data=data.rstrip(b'\n')
    log=logdir/('alert.123.gz' if compressed else 'alert')
    log.write_bytes(gzip.compress(data) if compressed else data)
    if corrupt:log.write_bytes(log.read_bytes()[:-4])
    code=(ROOT/'plugins/action/files/snort_collect.php').read_text()
    # Replace only filesystem roots and process-health probe in the test copy.
    code=code.replace('/conf/config.xml',str(config)).replace('/usr/local/etc/snort',str(tmp_path/'etc'))
    code=code.replace('/var/log/snort',str(tmp_path/'log')).replace("trim(file_get_contents('/etc/version'))","'test'")
    code=code.replace("shell_exec('/usr/bin/pgrep -x snort')","'123'")
    code=code.replace('__REPORT_END__',str(END)).replace('__MAX_BYTES__',str(max_bytes))
    p=subprocess.run(php,input=code,text=True,capture_output=True)
    assert p.returncode==0,p.stderr
    assert 'must-not-export' not in p.stdout+p.stderr
    return [json.loads(line) for line in p.stdout.splitlines()]


@pytest.mark.parametrize('compressed',[False,True])
def test_real_php_collector_csv_and_gzip_preserves_metadata(tmp_path,php,compressed):
    rows=php_fixture(tmp_path,php,[event(),event(END-DAY-60)],compressed=compressed)
    r=analyze(rows)
    assert r['collection_ok'],r['issues']
    assert r['total_alerts']==1 and r['baseline']['events']==1
    assert r['findings'][0]['message']=='Synthetic, quoted alert'


def test_real_php_partial_record_and_input_cap_are_not_clean(tmp_path,php):
    rows=php_fixture(tmp_path,php,[event()],partial=True)
    r=analyze(rows)
    assert not r['collection_ok'] and any('Partial' in x for x in r['issues'])


def test_real_php_input_cap_reports_incomplete(tmp_path,php):
    rows=php_fixture(tmp_path,php,[event() for _ in range(100)],max_bytes=1024)
    r=analyze(rows)
    assert not r['collection_ok'] and any('limit' in x for x in r['issues'])


def test_real_php_unknown_format_fails_explicitly(tmp_path,php):
    rows=php_fixture(tmp_path,php,[event()],columns=['timestamp','msg'])
    r=analyze(rows)
    assert not r['collection_ok'] and any('CSV output' in x for x in r['issues'])


@pytest.mark.parametrize('compressed',[False,True])
def test_real_php_empty_log_is_not_a_collection_failure(tmp_path,php,compressed):
    r=analyze(php_fixture(tmp_path,php,[],compressed=compressed))
    assert r['collection_ok'],r['issues']
    assert r['total_alerts']==0


def test_real_php_corrupt_gzip_fails_explicitly(tmp_path,php):
    r=analyze(php_fixture(tmp_path,php,[event()],compressed=True,corrupt=True))
    assert not r['collection_ok'] and any('checksum' in x for x in r['issues'])
