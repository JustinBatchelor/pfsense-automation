"""Run read-only SSH collection locally in the execution environment."""
import os
from pathlib import Path
import sys

from ansible.plugins.action import ActionBase

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'module_utils'))
from snort_report import analyze, collect  # noqa: E402


class ActionModule(ActionBase):
    TRANSFERS_FILES = False

    def run(self, tmp=None, task_vars=None):
        result = super().run(tmp, task_vars)
        args = self._task.args
        try:
            if sys.prefix == sys.base_prefix or ((task_vars or {}).get('awx_job_id') and sys.prefix != '/opt/venv'):
                raise ValueError('An isolated execution environment is required')
            messages = collect(
                Path(__file__).parent / 'files/snort_collect.php',
                host=args['host'], user=args.get('user', 'admin'),
                known_hosts=os.path.expanduser(args.get('known_hosts') or os.environ.get('PFSENSE_KNOWN_HOSTS_FILE', '')),
                key_file=args.get('private_key_file') or self._play_context.private_key_file,
                end=int(args.get('end_epoch', 0)), max_bytes=int(args.get('max_bytes', 64*1024*1024)),
            )
            report = analyze(messages, min_count=int(args.get('min_count', 20)),
                             multiplier=float(args.get('multiplier', 5)),
                             scan_threshold=int(args.get('scan_threshold', 20)),
                             max_groups=int(args.get('max_groups', 100)))
        except (OSError, ValueError, KeyError) as exc:
            # Do not return invocation data, SSH diagnostics, or exception values from remote input.
            report = {'schema_version': 1, 'collection_ok': False,
                      'issues': ['Report failed: '+type(exc).__name__],
                      'summary': 'Report failed; verify SSH trust/access, supported timezone and report parameters.'}
        report['runtime'] = {'executable': sys.executable, 'prefix': sys.prefix, 'python': sys.version.split()[0]}
        result.update(changed=False, report=report)
        # The play publishes artifacts before asserting collection health.
        return result
