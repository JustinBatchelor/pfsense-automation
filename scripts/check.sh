#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ ! -x .tools/bin/python ]]; then
  echo 'Create .tools with Python 3.12 and install requirements-dev.txt first.' >&2
  exit 1
fi
export PATH="$PWD/.tools/bin:$PATH"
export ANSIBLE_LOCAL_TEMP="$PWD/.ansible/tmp"
.tools/bin/python -c 'import sys; assert sys.prefix != sys.base_prefix'
.tools/bin/pytest -q
.tools/bin/yamllint .
.tools/bin/ansible-lint --offline
for playbook in playbooks/*.yml; do
  .tools/bin/ansible-playbook "$playbook" --syntax-check
done
