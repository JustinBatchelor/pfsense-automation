#!/usr/bin/env python3
"""Content-addressed OpenShift binary build; JSON output, no embedded credentials."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def oc(*args, data=None):
    return subprocess.check_output(["oc", *args], input=data, text=True)


def build(namespace, name, base):
    root = Path(__file__).resolve().parents[1]
    digest = hashlib.sha256(base.encode())
    for path in sorted((root / "ee").iterdir()):
        if path.is_file():
            digest.update(path.name.encode() + path.read_bytes())
    tag = digest.hexdigest()[:24]
    target = f"{name}:{tag}"
    exists = subprocess.run(
        ["oc", "-n", namespace, "get", "istag", target, "-o", "json"],
        capture_output=True,
        text=True,
    )
    changed = exists.returncode != 0
    if changed:
        resources = {
            "apiVersion": "v1",
            "kind": "List",
            "items": [
                {
                    "apiVersion": "image.openshift.io/v1",
                    "kind": "ImageStream",
                    "metadata": {"name": name, "namespace": namespace},
                },
                {
                    "apiVersion": "build.openshift.io/v1",
                    "kind": "BuildConfig",
                    "metadata": {"name": name, "namespace": namespace},
                    "spec": {
                        "runPolicy": "Serial",
                        "source": {"type": "Binary", "binary": {}},
                        "strategy": {
                            "type": "Docker",
                            "dockerStrategy": {
                                "dockerfilePath": "Containerfile",
                                "buildArgs": [{"name": "EE_BASE_IMAGE", "value": base}],
                            },
                        },
                        "output": {"to": {"kind": "ImageStreamTag", "name": target}},
                        "triggers": [],
                    },
                },
            ],
        }
        oc("apply", "-f", "-", data=json.dumps(resources))
        # Build logs go to stderr; stdout is exclusively the result consumed by Ansible.
        p = subprocess.run(
            [
                "oc",
                "-n",
                namespace,
                "start-build",
                name,
                "--from-dir",
                str(root / "ee"),
                "--wait",
                "--follow",
            ],
            stdout=sys.stderr,
        )
        if p.returncode:
            raise RuntimeError(
                "Execution image build failed; inspect the OpenShift build log"
            )
        image = json.loads(oc("-n", namespace, "get", "istag", target, "-o", "json"))
    else:
        image = json.loads(exists.stdout)
    immutable = image["image"]["dockerImageReference"]
    if "@sha256:" not in immutable:
        immutable = f"image-registry.openshift-image-registry.svc:5000/{namespace}/{name}@{image['image']['metadata']['name']}"
    return {"changed": changed, "image": immutable, "tag": tag}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--base", required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.namespace, args.name, args.base)))
