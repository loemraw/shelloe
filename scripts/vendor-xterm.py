#!/usr/bin/env python3
"""Vendor xterm.js and its add-ons into web/vendor/.

The pins are in vendor-xterm.json, next to this script: each npm package's
version, its tarball's sha512 integrity, and the files to take from it.

Downloads the pinned npm tarballs, checks each against its pinned integrity,
and writes the listed files unmodified into web/vendor/. Any other file
directly in web/vendor/ is deleted. Nothing is written if a download fails
verification or a listed file is missing from its tarball.

To move to a new version, change the version and the integrity in the pins.
The integrity is the registry's dist.integrity:

    curl -s https://registry.npmjs.org/<name>/<version>

js-base64 is bundled inside addon-clipboard.mjs and only its license is
shipped. Pin the version that bundle contains: the VERSION it exports.
"""

import base64
import hashlib
import io
import json
import sys
import tarfile
import urllib.request
from pathlib import Path

PINS = json.loads(Path(__file__).resolve().with_suffix(".json").read_text())

VENDOR_DIR = Path(__file__).resolve().parent.parent / "web" / "vendor"


def tarball_url(name, version):
    bare_name = name.split("/")[-1]
    return f"https://registry.npmjs.org/{name}/-/{bare_name}-{version}.tgz"


def fetch_verified(pin):
    with urllib.request.urlopen(tarball_url(pin["name"], pin["version"])) as response:
        data = response.read()
    digest = base64.b64encode(hashlib.sha512(data).digest()).decode()
    if "sha512-" + digest != pin["integrity"]:
        sys.exit(f"integrity mismatch for {pin['name']}@{pin['version']}")
    return data


def read_members(pin, data):
    contents = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member_path, out_name in pin["files"].items():
            try:
                member = tar.extractfile(member_path)
            except KeyError:
                member = None
            if member is None:
                sys.exit(f"{pin['name']}@{pin['version']}: missing {member_path}")
            contents[out_name] = member.read()
    return contents


def main():
    outputs = {}
    for pin in PINS:
        outputs.update(read_members(pin, fetch_verified(pin)))

    VENDOR_DIR.mkdir(parents=True, exist_ok=True)
    for out_name, content in sorted(outputs.items()):
        (VENDOR_DIR / out_name).write_bytes(content)
        print(f"wrote web/vendor/{out_name}")
    for path in VENDOR_DIR.iterdir():
        if path.is_file() and path.name not in outputs:
            path.unlink()
            print(f"removed web/vendor/{path.name}")


main()
