#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Strip post-termination cleartext pcap from a bundle directory.

Per the HF-DATASET-AUDIT findings (HF-DATASET-AUDIT-2026-05-05.md
Option A), the cleanest path to publish a lab-tls-fronted bundle is
to drop ``packets.pcap`` (post-term cleartext loopback, contains
HTTP/JSON-RPC payload) and keep only ``pcap_pre_termination.pcap``
(pre-term TLS frames, no cleartext leak). The pre-term wire shows
only encrypted bytes + IP/TCP headers; safe for public release.

This tool:
1. Confirms ``pcap_pre_termination.pcap`` exists in the source bundle.
2. Copies the bundle to the destination directory.
3. Removes ``packets.pcap`` from the destination copy.
4. Re-emits ``manifest.json`` with ``files.packets_pcap=False``.
5. Validates the resulting manifest against the v0.1.0 JSON Schema.

Usage::

    python tools/strip_pcap.py <src_bundle_dir> <dst_bundle_dir>

The destination directory must not already exist; the tool refuses
to overwrite to prevent accidental data loss.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "python"))

from bundle_spec import BundleManifest  # noqa: E402


def strip_bundle(src: Path, dst: Path) -> None:
    if not src.is_dir():
        raise FileNotFoundError(f"source bundle not found: {src}")
    if dst.exists():
        raise FileExistsError(
            f"destination already exists: {dst} "
            "(refusing to overwrite; remove it first if you really want)"
        )

    pre_term = src / "pcap_pre_termination.pcap"
    if not pre_term.exists():
        raise FileNotFoundError(
            f"source bundle has no pcap_pre_termination.pcap: {src} "
            "(is it really a lab-tls-fronted bundle?)"
        )

    # Copy everything, then strip the post-term pcap.
    shutil.copytree(src, dst)
    post_term = dst / "packets.pcap"
    if post_term.exists():
        post_term.unlink()
        print(f"removed {post_term.relative_to(dst.parent)}")

    # Re-emit manifest with packets_pcap=False.
    manifest_path = dst / "manifest.json"
    raw = json.loads(manifest_path.read_text())
    raw.setdefault("files", {})["packets_pcap"] = False
    # Validate against the v0.1.0 schema before writing back.
    parsed = BundleManifest.model_validate(raw)
    manifest_path.write_text(parsed.model_dump_json(indent=2) + "\n")
    print(f"updated {manifest_path.relative_to(dst.parent)} (packets_pcap=False)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("src", type=Path, help="source bundle directory")
    parser.add_argument("dst", type=Path, help="destination bundle directory")
    args = parser.parse_args()
    strip_bundle(args.src, args.dst)
    return 0


if __name__ == "__main__":
    sys.exit(main())
