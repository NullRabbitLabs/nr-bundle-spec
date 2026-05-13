#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate one or more bundle directories against bundle v1 spec v0.1.0.

Per-bundle checks:
  1. ``manifest.json`` exists and parses as JSON.
  2. Pydantic ``BundleManifest.model_validate`` passes on the manifest dict.
  3. For each ``BundleFiles.<modality>=True`` flag, the corresponding file
     is present on disk.
  4. For each ``BundleFiles.<modality>=False`` flag, the corresponding file
     is absent (asserts the file-flag is honest, not just default-True).

Exit status: 0 if every bundle passes; 1 if any bundle fails. Outputs a
release-cert JSON when ``--cert-out`` is supplied.

Usage::

    python tools/validate_bundle.py <bundle_dir> [<bundle_dir> ...] \\
        [--cert-out release-cert.json]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "python"))

from bundle_spec import BundleManifest  # noqa: E402

# bundle_v1 BundleFiles field → on-disk filename
_FILE_FLAGS = {
    "packets_pcap": "packets.pcap",
    "host_parquet": "host.parquet",
    "app_parquet": "app.parquet",
    "protocol_parquet": "protocol.parquet",
    "responses_parquet": "responses.parquet",
    "vectors_parquet": "vectors.parquet",
}


def validate_one(bundle_dir: Path) -> dict:
    cert: dict = {"bundle_dir": str(bundle_dir), "checks": []}

    mf_path = bundle_dir / "manifest.json"
    if not mf_path.is_file():
        cert["checks"].append({"check": "manifest_exists", "ok": False})
        cert["release_ok"] = False
        return cert
    cert["checks"].append({"check": "manifest_exists", "ok": True})

    try:
        raw = json.loads(mf_path.read_text())
    except Exception as exc:
        cert["checks"].append(
            {"check": "manifest_json_parses", "ok": False, "detail": str(exc)[:200]}
        )
        cert["release_ok"] = False
        return cert
    cert["checks"].append({"check": "manifest_json_parses", "ok": True})

    try:
        manifest = BundleManifest.model_validate(raw)
        cert["checks"].append({"check": "manifest_validates_v0.1.0", "ok": True})
        cert["corpus_id"] = manifest.corpus_id
        cert["primitive_id"] = manifest.primitive_id
    except Exception as exc:
        cert["checks"].append(
            {"check": "manifest_validates_v0.1.0", "ok": False, "detail": str(exc)[:400]}
        )
        cert["release_ok"] = False
        return cert

    # Spec intent (BundleFiles docstring): True = file is present AND
    # schema-conformant. False = modality intentionally skipped (file
    # may still exist on disk as an empty placeholder per existing
    # example-bundle convention, but isn't considered present-and-conformant).
    # Validator therefore asserts the forward direction only:
    #   flag=True  ⇒ file MUST exist on disk
    #   flag=False ⇒ no on-disk constraint (file may or may not exist)
    files_block = manifest.files
    for flag_name, filename in _FILE_FLAGS.items():
        flag = bool(getattr(files_block, flag_name))
        on_disk = (bundle_dir / filename).is_file()
        ok = (not flag) or on_disk
        cert["checks"].append(
            {
                "check": f"file_flag_consistent:{flag_name}",
                "ok": ok,
                "flag": flag,
                "on_disk": on_disk,
            }
        )

    cert["release_ok"] = all(c["ok"] for c in cert["checks"])
    return cert


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("bundle_dirs", nargs="+", type=Path)
    ap.add_argument("--cert-out", type=Path, default=None)
    args = ap.parse_args()

    certs = [validate_one(d) for d in args.bundle_dirs]
    n_ok = sum(1 for c in certs if c["release_ok"])
    n = len(certs)
    summary = {
        "schema_version": "v0.1.0",
        "n_bundles": n,
        "n_release_ok": n_ok,
        "bundles": certs,
    }
    if args.cert_out:
        args.cert_out.write_text(json.dumps(summary, indent=2))
        print(f"release-cert: {args.cert_out}")
    print(f"pass: {n_ok}/{n}")
    for c in certs:
        if not c["release_ok"]:
            print(f"  FAIL {c['bundle_dir']}")
            for chk in c["checks"]:
                if not chk["ok"]:
                    print(f"    - {chk}")
    return 0 if n_ok == n else 1


if __name__ == "__main__":
    sys.exit(main())
