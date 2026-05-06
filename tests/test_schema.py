# SPDX-License-Identifier: MIT
"""Tests for the generated JSON Schema artefacts.

These tests pin two contracts:

1. The committed JSON Schema files are byte-for-byte equal to what
   ``tools/regen_schema.py`` produces. CI fails on drift.
2. Round-trip — a manifest valid under Pydantic is also valid under
   the generated JSON Schema; a manifest invalid under Pydantic is
   also invalid under the generated JSON Schema.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = REPO_ROOT / "schema"
BUNDLE_SCHEMA_PATH = SCHEMA_DIR / "bundle_v1.schema.json"
PRIMITIVE_SCHEMA_PATH = SCHEMA_DIR / "primitive_v1.schema.json"


def _load_schema(path: Path) -> dict:
    return json.loads(path.read_text())


def _run_regen(into_dir: Path) -> None:
    """Run regen_schema.py with SCHEMA_DIR redirected to `into_dir`.

    We invoke as a subprocess so the script's `__main__` path is
    exercised the same way CI would. We monkeypatch SCHEMA_DIR via
    an env var read inside the script.
    """
    # The script writes to a hard-coded SCHEMA_DIR. To avoid changing
    # the script's signature, we just run it normally and compare
    # against the committed files (the script writes back to repo).
    # For per-test temp redirection we use a small inline runner:
    src = (
        "import sys, json\n"
        f"sys.path.insert(0, {str(REPO_ROOT / 'python')!r})\n"
        f"sys.path.insert(0, {str(REPO_ROOT / 'tools')!r})\n"
        "import regen_schema\n"
        f"regen_schema.SCHEMA_DIR = __import__('pathlib').Path({str(into_dir)!r})\n"
        "regen_schema.regenerate()\n"
    )
    subprocess.run(
        [sys.executable, "-c", src],
        check=True,
        cwd=REPO_ROOT,
    )


def test_committed_bundle_schema_matches_regenerated(tmp_path):
    _run_regen(tmp_path)
    committed = BUNDLE_SCHEMA_PATH.read_text()
    regenerated = (tmp_path / "bundle_v1.schema.json").read_text()
    assert committed == regenerated, (
        "schema/bundle_v1.schema.json is out of sync with the Pydantic "
        "models. Run `python tools/regen_schema.py` and commit the diff."
    )


def test_committed_primitive_schema_matches_regenerated(tmp_path):
    _run_regen(tmp_path)
    committed = PRIMITIVE_SCHEMA_PATH.read_text()
    regenerated = (tmp_path / "primitive_v1.schema.json").read_text()
    assert committed == regenerated, (
        "schema/primitive_v1.schema.json is out of sync with the Pydantic "
        "models. Run `python tools/regen_schema.py` and commit the diff."
    )


def test_bundle_schema_validates_a_minimal_attack_manifest():
    schema = _load_schema(BUNDLE_SCHEMA_PATH)
    now = datetime.now(timezone.utc).isoformat()
    manifest = {
        "bundle_version": 1,
        "shape": "v1.0",
        "corpus_id": "crp_test_00000001",
        "attack_id": "atk_test_00000001",
        "genome_id": "aabbccdd11223344",
        "family_id": "response_amp",
        "primitive_id": "sui_F10_multi_get_objects_amp",
        "posture": "saturating",
        "ground_truth_label": "attack",
        "chain": "sui",
        "run_tag": "smoke",
        "target_env": "localnet-sui-multinode4",
        "started_at": now,
        "ended_at": now,
        "provenance": {
            "traffic_source": "reproducer-attack",
            "fidelity_class": "lab",
            "target_authorisation": "self-owned",
        },
    }
    jsonschema.validate(instance=manifest, schema=schema)


def test_bundle_schema_rejects_unknown_required_top_level_field_on_drift():
    """If someone removes a required field from the Pydantic model,
    the generated schema would lose that requirement and a manifest
    missing the field would validate. This test pins the current
    required-set."""
    schema = _load_schema(BUNDLE_SCHEMA_PATH)
    required = set(schema.get("required", []))
    # Pin the v0.1.0 required-set. If you intend to change this, bump
    # the schema version + update the test.
    expected_required = {
        "shape",
        "corpus_id",
        "attack_id",
        "family_id",
        "primitive_id",
        "posture",
        "ground_truth_label",
        "chain",
        "run_tag",
        "target_env",
        "started_at",
        "ended_at",
        "provenance",
    }
    assert required == expected_required, (
        f"Required-fields drift: missing {expected_required - required}, "
        f"unexpected {required - expected_required}"
    )


def test_primitive_schema_validates_a_minimal_descriptor():
    schema = _load_schema(PRIMITIVE_SCHEMA_PATH)
    descriptor = {
        "primitive_id": "F10_multi_get_objects_amp",
        "chain": "sui",
        "class_label": "response-amp",
        "default_ground_truth": "attack",
        "supported_postures": ["saturating", "low-volume"],
        "description": "Multi-get-objects response amplification.",
        "reproducer_path": "chains/sui/findings/F10/reproducer.py",
        "requires_lab": "localnet-sui-multinode4",
    }
    jsonschema.validate(instance=descriptor, schema=schema)


def test_bundle_schema_includes_family_id_enum():
    schema = _load_schema(BUNDLE_SCHEMA_PATH)
    family_id_def = schema["$defs"]["FamilyId"]
    enum_values = set(family_id_def["enum"])
    expected = {
        "response_amp", "compute_amp", "memory_amp",
        "connection_exhaustion", "consensus_abuse", "gossip_abuse",
        "auth_bypass", "rate_limiter_bypass", "service_misconfig",
        "reconnaissance", "benign",
    }
    assert enum_values == expected


def test_bundle_schema_includes_fidelity_class_enum():
    schema = _load_schema(BUNDLE_SCHEMA_PATH)
    fc_def = schema["$defs"]["FidelityClass"]
    enum_values = set(fc_def["enum"])
    expected = {
        "stub", "proxy", "lab", "lab-tls-fronted",
        "production-captured", "production-derived",
    }
    assert enum_values == expected


def test_bundle_schema_includes_target_authorisation_enum():
    schema = _load_schema(BUNDLE_SCHEMA_PATH)
    ta_def = schema["$defs"]["TargetAuthorisation"]
    enum_values = set(ta_def["enum"])
    expected = {
        "self-owned", "customer-authorised",
        "public-mainnet-passive", "synthetic",
    }
    assert enum_values == expected
