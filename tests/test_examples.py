# SPDX-License-Identifier: MIT
"""Tests that every example bundle loads cleanly under v0.1.0."""

from __future__ import annotations

import json
from pathlib import Path

import pyarrow.parquet as pq
import pytest

from bundle_spec import (
    BundleManifest,
    app_ts_schema,
    host_ts_schema,
    protocol_ts_schema,
    responses_schema,
)

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"
EXAMPLE_NAMES = [
    "example_sui_F10_attack",
    "example_sui_F14_attack",
    "example_sui_benign",
    "example_SOL_F10_attack",
    "example_solana_benign",
]


@pytest.mark.parametrize("example", EXAMPLE_NAMES)
def test_example_manifest_validates(example: str) -> None:
    manifest_path = EXAMPLES_DIR / example / "manifest.json"
    raw = json.loads(manifest_path.read_text())
    m = BundleManifest.model_validate(raw)
    assert m.bundle_version == 1
    assert m.shape == "v1.0"
    assert m.provenance.fidelity_class.value == "lab-tls-fronted"
    assert m.provenance.target_authorisation.value == "self-owned"


@pytest.mark.parametrize("example", EXAMPLE_NAMES)
def test_example_packets_pcap_stripped(example: str) -> None:
    """Per HF-DATASET-AUDIT Option A, post-term cleartext pcap must
    be absent and the manifest must record packets_pcap=False."""
    bundle = EXAMPLES_DIR / example
    assert not (bundle / "packets.pcap").exists(), (
        f"{example} still contains packets.pcap — strip not applied"
    )
    raw = json.loads((bundle / "manifest.json").read_text())
    assert raw["files"]["packets_pcap"] is False


@pytest.mark.parametrize("example", EXAMPLE_NAMES)
def test_example_pre_term_pcap_present(example: str) -> None:
    bundle = EXAMPLES_DIR / example
    pre_term = bundle / "pcap_pre_termination.pcap"
    assert pre_term.exists() and pre_term.stat().st_size > 0


@pytest.mark.parametrize(
    "example,parquet_name,schema_fn",
    [
        (e, "host.parquet", host_ts_schema)
        for e in EXAMPLE_NAMES
    ]
    + [
        (e, "protocol.parquet", protocol_ts_schema)
        for e in EXAMPLE_NAMES
    ]
    + [
        (e, "responses.parquet", responses_schema)
        for e in EXAMPLE_NAMES
    ],
)
def test_example_parquet_schema_matches(example, parquet_name, schema_fn):
    """Each parquet file in each example must conform to the v0.1.0
    schema for its modality."""
    path = EXAMPLES_DIR / example / parquet_name
    if not path.exists():
        pytest.skip(f"{example}/{parquet_name} not present (acceptable for some bundles)")
    table = pq.read_table(path)
    expected = schema_fn()
    # Bundle parquets may carry extra columns (additive); the
    # contract is that the spec's required columns are present with
    # matching types. Check intersection.
    for required_field in expected:
        actual_field = table.schema.field_by_name(required_field.name)
        assert actual_field is not None, (
            f"{example}/{parquet_name} missing required column "
            f"'{required_field.name}'"
        )
        assert actual_field.type == required_field.type, (
            f"{example}/{parquet_name} column "
            f"'{required_field.name}' type mismatch: "
            f"expected {required_field.type}, got {actual_field.type}"
        )


def test_examples_dir_has_readme():
    assert (EXAMPLES_DIR / "README.md").exists()


def test_all_examples_self_owned():
    """No customer-authorised, no public-mainnet — all 5 examples
    must be from operator-owned infrastructure for safe public
    redistribution under MIT."""
    for example in EXAMPLE_NAMES:
        raw = json.loads(
            (EXAMPLES_DIR / example / "manifest.json").read_text()
        )
        ta = raw["provenance"]["target_authorisation"]
        assert ta == "self-owned", (
            f"{example} has target_authorisation={ta!r}; only self-owned "
            "is acceptable for the reference example set."
        )
