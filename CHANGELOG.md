# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-05-06

### Added

Initial release of Bundle v1.

- **Python reference parser** (`bundle_spec` package on PyPI): full
  Pydantic-validated `BundleManifest`, `Provenance`, `BundleFiles`,
  `PrimitiveDescriptor`, `ParameterSpec`, six enum types
  (`Posture`, `GroundTruthLabel`, `TrafficSource`, `FidelityClass`,
  `TargetAuthorisation`, `FamilyId`), five parquet schema helper
  functions, and the deterministic `compute_genome_id` helper.
- **Rust reference parser** (`bundle-spec` crate on crates.io):
  byte-equivalent with the Python parser. Same wire enum strings,
  same JSON Schema, same parquet schemas (as
  `arrow_schema::Schema` constants), same `compute_genome_id`
  output (verified by shared test vectors). JSON Schema embedded
  via `include_str!()`.
- **JSON Schema artefacts** in `schema/` — generated from the
  Pydantic models via `tools/regen_schema.py`. Stable formatter
  (sorted keys, 2-space indent, trailing newline). CI verifies
  no drift between committed schema and Pydantic source.
- **Five reference example bundles** in `examples/` —
  `sui_F10_multi_get_objects_amp` (attack),
  `sui_F14_devinspect_tokio_wedge` (attack),
  `sui_BENIGN_reproducer_pipeline` (benign),
  `SOL_F10_multi_get_accounts_amp` (attack),
  `solana_BENIGN_organic_rpc` (benign). All `lab-tls-fronted`
  fidelity, `self-owned` authorisation, with post-term cleartext
  pcap stripped per the public-release audit.
- **`tools/regen_schema.py`** — regenerates JSON Schema from the
  canonical Pydantic models.
- **`tools/strip_pcap.py`** — drops post-term cleartext pcap from
  a bundle and re-emits the manifest with `packets_pcap=False`,
  for safe public release of lab-tls-fronted bundles.

### Stability commitment

- **0.1.x**: bug-fix-only patches on the current schema.
- **0.2.0**: reserved for the upcoming `provenance.substrate` ×
  `provenance.traffic_origin` decomposition (additive — existing
  `provenance.fidelity_class` becomes derived). Tracked as the
  *next test of additive extensibility* in upstream methodology
  documentation.
- **1.0.0**: deferred to first set of external citations — not
  calendar-bound.

### Cross-language guarantees pinned by tests

- Wire enum strings (snake_case for `FamilyId`, kebab-case for
  `TrafficSource`/`FidelityClass`/`TargetAuthorisation`, mixed for
  `Posture`).
- `compute_genome_id` byte-identical with Python (six shared test
  vectors).
- Parquet schemas: same field names, types, nullability across
  languages.

### Test posture

- Python: 71 tests across `test_contracts.py` (63), `test_schema.py`
  (8), plus 32 in `test_examples.py`.
- Rust: 48 tests across 8 unit-test modules + integration tests +
  doctests.
- Example-bundle round-trip pinned: every parquet column type +
  nullability matches the v0.1.0 schema across all five examples.
