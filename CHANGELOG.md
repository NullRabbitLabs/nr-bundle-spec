# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] — 2026-06-30

### Clarified

- **`family_id` scope boundary** (`python/bundle_spec/taxonomy.py` docstring + `README.md`): documented that `family_id` is the **validator / node-software** vulnerability-class vocabulary, and that on-chain contract / DeFi-economic findings (AMM value-extraction, oracle/TWAP manipulation, liquidation, governance capture, bridge-contract message abuse, ERC-4626/reentrancy logic) are **out of scope** — a separate DeFi-economic namespace, never `family_id` values, cross-mapped in the VII `ledger/family_map.csv`. Records the canonical-vocabulary ratification (the 11-value `FamilyId` enum, unchanged). **No enum/wire change** — `BUNDLE_VERSION` unchanged; doc-only patch.

## [0.1.1] — 2026-05-13

### Clarified

- **`BundleFiles` flag-semantics** (`python/bundle_spec/bundle_v1.py`): tightened the docstring to spell out the forward-only contract. `True` ⇒ file MUST be present and schema-conformant; `False` ⇒ no on-disk constraint (the file may exist as an empty placeholder per the reference-example convention, but consumers should not read it). The change aligns the docstring with the actual semantics already implemented by `tools/validate_bundle.py` and observed in the v0.1.0 reference example bundles, where some `False`-flagged modalities ship empty placeholder files. No on-the-wire schema change; this is a contract clarification only.

### Added

- **`tools/validate_bundle.py`**: release-cert validator CLI that walks bundle directories + asserts each manifest validates against `BundleManifest` + asserts flag-honest file presence per the forward-only `BundleFiles` semantic. Per-bundle release-cert JSON output when `--cert-out` supplied. Smoke-tested against the 5 reference example bundles (5/5 pass).

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
