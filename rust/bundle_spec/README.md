# bundle-spec — Rust reference parser

Reference Rust parser for [Bundle v1](https://github.com/NullRabbitLabs/nr-bundle-spec) —
the canonical multi-modal capture format for adversarial blockchain
validator research.

## Quick start

```toml
[dependencies]
bundle-spec = "0.1"
```

```rust
use bundle_spec::{BundleManifest, validate_manifest_json};

let json = std::fs::read_to_string("crp_abc123/manifest.json")?;
let v: serde_json::Value = serde_json::from_str(&json)?;

// Structural validation against the embedded JSON Schema:
validate_manifest_json(&v)?;

// Strongly-typed parse + cross-field invariants:
let manifest: BundleManifest = serde_json::from_value(v)?;
manifest.validate()?;

println!("{} {:?}", manifest.primitive_id, manifest.family_id);
```

## What's in the crate

- `bundle_spec::manifest` — `BundleManifest`, `Provenance`,
  `BundleFiles`, plus the `Posture` / `GroundTruthLabel` /
  `TrafficSource` / `FidelityClass` / `TargetAuthorisation` enums.
- `bundle_spec::primitive` — `PrimitiveDescriptor`, `ParameterSpec`.
- `bundle_spec::taxonomy` — `FamilyId` enum + `family_definitions()`.
- `bundle_spec::parquet` — `Schema` constants for the four time-
  series modalities + the optional `vectors` slot.
- `bundle_spec::genome_id` — `compute_genome_id` helper, byte-
  identical with the Python reference parser (pinned by tests).
- `bundle_spec::validation` — `validate_manifest_json` /
  `validate_primitive_json` for structural JSON Schema validation
  against the embedded schema artefacts.

## Cross-language guarantees

This crate is byte-equivalent with the Python `bundle_spec` package
on the load-bearing surfaces:

- Wire enum strings are identical (`response_amp`, `lab-tls-fronted`,
  `customer-authorised`, etc.).
- `compute_genome_id` produces the same 16-hex-char output for the
  same input (verified via shared test vectors in both languages).
- Parquet schemas (`host_ts_schema`, `app_ts_schema`,
  `protocol_ts_schema`, `responses_schema`, `vectors_schema`)
  produce equivalent Arrow schemas (verified by
  `tools/compare_arrow_schemas.py` in the spec repo).

## License

MIT — see the repo's top-level `LICENSE`.
