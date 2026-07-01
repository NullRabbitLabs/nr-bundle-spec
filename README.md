# Bundle v1

**A multi-modal capture format for adversarial research on
blockchain validator infrastructure.**

A *bundle* is one directory on disk containing the complete trace of
one attack (or benign) run against a validator: a manifest, a packet
capture, and four time-series Parquet modalities (host, app, protocol,
responses) all keyed off a monotonic `t_ns` referenced to the
manifest's `started_at`.

This repository contains the **canonical normative specification**
(JSON Schema generated from Pydantic) plus reference parsers in
**Python** and **Rust**.

```
<corpus_id>/
├── manifest.json       — BundleManifest (Pydantic-validated)
├── packets.pcap        — packet capture, snaplen-256 by default
├── host.parquet        — host telemetry time-series
├── app.parquet         — application metric scrape time-series
├── protocol.parquet    — consensus / protocol signal time-series
└── responses.parquet   — per-request response semantics
```

License: **MIT**. The format is intended to be adopted on third-party
data without coordination. A researcher can produce bundles against
their own infrastructure, train against them, and publish results
citing the format. Adoption is the point.

## Adopting the standard

- [Adoption guide](docs/adoption-guide.md): how to classify a validator-integrity
  finding into the eleven-family vocabulary.
- [Methodology](docs/methodology.md): how the Validator Integrity Index is built,
  and what it does and does not yet claim.

## Why a format?

Adversarial research on blockchain infrastructure has historically
been one-off — each project builds its own capture pipeline, its own
labelling conventions, its own evaluation methodology. That makes
results incomparable.

Bundle v1 specifies the **unit of measurement**: the on-disk shape
of a single run, the modalities captured, the provenance fields,
and the cross-language schema contract. With this in place:

- Detector models trained on one corpus can be evaluated on another.
- Cross-chain holdout becomes a primary evaluation methodology
  (train Sui, hold out Solana under the same family).
- Provenance fidelity (`fidelity_class`, `target_authorisation`)
  travels with the data, so dataset curators can stratify cleanly
  on it.

## Reference public bundles

A curated sample of 31 bundles conformant with this spec is published
on Hugging Face:

**[nr-bundles-public](https://huggingface.co/datasets/NullRabbit/nr-bundles-public)**

Multi-modal observations of blockchain validator infrastructure under
attack and benign workloads, covering 7 vulnerability families across
Sui and Solana. CC-BY-4.0.

Use these bundles to:

- Test parsers and tooling built against this spec
- Benchmark anomaly detection models on validator-infrastructure
  network data
- Reference the format in academic citations

## What's in a bundle

### manifest.json (BundleManifest)

Identity, taxonomy, time window, attack parameters, provenance.

```json
{
  "bundle_version": 1,
  "shape": "v1.0",
  "corpus_id": "crp_abc123…",
  "attack_id": "atk_xyz789…",
  "genome_id": "aabbccdd11223344",
  "family_id": "response_amp",
  "primitive_id": "sui_F10_multi_get_objects_amp",
  "posture": "saturating",
  "ground_truth_label": "attack",
  "chain": "sui",
  "run_tag": "saturating_baseline_2026-04-25",
  "target_env": "localnet-sui-multinode4",
  "started_at": "2026-04-25T10:14:30Z",
  "ended_at":   "2026-04-25T10:15:30Z",
  "attack_parameters": { … },
  "provenance": {
    "traffic_source": "reproducer-attack",
    "fidelity_class": "lab",
    "target_authorisation": "self-owned",
    "tooling": { … }
  },
  "files": {
    "packets_pcap": true,
    "host_parquet": true,
    "app_parquet": true,
    "protocol_parquet": true,
    "responses_parquet": true,
    "vectors_parquet": false
  }
}
```

The `family_id` is a **chain-agnostic** vulnerability-class label
(11 values: 10 attack families + benign) — **validator / node-software
classes only**; on-chain contract / DeFi-economic findings are a
separate out-of-scope namespace (cross-mapped in the VII
`ledger/family_map.csv`). The `primitive_id` is the
**chain-specific** implementation. This two-level taxonomy is the
load-bearing decomposition for cross-chain holdout.

### packets.pcap

Raw packet capture. Default snaplen 256 bytes (TCP/IP headers only —
no payload bytes leak). Producers can use larger snaplens when they
control the privacy posture.

### Time-series Parquet modalities

All four files share a monotonic `t_ns` column (nanoseconds since
`started_at`). Joining is merge-asof.

- **host.parquet**: per-process telemetry (~100 ms resolution; psutil-
  shaped: cpu, rss, io_bytes, fds, ctx_switches, …).
- **app.parquet**: long-format Prometheus scrape samples
  (`metric_name` + `labels_json` + `value`).
- **protocol.parquet**: chain-agnostic consensus / protocol signals
  (checkpoint_height, peer_count, queue_depth, …).
- **responses.parquet**: per-request semantics (`request_size_bytes`,
  `response_size_bytes`, `status_code`, `duration_ns`, …).

Schemas are stable; new columns require a `BUNDLE_VERSION` bump.

## Quick start — Python

```bash
pip install bundle-spec
```

```python
from bundle_spec import BundleManifest

with open("crp_abc123/manifest.json") as f:
    manifest = BundleManifest.model_validate_json(f.read())

print(manifest.family_id, manifest.primitive_id, manifest.ground_truth_label)
# response_amp sui_F10_multi_get_objects_amp attack
```

For the Parquet modalities:

```python
import pyarrow.parquet as pq
from bundle_spec import responses_schema

table = pq.read_table("crp_abc123/responses.parquet")
assert table.schema.equals(responses_schema())  # or a superset, additive
```

## Quick start — Rust

```toml
[dependencies]
bundle-spec = "0.1"
```

```rust
use bundle_spec::manifest::BundleManifest;

let json = std::fs::read_to_string("crp_abc123/manifest.json")?;
let m: BundleManifest = serde_json::from_str(&json)?;
m.validate()?;
println!("{} {} {:?}", m.family_id, m.primitive_id, m.ground_truth_label);
```

## Manifest field reference

See `python/bundle_spec/bundle_v1.py` (Pydantic models with
docstrings) and `schema/bundle_v1.schema.json` (generated). Both are
the same content in different forms — the Pydantic model is
canonical.

Required structured-enum fields:

- `family_id`: see `bundle_spec.taxonomy.FamilyId` (11 values).
- `posture`: see `Posture` (16 values).
- `ground_truth_label`: `attack` / `benign` / `suspicious`.
- `provenance.traffic_source`: see `TrafficSource` (6 values).
- `provenance.fidelity_class`: see `FidelityClass` (6 values).
- `provenance.target_authorisation`: see `TargetAuthorisation`
  (4 values).

## Schema regeneration

The JSON Schema artefacts in `schema/` are generated from the
Pydantic models and committed. CI fails if regeneration produces a
diff against the committed artefact (so producers and consumers
can't drift).

```bash
python tools/regen_schema.py
git diff schema/  # should be empty
```

## Cross-language schema consistency

The Python pyarrow schemas in `bundle_v1.py` and the Rust
`arrow_schema::Schema` constants in `rust/bundle_spec/src/parquet.rs`
must be byte-for-byte equivalent. CI runs
`tools/compare_arrow_schemas.py` to check.

The `genome_id` canonicalisation (sorted-key JSON, SHA-256, first 16
hex chars) is also pinned by a cross-language determinism test — a
fixed input must produce the same hex string in both languages.

## Examples

`examples/` contains 5 reference bundles drawn from a
controlled-lab capture pipeline. Each bundle:

- Has a complete `manifest.json` validated against the schema.
- Has a `pcap_pre_termination.pcap` (TLS-fronted capture; no
  cleartext payload visible).
- Has `host.parquet`, `protocol.parquet`, `responses.parquet`
  populated. (`app.parquet` may be empty if Prometheus didn't scrape
  during the capture window.)
- Was produced under `target_authorisation=self-owned` against
  operator-owned localnet validators.

The 5 examples span:
- 1 attack on Sui (`sui_F10_multi_get_objects_amp`)
- 1 attack on Solana (`SOL_F10_multi_get_accounts_amp`)
- 1 mechanism contrast (`sui_F14_devinspect_tokio_wedge`)
- 1 benign Sui (`sui_BENIGN_reproducer_pipeline`)
- 1 benign Solana (`solana_BENIGN_organic_rpc`)

## Stability and versioning

Format-additive extensibility is the design property: adding new
optional fields, new enum members, new Parquet columns is a minor
bump (no `BUNDLE_VERSION` change); breaking changes (renaming,
re-typing, removing) require a major bump and a new module path
(`bundle_v2`).

SemVer for `bundle-spec` (this package):

- **0.1.x** — bug-fix-only patches on the current schema.
- **0.2.0** — reserved for the upcoming `provenance.substrate` ×
  `provenance.traffic_origin` decomposition (additive: existing
  `provenance.fidelity_class` will be derived from the new pair via
  a model validator; existing readers stay compatible).
- **1.0.0** — deferred to first set of external citations.

## Reproducibility

The format is the publication artefact. The reference parsers in
this repo accept any bundle conforming to the schema, regardless of
who produced it. There's no central registry, no API key, no
network dependency.

## Citation

```bibtex
@software{bundle_spec_v0_1_0,
  title  = {Bundle v1: A Multi-Modal Capture Format for Adversarial
           Research on Blockchain Validator Infrastructure},
  author = {{NullRabbit}},
  year   = 2026,
  url    = {https://github.com/NullRabbitLabs/nr-bundle-spec},
  version = {0.1.0},
  note   = {MIT-licensed}
}
```

## License

MIT — see `LICENSE`. Code, schemas, and example metadata are MIT-
licensed and free to use without restriction. The example bundle
**data** (Parquet files, packet captures) is also MIT-licensed.
