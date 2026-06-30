---
license: cc-by-4.0
language:
  - en
tags:
  - cybersecurity
  - blockchain
  - network-security
  - validator-security
  - anomaly-detection
  - adversarial-robustness
  - solana
  - sui
pretty_name: nr-bundles-public
size_categories:
  - n<1K
---

# nr-bundles-public

A curated, multi-modal dataset of blockchain validator infrastructure under attack and benign workloads. Thirty-one bundles across two chains (Sui, Solana), seven populated families (of eleven in the taxonomy), and ten attack primitives. Released as the first public sample of NullRabbit's bundle corpus, which underpins [NullRabbit Labs'](https://huggingface.co/NullRabbit) ML research on autonomous defence for decentralised networks.

## What this dataset is

Most security datasets on the Hub are either application-layer (smart contract vulnerabilities, exploit code snippets) or generic (enterprise network traffic, malware signatures). The infrastructure layer where blockchain validators actually run — the RPC surface, the gossip layer, the consensus daemon, the indexer — has no shared, ML-trainable representation. This dataset is the first public sample of one.

Each entry is a **bundle**: a multi-modal observation of validator infrastructure under a single workload. Bundles capture network packets, host telemetry, application metrics, and observed responses simultaneously, under a chain-agnostic schema. The format is open and specified at [`nr-bundle-spec`](https://github.com/NullRabbitLabs/nr-bundle-spec) (MIT-licensed). Anyone can produce v1 bundles for any chain.

This release publishes thirty-one bundles drawn from the NullRabbit corpus, with archive-provenance recorded per-bundle. The bundles selected demonstrate format coverage across the populated vulnerability families and provide attack/benign training material for cross-chain anomaly detection research.

## Bundle structure

Each bundle is a directory containing a manifest plus up to six modality files. Per-bundle modality presence is reflected in the manifest's `files` block; bundles do not contain modalities that were not captured during the workload, and the manifest is the ground-truth for which files are present.

| File | Modality | Present in this release |
|---|---|---|
| `manifest.json` | Schema-pinned metadata + provenance hashes | All bundles |
| `packets.pcap` | Raw network-layer packet capture | **Dropped from every bundle** (post-term cleartext concern; see Limitations) |
| `pcap_pre_termination.pcap` | Pre-termination TLS frames (encrypted; IP/TCP headers visible) | Bundles at `fidelity_class: lab-tls-fronted` only (17 bundles in this release) |
| `host.parquet` | Host telemetry (CPU, memory, IO, syscall counters) | All bundles |
| `app.parquet` | Application-level metrics from the validator daemon | Bundles where the validator exposed a metrics endpoint (most bundles; empty placeholders elsewhere) |
| `protocol.parquet` | Chain-agnostic consensus/protocol signal time-series | Bundles where consensus/protocol signals were captured (manifest `protocol_parquet=True`; empty placeholders for some passive-workload benigns) |
| `responses.parquet` | RPC/API response metadata (no bodies) | Bundles where the validator served RPC traffic during the capture window (manifest `responses_parquet=True`); **absent or zero-rows for passive-workload benigns** (`sui_BENIGN_passive_fullnode`, `solana_BENIGN_validator_passive`) |
| `vectors.parquet` | Computed feature vectors derived from the above | **Not populated in this release.** Reserved schema slot; consumers should derive feature vectors at inference time using the bundle-spec reference parser plus their own feature pipeline |

The manifest pins `primitive_id`, `family_id`, `traffic_source`, `fidelity_class`, `target_authorisation`, and provenance hashes for every file in the bundle. The schema is chain-agnostic — no field assumes a specific blockchain. The `BundleFiles` block (`packets_pcap`, `host_parquet`, `app_parquet`, `protocol_parquet`, `responses_parquet`, `vectors_parquet`) is the authoritative present/absent contract; readers should check the manifest before reading each modality file.

Bundles in this release carry one of two `fidelity_class` values: `lab` (controlled reproducer environment, no TLS termination) and `lab-tls-fronted` (controlled reproducer with an nginx TLS-termination front; pre-term TLS pcap is retained, post-term cleartext pcap is dropped). All bundles have `target_authorisation: self-owned` (every validator targeted was operated by NullRabbit).

Full schema: [`nr-bundle-spec` v0.1.0](https://github.com/NullRabbitLabs/nr-bundle-spec), which defines bundle v1 format.

## Family taxonomy

Bundles are classified by **family**, defined by attack mechanism rather than by chain. Because the format and the mechanism are shared across chains, cross-chain generalisation becomes **testable**: you can hold out an entire chain and measure whether a model trained on the others recovers a family. On this corpus it does **not** transfer yet — held-out-chain family macro-F1 is **0.17 (Sui held out) / 0.35 (Solana held out)**, against a 7-class random floor of ~0.14. Cross-chain transfer is the open question the shared format lets you pose and measure, not a result this dataset demonstrates; closing the gap needs more chains per family, not more features.

These are **validator / node-software** vulnerability classes only — on-chain contract / DeFi-economic findings are a separate, out-of-scope namespace and are never used here. The full taxonomy defines eleven families (ten attack classes plus `benign`). Seven are populated in this release:

| Family | Mechanism |
|---|---|
| `response_amp` | Asymmetric output:input byte ratio |
| `compute_amp` | Asymmetric work:request CPU ratio |
| `rate_limiter_bypass` | Behaviour conformant with rate limits but resource-exhausting |
| `reconnaissance` | Information gathering for follow-on attacks |
| `service_misconfig` | Exploitable default or operator configurations |
| `auth_bypass` | Authentication/authorisation circumvention |
| `benign` | Validator under normal workload (negative class) |

Four families in the full taxonomy (`consensus_abuse`, `connection_exhaustion`, `gossip_abuse`, `memory_amp`) are not populated in this release pending measurement work and disclosure-coordination on related findings.

## What's included

Thirty-one bundles total. Twenty-four attack bundles, seven benign. Twenty-two Solana, nine Sui. Seventeen bundles at `fidelity_class: lab-tls-fronted` (retain pre-term TLS pcap), fourteen at `fidelity_class: lab` (no TLS termination; raw pcap dropped).

The `Pcap modality` column below specifies which network-layer file is present on disk per bundle: `pre-term TLS` means `pcap_pre_termination.pcap` is retained (encrypted TLS frames; IP/TCP headers visible); `none` means the raw `packets.pcap` was dropped and no pre-term variant exists (`BundleFiles.packets_pcap=False` in the manifest).

**Solana (22 bundles)**

| Primitive | Family | Bundles | Fidelity | Pcap modality | Coverage |
|---|---|---|---|---|---|
| `SOL_F10_multi_get_accounts_amp` | response_amp | 4 | lab-tls-fronted | pre-term TLS | 4 postures |
| `SOL_F14_simulate_transaction_sync_wedge` | compute_amp | 4 | lab-tls-fronted | pre-term TLS | 4 postures |
| `SOL_P07_get_program_accounts_filter_miss` | compute_amp | 5 | lab | none | 5 postures |
| `SOL_RC_nmap_slow` | reconnaissance | 1 | lab | none | saturating posture |
| `SOL_MC_grafana_anon` | service_misconfig | 1 | lab | none | saturating posture |
| `SOL_MC_ssh_pwauth` | service_misconfig | 1 | lab | none | saturating posture |
| `SOL_H01_admin_rpc_probe` | auth_bypass | 1 | lab | none | saturating posture |
| `SOL_GR01_simulate_compute_flood` | rate_limiter_bypass | 1 | lab | none | saturating posture |
| `solana_BENIGN_organic_rpc` | benign | 2 | lab-tls-fronted | pre-term TLS | mixed postures |
| `solana_BENIGN_validator_passive` | benign | 2 | lab | none | mixed postures |

The SOL_F10 / SOL_F14 / SOL_P07 primitives correspond to the findings published as [NR-2026-001](https://nullrabbit.ai) (Agave RPC architectural findings, 2026-05-12).

The two Solana benign primitives have different fidelity classes because they observe different workloads through different capture paths. `solana_BENIGN_organic_rpc` is RPC-client traffic against the validator (JSON-RPC over TCP); the Step-11 capture sweep included a TLS-fronted variant where nginx terminates TLS in front of the validator, enabling the pre-term TLS pcap modality. `solana_BENIGN_validator_passive` is passive consensus-layer observation (validator running idle, no RPC clients); no TLS-fronting capture path was run for this workload, so the `lab` variant is the only one available.

**Sui (9 bundles)**

| Primitive | Family | Bundles | Fidelity | Pcap modality | Coverage |
|---|---|---|---|---|---|
| `sui_F10_multi_get_objects_amp` | response_amp | 3 | lab-tls-fronted | pre-term TLS | 3 postures |
| `sui_F14_devinspect_tokio_wedge` | compute_amp | 3 | lab-tls-fronted | pre-term TLS | 3 postures |
| `sui_BENIGN_passive_fullnode` | benign | 1 | lab | none | passive workload |
| `sui_BENIGN_reproducer_pipeline` | benign | 1 | lab-tls-fronted | pre-term TLS | reproducer baseline |
| `sui_BENIGN_validator_under_load` | benign | 1 | lab | none | active workload |

Posture variations capture distinct attack shapes against the same primitive (saturating throughput, low-volume, distributed-source, mimicry of organic traffic, historical-CVE patterns). Bundles within a primitive are intentionally non-identical so the dataset surfaces the variance the format is designed to represent.

## How the corpus is built

NullRabbit operates a reproducer pipeline that captures bundles under controlled conditions: validator daemons run on isolated infrastructure, workloads (attack or benign) are scripted and replayable, capture is synchronous across all five modalities, and every bundle's provenance is hashed end-to-end.

The full archived corpus (corpus_v1.0 through corpus_v1.10) contains thousands of bundles across additional primitives, families, and fidelity classes. This release is a curated thirty-one-bundle subset selected to demonstrate format coverage and provide training material for external researchers, with the rest of the corpus retained as the proprietary training surface for NullRabbit's production models.

The corpus is versioned and immutable. Each version archives only bundles new to that version. Failed iterations stay on disk as evidence; only versions passing close-out are promoted to archive.

## Methodology

NullRabbit's ML work against this corpus follows pre-registration discipline borrowed from the empirical-reproducibility literature. Every training cycle has a design document committed before the trainer runs. Audits run on close against sanity floors, per-feature audit trails, and falsification holdouts. Where an audit fires, training halts, the design is re-registered, and the prior version is retracted in writing.

The methodology, the iterative leak-surface peeling pattern, and the multi-cycle audit arc are documented in the substrate paper (in preparation) and in companion docs in the NullRabbit Labs research track. The corpus format and family taxonomy are open; the methodology is open; the specific corpus contents beyond this public sample are proprietary.

The governance framework for autonomous defensive systems built on this data is published separately as the earned-autonomy paper ([Zenodo DOI 10.5281/zenodo.18406828](https://doi.org/10.5281/zenodo.18406828)).

## Intended uses

This dataset is intended for:

- **Research on multi-modal anomaly detection** against validator infrastructure, particularly cross-chain generalisation claims.
- **Benchmarking** for adversarial-robustness work on network-layer ML detection.
- **Format adoption**: as the reference public sample of the bundle v1 format. Anyone building their own corpus against `nr-bundle-spec` can use these bundles as ground-truth examples.
- **Methodology study**: the bundles are the data layer; the pre-registration / falsifiability methodology applied to training against them is documented in the substrate paper.

## Limitations

- **Lab fidelity only.** All bundles in this release were captured in a controlled reproducer environment, not on mainnet or testnet. The capture pipeline has known fidelity envelopes; production-deployment generalisation is an open empirical question.
- **Two chains.** Sui and Solana only. Cross-chain claims in published work apply specifically to this two-chain corpus; broader generalisation (Cosmos, Ethereum, Aptos, others) is queued for subsequent corpus versions.
- **Curated subset.** Thirty-one bundles do not represent the full distribution of attack shapes in NullRabbit's archived corpus. The subset is selected for coverage, not for statistical sufficiency. Training a production-grade model on this subset alone is not recommended.
- **Raw `packets.pcap` is dropped from every bundle in this release.** Two policies apply per fidelity class:
  - `lab-tls-fronted` bundles (17): post-termination cleartext `packets.pcap` is dropped via `tools/strip_pcap.py` (from `nr-bundle-spec`); the pre-termination TLS pcap (`pcap_pre_termination.pcap`) is retained. TLS frames are encrypted; only IP/TCP headers are visible at the pre-term wire vantage.
  - `lab` bundles (14): no pre-term variant exists; the raw `packets.pcap` is dropped and `BundleFiles.packets_pcap=False` is set in the manifest. The remaining Parquet modalities (host plus whichever of app, protocol, responses were captured for the workload) stay intact.
  Future dataset versions may include a header-only stripped variant of `packets.pcap` for `lab` bundles once payload-stripping tooling has been verified.
- **Modality presence varies by workload.** Passive-workload benigns (`sui_BENIGN_passive_fullnode`, `solana_BENIGN_validator_passive`) do not serve RPC traffic during capture; their `responses.parquet` is absent or zero-rows and `BundleFiles.responses_parquet=False` in the manifest. Consumers must check the manifest's `files` block before reading each modality. `vectors.parquet` is reserved-but-unpopulated in this release; consumers derive feature vectors at inference time.
- **Disclosure status varies by primitive.** SOL_F10/F14/P07 are publicly disclosed per NR-2026-001. Other primitives represent methodology-class findings or are referenced in coordinated-disclosure channels with respective ecosystems.

## How to use this dataset

Each bundle is a directory of Parquet files plus a manifest, with schemas that vary by modality. The dataset is **tree-shaped**, not tabular, so the canonical way to consume it is `snapshot_download` followed by the bundle-spec reference parsers:

```python
from huggingface_hub import snapshot_download
from bundle_spec import BundleManifest  # nr-bundle-spec / python
import json
from pathlib import Path

# Pull the full dataset (or use allow_patterns=["crp_<id>/*"] for one bundle).
local = snapshot_download(repo_id="NullRabbit/nr-bundles-public",
                          repo_type="dataset")

# Iterate bundles
for bundle_dir in sorted(Path(local).glob("crp_*")):
    manifest = BundleManifest.model_validate_json(
        (bundle_dir / "manifest.json").read_text()
    )
    print(manifest.primitive_id, manifest.family_id, manifest.fidelity_class)
    # Each modality is a Parquet file — read with pyarrow / pandas / polars
    # as the modality demands. See nr-bundle-spec for per-modality schemas.
    # Check manifest.files.<modality_parquet> before reading; bundles do
    # not contain modalities that were not captured during the workload.
```

`datasets.load_dataset("NullRabbit/nr-bundles-public")` does **not** work on this dataset — HF's auto-loader assumes a single tabular schema, which doesn't match the multi-modal bundle layout. Use `snapshot_download` + the bundle-spec parsers as shown above.

For schema, validation, and reference parsers (Python + Rust), see [`nr-bundle-spec`](https://github.com/NullRabbitLabs/nr-bundle-spec). A validator CLI is available at `tools/validate_bundle.py`.

## Licensing

- **Dataset**: CC-BY-4.0. Attribution required; commercial use permitted.
- **Format spec**: MIT (separate, at `nr-bundle-spec`).

The split is intentional. The format is freely reusable code/schema; the data carries attribution requirements so downstream work that uses NullRabbit's specific bundles can be traced.

## Citation

```bibtex
@dataset{nullrabbit_nrbundlespublic_2026,
  author       = {NullRabbit},
  title        = {nr-bundles-public: a curated multi-modal bundle dataset for adversarial blockchain validator research},
  year         = {2026},
  month        = may,
  version      = {1},
  publisher    = {Hugging Face},
  url          = {https://huggingface.co/datasets/NullRabbit/nr-bundles-public},
  note         = {Format specified by nr-bundle-spec v0.1.0 (https://github.com/NullRabbitLabs/nr-bundle-spec).},
}
```

Related:

- **Bundle format specification**: [`nr-bundle-spec`](https://github.com/NullRabbitLabs/nr-bundle-spec)
- **Earned autonomy paper** (governance layer): [Zenodo DOI 10.5281/zenodo.18406828](https://doi.org/10.5281/zenodo.18406828)
- **Substrate paper** (data-layer methodology): in preparation
- **NullRabbit Labs**: [huggingface.co/NullRabbit](https://huggingface.co/NullRabbit)
- **Website**: [nullrabbit.ai](https://nullrabbit.ai)

## Contact

Research enquiries: security@nullrabbit.ai

Format extensions, schema feedback, or bundles produced by external researchers against the open spec — open an issue at `nr-bundle-spec`.
