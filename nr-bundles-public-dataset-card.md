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

A curated, multi-modal dataset of blockchain validator infrastructure under
attack and benign workloads. Thirty-one bundles across two chains (Sui,
Solana), seven vulnerability families, and ten attack primitives. Released
as the first public sample of NullRabbit's bundle corpus, which underpins
[NullRabbit Labs'](https://huggingface.co/NullRabbit) ML research on
autonomous defence for decentralised networks.

## What this dataset is

Most security datasets on the Hub are either application-layer
(smart contract vulnerabilities, exploit code snippets) or generic
(enterprise network traffic, malware signatures). The infrastructure layer
where blockchain validators actually run — the RPC surface, the gossip
layer, the consensus daemon, the indexer — has no shared, ML-trainable
representation. This dataset is the first public sample of one.

Each entry is a **bundle**: a multi-modal observation of validator
infrastructure under a single workload. Bundles capture network packets,
host telemetry, application metrics, and observed responses simultaneously,
under a chain-agnostic schema. The format is open and specified at
[`nr-bundle-spec`](https://github.com/NullRabbitLabs/nr-bundle-spec)
(MIT-licensed). Anyone can produce v1 bundles for any chain.

This release publishes thirty-one bundles drawn from the NullRabbit
corpus, with archive-provenance recorded per-bundle. The bundles
selected demonstrate format coverage across the populated vulnerability
families and provide attack/benign training material for cross-chain
anomaly detection research.

## Bundle structure

Each bundle is a directory containing a manifest plus one raw packet
capture and up to five Parquet files:

| File | Modality | Present in this release |
|---|---|---|
| `manifest.json` | Schema-pinned metadata + provenance hashes | All bundles |
| `packets.pcap` | Raw network-layer packet capture | **Dropped from every bundle** (post-term cleartext concern; see Limitations) |
| `pcap_pre_termination.pcap` | Pre-termination TLS frames (encrypted; IP/TCP headers visible) | Bundles at `fidelity_class: lab-tls-fronted` only (17 bundles in this release) |
| `host.parquet` | Host telemetry (CPU, memory, IO, syscall counters) | All bundles |
| `app.parquet` | Application-level metrics from the validator daemon | Bundles where the validator exposed a metrics endpoint |
| `protocol.parquet` | Chain-agnostic consensus/protocol signal time-series | All bundles |
| `responses.parquet` | RPC/API response metadata (no bodies) | All bundles |
| `vectors.parquet` | Computed feature vectors derived from the above | All bundles |

The manifest pins `primitive_id`, `family_id`, `traffic_source`,
`fidelity_class`, `target_authorisation`, and provenance hashes for every
file in the bundle. The schema is chain-agnostic — no field assumes a
specific blockchain. Per-bundle modality presence is reflected in the
manifest's `files` block (e.g. `packets_pcap: false` when the raw pcap
was dropped for safe public release).

Bundles in this release carry one of two `fidelity_class` values: `lab`
(controlled reproducer environment, no TLS termination) and
`lab-tls-fronted` (controlled reproducer with an nginx TLS-termination
front; pre-term TLS pcap is retained, post-term cleartext pcap is
dropped). All bundles have `target_authorisation: self-owned` (every
validator targeted was operated by NullRabbit).

Full schema: [`nr-bundle-spec` v0.1.0](https://github.com/NullRabbitLabs/nr-bundle-spec),
which defines bundle v1 format.

## Family taxonomy

Bundles are classified by **family**, defined by attack mechanism rather
than by chain. This is what makes cross-chain training claims tractable:
a model trained on Sui bundles for family X can generalise to Solana
bundles in family X because the format and the mechanism are the same.

The full taxonomy defines ten families. Seven are populated in this
release:

| Family | Mechanism |
|---|---|
| `response_amp` | Asymmetric output:input byte ratio |
| `compute_amp` | Asymmetric work:request CPU/memory ratio |
| `rate_limiter_bypass` | Behaviour conformant with rate limits but resource-exhausting |
| `reconnaissance` | Information gathering for follow-on attacks |
| `service_misconfig` | Exploitable default or operator configurations |
| `auth_bypass` | Authentication/authorisation circumvention |
| `benign` | Validator under normal workload (negative class) |

Three families in the full taxonomy (`consensus_abuse`,
`connection_exhaustion`, `protocol_abuse`) are not populated in this
release pending measurement work and disclosure-coordination on related
findings.

## What's included

Thirty-one bundles total. Twenty-four attack bundles, seven benign.
Twenty-two Solana, nine Sui. Seventeen bundles at `fidelity_class:
lab-tls-fronted` (retain pre-term TLS pcap), fourteen at
`fidelity_class: lab` (no TLS termination; raw pcap dropped).

**Solana (22 bundles)**

| Primitive | Family | Bundles | Fidelity | Coverage |
|---|---|---|---|---|
| `SOL_F10_multi_get_accounts_amp` | response_amp | 4 | lab-tls-fronted | 4 postures |
| `SOL_F14_simulate_transaction_sync_wedge` | compute_amp | 4 | lab-tls-fronted | 4 postures |
| `SOL_P07_get_program_accounts_filter_miss` | rate_limiter_bypass | 5 | lab | 5 postures |
| `SOL_RC_nmap_slow` | reconnaissance | 1 | lab | saturating posture |
| `SOL_MC_grafana_anon` | service_misconfig | 1 | lab | saturating posture |
| `SOL_MC_ssh_pwauth` | service_misconfig | 1 | lab | saturating posture |
| `SOL_H01_admin_rpc_probe` | auth_bypass | 1 | lab | saturating posture |
| `SOL_GR01_simulate_compute_flood` | rate_limiter_bypass | 1 | lab | saturating posture |
| `solana_BENIGN_organic_rpc` | benign | 2 | lab-tls-fronted | mixed postures |
| `solana_BENIGN_validator_passive` | benign | 2 | lab | mixed postures |

The SOL_F10 / SOL_F14 / SOL_P07 primitives correspond to the findings
published as [NR-2026-001](https://nullrabbit.ai) (Agave RPC architectural
findings, 2026-05-12).

**Sui (9 bundles)**

| Primitive | Family | Bundles | Fidelity | Coverage |
|---|---|---|---|---|
| `sui_F10_multi_get_objects_amp` | response_amp | 3 | lab-tls-fronted | 3 postures |
| `sui_F14_devinspect_tokio_wedge` | compute_amp | 3 | lab-tls-fronted | 3 postures |
| `sui_BENIGN_passive_fullnode` | benign | 1 | lab | passive workload |
| `sui_BENIGN_reproducer_pipeline` | benign | 1 | lab-tls-fronted | reproducer baseline |
| `sui_BENIGN_validator_under_load` | benign | 1 | lab | active workload |

Posture variations capture distinct attack shapes against the same primitive
(saturating throughput, low-volume, distributed-source, mimicry of organic
traffic, historical-CVE patterns). Bundles within a primitive are
intentionally non-identical so the dataset surfaces the variance the format
is designed to represent.

## How the corpus is built

NullRabbit operates a reproducer pipeline that captures bundles under
controlled conditions: validator daemons run on isolated infrastructure,
workloads (attack or benign) are scripted and replayable, capture is
synchronous across all five modalities, and every bundle's provenance is
hashed end-to-end.

The full archived corpus (corpus_v1.0 through corpus_v1.10) contains
thousands of bundles across additional primitives, families, and fidelity
classes. This release is a curated thirty-bundle subset selected to
demonstrate format coverage and provide training material for external
researchers, with the rest of the corpus retained as the proprietary
training surface for NullRabbit's production models.

The corpus is versioned and immutable. Each version archives only bundles
new to that version. Failed iterations stay on disk as evidence; only
versions passing close-out are promoted to archive.

## Methodology

NullRabbit's ML work against this corpus follows pre-registration
discipline borrowed from the empirical-reproducibility literature. Every
training cycle has a design document committed before the trainer runs.
Audits run on close against sanity floors, per-feature audit trails, and
falsification holdouts. Where an audit fires, training halts, the design
is re-registered, and the prior version is retracted in writing.

The methodology, the iterative leak-surface peeling pattern, and the
multi-cycle audit arc are documented in the substrate paper
(in preparation) and in companion docs in the NullRabbit Labs research
track. The corpus format and family taxonomy are open; the methodology is
open; the specific corpus contents beyond this public sample are
proprietary.

The governance framework for autonomous defensive systems built on this
data is published separately as the earned-autonomy paper
([Zenodo DOI 10.5281/zenodo.18406828](https://doi.org/10.5281/zenodo.18406828)).

## Intended uses

This dataset is intended for:

- **Research on multi-modal anomaly detection** against validator
  infrastructure, particularly cross-chain generalisation claims.
- **Benchmarking** for adversarial-robustness work on network-layer
  ML detection.
- **Format adoption**: as the reference public sample of the bundle v1
  format. Anyone building their own corpus against `nr-bundle-spec` can
  use these bundles as ground-truth examples.
- **Methodology study**: the bundles are the data layer; the
  pre-registration / falsifiability methodology applied to training
  against them is documented in the substrate paper.

## Limitations

- **Lab fidelity only.** All bundles in this release were captured in a
  controlled reproducer environment, not on mainnet or testnet. The
  capture pipeline has known fidelity envelopes; production-deployment
  generalisation is an open empirical question.
- **Two chains.** Sui and Solana only. Cross-chain claims in published
  work apply specifically to this two-chain corpus; broader
  generalisation (Cosmos, Ethereum, Aptos, others) is queued for
  subsequent corpus versions.
- **Curated subset.** Thirty-one bundles do not represent the full
  distribution of attack shapes in NullRabbit's archived corpus. The
  subset is selected for coverage, not for statistical sufficiency.
  Training a production-grade model on this subset alone is not
  recommended.
- **Raw `packets.pcap` is dropped from every bundle in this release.**
  Two policies apply per fidelity class:
  - `lab-tls-fronted` bundles (17): post-termination cleartext `packets.pcap`
    is dropped via `tools/strip_pcap.py` (from `nr-bundle-spec`); the
    pre-termination TLS pcap (`pcap_pre_termination.pcap`) is retained.
    TLS frames are encrypted; only IP/TCP headers are visible at the
    pre-term wire vantage.
  - `lab` bundles (14): no pre-term variant exists; the raw `packets.pcap`
    is dropped and `BundleFiles.packets_pcap=False` is set in the
    manifest. The five Parquet modalities (host, app, protocol,
    responses, vectors) remain intact.
  Future dataset versions may include a header-only stripped variant of
  `packets.pcap` for `lab` bundles once payload-stripping tooling has
  been verified.
- **Disclosure status varies by primitive.** SOL_F10/F14/P07 are
  publicly disclosed per NR-2026-001. Other primitives represent
  methodology-class findings or are referenced in coordinated-disclosure
  channels with respective ecosystems.

## How to use this dataset

```python
from datasets import load_dataset

dataset = load_dataset("NullRabbit/nr-bundles-public")
```

Each bundle is stored as a directory of Parquet files plus a manifest.
The bundle v1 reference parsers (Python and Rust) live in
`nr-bundle-spec` and can be used to load and validate bundles
programmatically.

For schema, validation, and reference parsers, see
[`nr-bundle-spec`](https://github.com/NullRabbitLabs/nr-bundle-spec).

## Licensing

- **Dataset**: CC-BY-4.0. Attribution required; commercial use permitted.
- **Format spec**: MIT (separate, at `nr-bundle-spec`).

The split is intentional. The format is freely reusable code/schema; the
data carries attribution requirements so downstream work that uses
NullRabbit's specific bundles can be traced.

## Citation

```bibtex
@dataset{nullrabbit_nrbundlespublic_2026,
  author       = {NullRabbit},
  title        = {nr-bundles-public: a curated multi-modal bundle dataset for adversarial blockchain validator research},
  year         = {2026},
  publisher    = {Hugging Face},
  url          = {https://huggingface.co/datasets/NullRabbit/nr-bundles-public},
  note         = {Format specified by nr-bundle-spec v0.1.0 (https://github.com/NullRabbitLabs/nr-bundle-spec).}
}
```

Related:

- **Bundle format specification**: [`nr-bundle-spec`](https://github.com/NullRabbitLabs/nr-bundle-spec)
- **Earned autonomy paper** (governance layer): [Zenodo DOI 10.5281/zenodo.18406828](https://doi.org/10.5281/zenodo.18406828)
- **Substrate paper** (data-layer methodology): in preparation
- **NullRabbit Labs**: [huggingface.co/NullRabbit](https://huggingface.co/NullRabbit)
- **Website**: [nullrabbit.ai](https://nullrabbit.ai)

## Contact

Research enquiries: simon@nullrabbit.ai

Format extensions, schema feedback, or bundles produced by external
researchers against the open spec — open an issue at `nr-bundle-spec`.
