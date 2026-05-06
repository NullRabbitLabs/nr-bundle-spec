# Reference example bundles

5 example bundles drawn from a controlled-lab capture pipeline.
Each bundle illustrates a specific point in the corpus's
attack/benign × cross-chain × mechanism design space.

| Directory | primitive_id | family | chain | ground_truth | size |
|---|---|---|---|---|---:|
| `example_sui_F10_attack` | `sui_F10_multi_get_objects_amp` | response_amp | sui | attack | 2.6M |
| `example_sui_F14_attack` | `sui_F14_devinspect_tokio_wedge` | compute_amp | sui | attack | 3.0M |
| `example_sui_benign` | `sui_BENIGN_reproducer_pipeline` | benign | sui | benign | 76K |
| `example_SOL_F10_attack` | `SOL_F10_multi_get_accounts_amp` | response_amp | solana | attack | 4.1M |
| `example_solana_benign` | `solana_BENIGN_organic_rpc` | benign | solana | benign | 56K |

## What's in each bundle

```
example_<name>/
├── manifest.json                 — BundleManifest (schema-validated)
├── pcap_pre_termination.pcap     — pre-term TLS pcap (no cleartext leak)
├── host.parquet                  — host telemetry
├── app.parquet                   — Prometheus scrape (often empty for these
│                                    bundles; the scrape didn't run during
│                                    the capture window)
├── protocol.parquet              — chain-protocol signals
└── responses.parquet             — per-request semantics
```

`packets.pcap` (the post-term cleartext loopback) has been **stripped**
from each example — it would contain HTTP/JSON-RPC bodies, which we
deliberately don't publish in this reference set. The manifest
records this via `files.packets_pcap=False`.

The pre-term TLS pcap is preserved. Per a full content audit
(`HF-DATASET-AUDIT-2026-05-05.md`), pre-term pcaps from these bundles
contain only:
- TLS handshake records (encrypted payload after EncryptedExtensions)
- Loopback IP addresses (127.0.0.1, 127.0.0.2)
- ALPN values (h2 / http/1.1 only — no surprising entries)

No SNI (clients use IP-only target URLs), no plaintext JSON-RPC
tokens, no customer/engagement metadata, no filesystem paths.

## Provenance

All five bundles share the same provenance posture:

- `target_authorisation`: `self-owned` — captured against operator-
  owned localnet validators.
- `target_env`: `localnet-sui-multinode4` (Sui side) or
  `localnet-solana-test-validator-v2.2.16` (Solana side).
- `fidelity_class`: `lab-tls-fronted` — full reproducer producing
  genuine traffic against a TLS-terminating nginx in front of a
  localnet validator, captured at the pre-term wire vantage.

## Loading an example (Python)

```python
import json
from pathlib import Path
from bundle_spec import BundleManifest

example = Path("examples/example_sui_F10_attack")
manifest = BundleManifest.model_validate(json.loads((example / "manifest.json").read_text()))
print(manifest.primitive_id, manifest.posture, manifest.ground_truth_label)
```

## Loading an example (Rust)

```rust
use bundle_spec::BundleManifest;
let json = std::fs::read_to_string("examples/example_sui_F10_attack/manifest.json")?;
let m: BundleManifest = serde_json::from_str(&json)?;
m.validate()?;
println!("{} {:?}", m.primitive_id, m.ground_truth_label);
```

## License

The example bundles are MIT-licensed alongside the spec — see the
top-level `LICENSE`. Use freely. The data was produced entirely on
operator-owned localnet infrastructure with no third-party traffic
involved.
