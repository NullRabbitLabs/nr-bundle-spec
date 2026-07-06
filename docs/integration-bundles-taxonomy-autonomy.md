# Bundles, the family taxonomy, and earned autonomy

*How the three layers of the NullRabbit stack connect: the on-disk **bundle**, the
chain-agnostic **family taxonomy** that labels it, and the **earned-autonomy**
validation the labelled corpus makes possible.*

The three are usually described separately — a capture format, a labelling scheme,
a rating methodology. They are one pipeline, and the joints between them are where
the honesty lives. This note is the joint documentation.

---

## 1. Bundle → observation

A [bundle](../README.md) is one directory: a `manifest.json` plus up to five
Parquet modalities (`host`, `app`, `protocol`, `responses`, `vectors`) and an
optional `packets.pcap`, all keyed on a monotonic `t_ns`. It is a **multi-modal
observation of one validator under one workload** — nothing more. Crucially it is
*chain-agnostic*: no field assumes a specific blockchain. A Bitcoin Core
`getheaders` flood and a Sui `multiGetObjects` amplification land in the same
schema, so they become directly comparable rather than two bespoke datasets.

What each modality carries, and why a detector cares:

| modality | signal | which mechanisms it exposes |
|---|---|---|
| `host.parquet` | cpu %, rss/vms bytes, fds, connections, io | `compute_amp` (cpu), `memory_amp` (rss growth), `connection_exhaustion` (fds/conns) |
| `responses.parquet` | per-request req/resp bytes, status, duration | `response_amp` (resp÷req ratio), `subscription_cpu_amp` (duration) |
| `protocol.parquet` | consensus / p2p signal time-series | `consensus_abuse`, `gossip_abuse` |
| `app.parquet` | validator-exposed metric scrapes | cross-checks host under the daemon's own view |

The `examples/train_a_family_detector.py` script in this repo is the minimal path
from these files to a feature vector.

---

## 2. Observation → family

The manifest's `family_id` is the **mechanism label**, drawn from the 12-attack +
`benign` [taxonomy](../python/bundle_spec/taxonomy.py) (see the
[adoption guide](adoption-guide.md) for the classification rules). The taxonomy is
defined by *attack mechanism*, not by chain, port, or client. That single design
choice is what makes the corpus more than a pile of captures:

- **The same mechanism on different chains shares a label.** `response_amp` is
  `response_amp` whether it is a Sui indexer or an XRPL batch. So a model can, in
  principle, learn the *mechanism* and carry it to a chain it has never seen.
- **`benign` is a first-class label, and it is load-bearing.** Benign traffic
  *exercises the same wire messages the attacks abuse*, at normal rate. A detector
  must separate attack-*use* from benign-*use* of a method — not merely "large" or
  "fast". A family classifier that cannot tell benign `multiGetObjects` from an
  amplifying one has learned nothing useful.
- **Provenance rides alongside, and gates publishing.** Each bundle's
  `provenance.source_class` is `public-cve-replication` (a faithful reproduction of
  a public CVE/GHSA/audit — freely publishable) or `original` (NullRabbit's own
  disclosure-gated measurement). The public dataset ships the former; the taxonomy
  label is identical for both, so the *mechanism* science is separable from the
  *disclosure* question. See [methodology.md](methodology.md) §2.

---

## 3. Family → earned autonomy

A labelled, chain-agnostic corpus turns a claim everyone wants to make —
*"our detector generalises across chains"* — into a **measurable one**, and that
measurement is what makes a detector's autonomy *earned* rather than asserted.

The test is **leave-one-chain-out (LOCO)**: hold out an entire chain, train the
family classifier on the others, and measure whether it recovers the held-out
chain's mechanism families zero-shot. Two numbers come out, and the discipline is
to never let the first stand in for the second:

- **In-distribution** (k-fold over the pooled corpus): the detector separates
  families it has seen on a chain. Real, but the *easy* number.
- **Cross-chain LOCO**: the detector on a chain it has **never trained on**. This
  is the honest number — and on the public corpus it does **not** yet transfer for
  protocol-distinct chains (near-floor macro-F1 for Monero, Bitcoin, Ethereum),
  while it is trivially high only for wire-identical forks (Dogecoin/Litecoin
  inherit Bitcoin's exact primitives, so "transfer" there is not generalisation).

**This is the earned-autonomy line.** A detector's autonomy is earned exactly on
the chains where its cross-chain number holds up:

> High LOCO on a chain → the mechanism signal genuinely transfers → the detector
> can run there with earned confidence.
> Near-floor LOCO → it cannot → the honest move is to **gate** the detector to
> chains you have training data for, and say so.

The corpus does not exist to prove generalisation; it exists to let you *find the
line* where generalisation stops, and to keep a detector's deployed autonomy on the
right side of it. That is the same discipline the Validator Integrity Index applies
to findings ([methodology.md](methodology.md)): the method and its honest limits
*are* the product. Run `examples/train_a_family_detector.py` to reproduce both
numbers on the public data and see the line for yourself.
