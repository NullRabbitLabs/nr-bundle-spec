# Adopting the standard: classify a validator-integrity finding

The Bundle v1 format and its family vocabulary are published so that adversarial research on validator
infrastructure becomes comparable: one on-disk shape, one labelling scheme, one evaluation methodology,
adoptable on your own data without coordination. This guide shows how to classify a node or client
integrity finding into the vocabulary. It is deliberately short.

## The eleven families

| family | what it is | how to tell it apart |
|---|---|---|
| `response_amp` | a small request that returns disproportionately large response bytes | the cost lands on the server's outbound bandwidth |
| `compute_amp` | a small request that triggers disproportionate server-side CPU | parser pathologies, verification fallbacks, sync-over-async wedges |
| `memory_amp` | unbounded accumulation of retained state in process memory | it grows over time, not per request |
| `connection_exhaustion` | a per-connection or per-subscription resource that is never released on disconnect | the leak is the open handle, not the payload |
| `consensus_abuse` | validator-authenticated misbehaviour inside consensus | it presupposes validator key material |
| `gossip_abuse` | unauthenticated peer-to-peer or gossip abuse via public peer endpoints | state-sync floods, request amplification |
| `auth_bypass` | missing or broken authentication on a control, admin, or first-party API | the surface should have required credentials |
| `rate_limiter_bypass` | a defect in the rate-limiter's own logic | fail-open, burst-doubling, or key-collision, not a response-size issue |
| `service_misconfig` | exploitation of a misconfigured co-located daemon | Redis, Grafana, Prometheus, SSH, and similar |
| `reconnaissance` | discovery and target-mapping traffic itself | it is the prior stage, not the exploit |
| `benign` | no attack shape | it trains the "not malicious" boundary |

## How to classify a finding

Work top to bottom. The first rule that matches gives the family.

1. If it is only discovery or mapping traffic, with no exploitation, it is `reconnaissance`.
2. If it requires validator key material to misbehave inside consensus, it is `consensus_abuse`.
3. If it is unauthenticated abuse of a public peer-to-peer or gossip endpoint, it is `gossip_abuse`.
4. If it defeats authentication on a surface that should need credentials, it is `auth_bypass`.
5. If the bug is in the rate-limiter's own logic, it is `rate_limiter_bypass`.
6. If it is a misconfigured co-located service being exploited, it is `service_misconfig`.
7. Otherwise it is a resource-amplification shape. Pick by the resource that dominates: large response
   bytes from a small request is `response_amp`; large CPU from a small request is `compute_amp`;
   unbounded retained memory over time is `memory_amp`; a per-connection or per-subscription leak is
   `connection_exhaustion`.
8. If there is no attack shape, it is `benign`.

A finding can touch more than one mechanism. Label it by the dominant one, meaning the mechanism the
mitigation lives in. A response-size cap fixes `response_amp`; a fix in the limiter logic is
`rate_limiter_bypass`.

## A worked example, using a public NullRabbit advisory

Take advisory NR-2026-001 (Solana). An unauthenticated `getMultipleAccounts` JSON-RPC call returns far
more response bytes than the request costs to send, so one caller can drive disproportionate server
egress.

Walk the rules in order. Is it discovery only? No. Does it need consensus key material? No. Is it
peer-to-peer or gossip? No, it is the public JSON-RPC surface. Does it defeat authentication? No. Is it a
rate-limiter logic bug? No. Is it a co-located service? No. It is a resource-amplification shape, and the
dominant cost is response bytes, so it is `response_amp`.

For contrast, the same advisory's `simulateTransaction` finding drives disproportionate CPU rather than
bytes, so it is `compute_amp`. Same endpoint family, different family label, because the dominant resource
differs. That is the discipline the vocabulary is meant to enforce.

## Producing bundles

To contribute measurements, capture each run in the Bundle v1 shape: a manifest, a packet capture, and the
four time-series modalities (host, app, protocol, responses), as specified in this repository. The public
sample dataset provides ground-truth examples to validate your pipeline against.

## Citing and contributing

Cite the format using the `CITATION.cff` file in this repository. The format is MIT-licensed, so you can
adopt it on your own infrastructure and publish results citing it. To propose a new family or refine a
definition, open an issue. The vocabulary is versioned and evolves by proposal, not by decree.

## Scope

This vocabulary is for node and client software findings only. On-chain contract, protocol, and
DeFi-economic findings use a separate vocabulary and are out of scope here.
