# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Simon Morley / NullRabbit
"""Family taxonomy for bundle primitive classification.

The format targets the systems-software layer of validator
infrastructure. The same vulnerability classes you'd find in any
networked OSS daemon — response amplification, compute amplification,
memory amplification, connection exhaustion — just applied to
validator software specifically.

``family_id`` is the chain-agnostic vulnerability-class label.
``primitive_id`` (field on the manifest) is the chain-specific
implementation of a family (e.g. ``sui_F10_multi_get_objects_amp``
under ``family_id=response_amp``).

Models can train against either: family-level classification asks
"what kind of attack is this?"; primitive-level asks "which specific
known exploit is this?". Cross-chain holdout validates the format by
testing whether a model trained on Sui primitives under a family
generalises to a Solana primitive under the same family.

The enumeration is tight on purpose — each family is backed by at
least one real primitive, OR represents a pre-defined threat-model
slot whose population is intentionally deferred. Empty enum members
would be a contract claim that can't be validated, and the published
taxonomy reads as a research-scope claim. Tight beats aspirational.
Add a new family only when a primitive exists that doesn't fit any
current family, OR when the family represents a pre-defined
threat-model slot whose population is intentionally deferred.

``family_id`` is the **validator / node-software** vulnerability-class
vocabulary. On-chain contract / protocol / DeFi-economic findings (AMM
value-extraction, oracle / TWAP manipulation, liquidation, governance
capture, bridge-*contract* message abuse, ERC-4626 / reentrancy logic)
are **out of scope** — a separate DeFi-economic namespace, never
``family_id`` values. The VII ``ledger/family_map.csv`` is the
authoritative cross-map.

If a family name changes, bump ``BUNDLE_VERSION`` — it's a breaking
contract change for every bundle in the corpus.
"""

from __future__ import annotations

from enum import Enum


class FamilyId(str, Enum):
    """Chain-agnostic vulnerability-class label for a bundle.

    Enumeration: 10 attack families + 1 benign. ``reconnaissance`` is
    a deferred-population slot in v0.1.0 — the scaffolded family for
    pre-discovery and target-mapping activity (covered in upstream
    research but currently unpopulated in the public reference
    corpus).
    """

    response_amp = "response_amp"
    compute_amp = "compute_amp"
    memory_amp = "memory_amp"
    connection_exhaustion = "connection_exhaustion"
    consensus_abuse = "consensus_abuse"
    gossip_abuse = "gossip_abuse"
    auth_bypass = "auth_bypass"
    rate_limiter_bypass = "rate_limiter_bypass"
    service_misconfig = "service_misconfig"
    reconnaissance = "reconnaissance"
    benign = "benign"


FAMILY_DEFINITIONS: dict[FamilyId, str] = {
    FamilyId.response_amp:
        "Small request → disproportionately large response bytes. "
        "Attacker-side upstream cost is trivial; target-side egress "
        "dominates.",
    FamilyId.compute_amp:
        "Small request → disproportionate server-side CPU. Input size "
        "is small, processing cost is large (filter misses, parser "
        "pathologies, verification fallbacks, sync-over-async wedges).",
    FamilyId.memory_amp:
        "Unbounded accumulation of state in process memory. The "
        "attacker's input does not need to shrink, but every subsequent "
        "observation adds to retained state without bound.",
    FamilyId.connection_exhaustion:
        "Per-connection or per-subscription resource leak. Opening or "
        "subscribing consumes quota that isn't released on disconnect.",
    FamilyId.consensus_abuse:
        "Validator-authenticated misbehaviour inside the consensus "
        "protocol — equivocations, backpressure injection, proposal "
        "poisoning. Presupposes validator key material.",
    FamilyId.gossip_abuse:
        "Unauthenticated p2p / gossip protocol abuse — state-sync "
        "floods, request amplification via public peer endpoints.",
    FamilyId.auth_bypass:
        "Missing or broken authentication on a control, admin, or "
        "first-party API surface that should not be reachable without "
        "credentials.",
    FamilyId.rate_limiter_bypass:
        "Defect in rate-limiting logic allowing amplified or higher-"
        "than-intended traffic through the limiter — fail-open under "
        "errors, burst-doubling in token-bucket math, key-collision "
        "that shares quota across principals. Distinct from "
        "response_amp: the mechanism is a rate-limiter bug, the "
        "detection feature is limiter-state desync, and the mitigation "
        "is in the limiter code path — not a response-size cap.",
    FamilyId.service_misconfig:
        "Exploitable misconfiguration of an ancillary daemon that "
        "validators commonly co-locate (Redis, Elasticsearch, Grafana, "
        "Prometheus, SSH, …). Distinct from `reconnaissance` — "
        "`service_misconfig` is the exploitation of a discovered "
        "misconfig; `reconnaissance` is the prior-stage discovery "
        "traffic itself.",
    FamilyId.reconnaissance:
        "Pre-discovery and target-mapping activity against validator "
        "infrastructure. Spans the full spectrum from conventional "
        "active scanning (port enumeration, service fingerprinting, "
        "JSON-RPC method discovery) to the stealth end of the "
        "spectrum: low-frequency jittered probing, distributed low-"
        "volume reconnaissance, and timing-resonance fingerprinting "
        "that operates below the detection thresholds of conventional "
        "perimeter tooling. Included in the v1.0 taxonomy because "
        "off-the-shelf detection at the stealth end is unreliable in "
        "production deployments, and validator infrastructure is "
        "exactly the threat profile where patient adversarial pre-"
        "positioning matters. Distinct from `service_misconfig` "
        "(which is exploitation of a discovered weakness, not the "
        "discovery itself). Currently unpopulated in the v0.1.0 "
        "reference corpus.",
    FamilyId.benign:
        "No attack shape. Present to train the 'not malicious' decision "
        "boundary.",
}


assert set(FAMILY_DEFINITIONS.keys()) == set(FamilyId), (
    "every FamilyId must have a definition in FAMILY_DEFINITIONS"
)
