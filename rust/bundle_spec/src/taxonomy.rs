// SPDX-License-Identifier: MIT
//! Family taxonomy — chain-agnostic vulnerability-class label.
//!
//! Mirrors `python/bundle_spec/taxonomy.py`. Cross-language enum
//! consistency is pinned by the JSON Schema contract: both
//! languages emit the same wire string for each variant.

use serde::{Deserialize, Serialize};

/// Chain-agnostic vulnerability-class label for a bundle.
///
/// Enumeration: 10 attack families + 1 benign. `reconnaissance` is a
/// deferred-population slot in v0.1.0 — the scaffolded family for
/// pre-discovery and target-mapping activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FamilyId {
    /// Small request → disproportionately large response bytes.
    ResponseAmp,
    /// Small request → disproportionate server-side CPU.
    ComputeAmp,
    /// Unbounded accumulation of state in process memory.
    MemoryAmp,
    /// Per-connection or per-subscription resource leak.
    ConnectionExhaustion,
    /// Validator-authenticated misbehaviour inside consensus.
    ConsensusAbuse,
    /// Unauthenticated p2p / gossip protocol abuse.
    GossipAbuse,
    /// Missing or broken authentication on a control surface.
    AuthBypass,
    /// Defect in rate-limiting logic allowing amplified traffic.
    RateLimiterBypass,
    /// Exploitable misconfiguration of an ancillary daemon.
    ServiceMisconfig,
    /// Pre-discovery / target-mapping activity.
    Reconnaissance,
    /// Subscription/streaming filter with disproportionate per-event CPU.
    SubscriptionCpuAmp,
    /// Abuse of the state / snapshot bootstrap-import path.
    StateImportAbuse,
    /// No attack shape; trains the "not malicious" decision boundary.
    Benign,
}

impl FamilyId {
    /// Wire string (matches Python `FamilyId.value`).
    pub const fn as_str(self) -> &'static str {
        match self {
            FamilyId::ResponseAmp => "response_amp",
            FamilyId::ComputeAmp => "compute_amp",
            FamilyId::MemoryAmp => "memory_amp",
            FamilyId::ConnectionExhaustion => "connection_exhaustion",
            FamilyId::ConsensusAbuse => "consensus_abuse",
            FamilyId::GossipAbuse => "gossip_abuse",
            FamilyId::AuthBypass => "auth_bypass",
            FamilyId::RateLimiterBypass => "rate_limiter_bypass",
            FamilyId::ServiceMisconfig => "service_misconfig",
            FamilyId::Reconnaissance => "reconnaissance",
            FamilyId::SubscriptionCpuAmp => "subscription_cpu_amp",
            FamilyId::StateImportAbuse => "state_import_abuse",
            FamilyId::Benign => "benign",
        }
    }
}

/// One-line definition for each family. Mirrors
/// `bundle_spec.taxonomy.FAMILY_DEFINITIONS` in Python.
pub fn family_definitions() -> &'static [(FamilyId, &'static str)] {
    &[
        (
            FamilyId::ResponseAmp,
            "Small request → disproportionately large response bytes. \
             Attacker-side upstream cost is trivial; target-side egress \
             dominates.",
        ),
        (
            FamilyId::ComputeAmp,
            "Small request → disproportionate server-side CPU. Input size \
             is small, processing cost is large (filter misses, parser \
             pathologies, verification fallbacks, sync-over-async wedges).",
        ),
        (
            FamilyId::MemoryAmp,
            "Unbounded accumulation of state in process memory. The \
             attacker's input does not need to shrink, but every subsequent \
             observation adds to retained state without bound.",
        ),
        (
            FamilyId::ConnectionExhaustion,
            "Per-connection or per-subscription resource leak. Opening or \
             subscribing consumes quota that isn't released on disconnect.",
        ),
        (
            FamilyId::ConsensusAbuse,
            "Validator-authenticated misbehaviour inside the consensus \
             protocol — equivocations, backpressure injection, proposal \
             poisoning. Presupposes validator key material.",
        ),
        (
            FamilyId::GossipAbuse,
            "Unauthenticated p2p / gossip protocol abuse — state-sync \
             floods, request amplification via public peer endpoints.",
        ),
        (
            FamilyId::AuthBypass,
            "Missing or broken authentication on a control, admin, or \
             first-party API surface that should not be reachable without \
             credentials.",
        ),
        (
            FamilyId::RateLimiterBypass,
            "Defect in rate-limiting logic allowing amplified or higher-\
             than-intended traffic through the limiter.",
        ),
        (
            FamilyId::ServiceMisconfig,
            "Exploitable misconfiguration of an ancillary daemon that \
             validators commonly co-locate (Redis, Elasticsearch, Grafana, \
             Prometheus, SSH, …).",
        ),
        (
            FamilyId::Reconnaissance,
            "Pre-discovery and target-mapping activity against validator \
             infrastructure. Currently unpopulated in the v0.1.0 reference \
             corpus.",
        ),
        (
            FamilyId::SubscriptionCpuAmp,
            "A subscription or streaming filter whose per-notification \
             server-side cost is disproportionate to the trivial cost of \
             subscribing. A wide filter makes every matching event drive \
             expensive server work, so one cheap subscribe sustains \
             unbounded CPU.",
        ),
        (
            FamilyId::StateImportAbuse,
            "Abuse of a node's state / snapshot bootstrap-import path. A \
             malformed or oversized state artefact (snapshot, append-vec, \
             ledger segment) fed to the import / reconstruction pipeline \
             triggers a crash, panic, or resource blow-up during \
             deserialisation — before the artefact is fully validated.",
        ),
        (
            FamilyId::Benign,
            "No attack shape. Present to train the 'not malicious' decision \
             boundary.",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn family_id_serialises_to_wire_string() {
        for (variant, expected) in [
            (FamilyId::ResponseAmp, "response_amp"),
            (FamilyId::ComputeAmp, "compute_amp"),
            (FamilyId::MemoryAmp, "memory_amp"),
            (FamilyId::ConnectionExhaustion, "connection_exhaustion"),
            (FamilyId::ConsensusAbuse, "consensus_abuse"),
            (FamilyId::GossipAbuse, "gossip_abuse"),
            (FamilyId::AuthBypass, "auth_bypass"),
            (FamilyId::RateLimiterBypass, "rate_limiter_bypass"),
            (FamilyId::ServiceMisconfig, "service_misconfig"),
            (FamilyId::Reconnaissance, "reconnaissance"),
            (FamilyId::SubscriptionCpuAmp, "subscription_cpu_amp"),
            (FamilyId::StateImportAbuse, "state_import_abuse"),
            (FamilyId::Benign, "benign"),
        ] {
            assert_eq!(serde_json::to_value(variant).unwrap(), json!(expected));
            assert_eq!(variant.as_str(), expected);
        }
    }

    #[test]
    fn family_id_deserialises_from_wire_string() {
        for s in [
            "response_amp",
            "compute_amp",
            "memory_amp",
            "connection_exhaustion",
            "consensus_abuse",
            "gossip_abuse",
            "auth_bypass",
            "rate_limiter_bypass",
            "service_misconfig",
            "reconnaissance",
            "benign",
        ] {
            let _: FamilyId = serde_json::from_str(&format!("\"{}\"", s)).unwrap();
        }
    }

    #[test]
    fn family_id_rejects_unknown_value() {
        let result: Result<FamilyId, _> = serde_json::from_str("\"not_a_family\"");
        assert!(result.is_err());
    }

    #[test]
    fn family_definitions_covers_all_variants() {
        let defs = family_definitions();
        assert_eq!(defs.len(), 13);
        for variant in [
            FamilyId::ResponseAmp,
            FamilyId::ComputeAmp,
            FamilyId::MemoryAmp,
            FamilyId::ConnectionExhaustion,
            FamilyId::ConsensusAbuse,
            FamilyId::GossipAbuse,
            FamilyId::AuthBypass,
            FamilyId::RateLimiterBypass,
            FamilyId::ServiceMisconfig,
            FamilyId::Reconnaissance,
            FamilyId::SubscriptionCpuAmp,
            FamilyId::StateImportAbuse,
            FamilyId::Benign,
        ] {
            assert!(
                defs.iter().any(|(v, _)| *v == variant),
                "missing family definition for {:?}",
                variant
            );
        }
    }
}
