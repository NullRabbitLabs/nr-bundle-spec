// SPDX-License-Identifier: MIT
//! Bundle manifest types — `#[repr(C)]`-free, serde-driven.
//!
//! Mirrors `python/bundle_spec/bundle_v1.py`. Wire enum strings are
//! pinned in tests against the JSON Schema's enum lists.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::errors::BundleError;
use crate::taxonomy::FamilyId;

/// Current bundle schema version. Mirrors Python's `BUNDLE_VERSION`.
pub const BUNDLE_VERSION: u32 = 1;

/// Posture taxonomy. Mixed kebab-case / snake_case wire values
/// (preserved verbatim from corpus history; explicit per-variant
/// `serde(rename)` because no single `rename_all` rule fits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Posture {
    #[serde(rename = "saturating")]
    Saturating,
    #[serde(rename = "low-volume")]
    LowVolume,
    #[serde(rename = "distributed")]
    Distributed,
    #[serde(rename = "mimicry")]
    Mimicry,
    #[serde(rename = "insider")]
    Insider,
    #[serde(rename = "validator-compromised")]
    ValidatorCompromised,
    #[serde(rename = "reconnaissance")]
    Reconnaissance,
    #[serde(rename = "historical-cve")]
    HistoricalCve,
    #[serde(rename = "wallet_normal")]
    WalletNormal,
    #[serde(rename = "indexer_normal")]
    IndexerNormal,
    #[serde(rename = "light_client_normal")]
    LightClientNormal,
    #[serde(rename = "mixed_normal")]
    MixedNormal,
    #[serde(rename = "dex_swap_burst")]
    DexSwapBurst,
    #[serde(rename = "nft_mint_storm")]
    NftMintStorm,
    #[serde(rename = "indexer_backfill")]
    IndexerBackfill,
    #[serde(rename = "mixed_high_load")]
    MixedHighLoad,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroundTruthLabel {
    Attack,
    Benign,
    Suspicious,
}

/// How the captured traffic was produced. All values kebab-case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrafficSource {
    SyntheticClient,
    MainnetOrganic,
    Mixed,
    ReproducerAttack,
    ReproducerBenign,
    ValidatorUnderLoad,
}

/// Fidelity tier — how faithfully the bundle reproduces the real
/// attack on the wire. All values kebab-case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FidelityClass {
    Stub,
    Proxy,
    Lab,
    LabTlsFronted,
    ProductionCaptured,
    ProductionDerived,
}

/// Authorisation scope for the captured target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetAuthorisation {
    SelfOwned,
    CustomerAuthorised,
    PublicMainnetPassive,
    Synthetic,
}

/// Bundle-production provenance. Required structured fields plus a
/// catch-all extras map (mirrors Pydantic's `extra="allow"`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provenance {
    pub traffic_source: TrafficSource,
    pub fidelity_class: FidelityClass,
    pub target_authorisation: TargetAuthorisation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engagement_id: Option<String>,
    #[serde(default)]
    pub tooling: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcap_path_pre_termination: Option<String>,
    /// Catch-all for the per-recorder extras Python's
    /// `model_config(extra="allow")` permits (return codes, node
    /// pids, capture-module name, etc.). Preserved on round-trip.
    #[serde(flatten)]
    pub extras: HashMap<String, Value>,
}

impl Provenance {
    /// Validate the cross-field invariant: customer-authorised
    /// captures require `engagement_id`. Mirrors Python's
    /// `_engagement_id_required_for_customer` model_validator.
    pub fn validate(&self) -> Result<(), BundleError> {
        if matches!(
            self.target_authorisation,
            TargetAuthorisation::CustomerAuthorised
        ) && self.engagement_id.as_deref().unwrap_or("").is_empty()
        {
            return Err(BundleError::Contract(
                "engagement_id is required when \
                 target_authorisation='customer-authorised'"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Which on-disk files the bundle actually contains.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleFiles {
    #[serde(default = "default_true")]
    pub packets_pcap: bool,
    #[serde(default)]
    pub host_parquet: bool,
    #[serde(default)]
    pub app_parquet: bool,
    #[serde(default)]
    pub protocol_parquet: bool,
    #[serde(default)]
    pub responses_parquet: bool,
    #[serde(default)]
    pub vectors_parquet: bool,
}

fn default_true() -> bool {
    true
}

impl Default for BundleFiles {
    fn default() -> Self {
        Self {
            packets_pcap: true,
            host_parquet: false,
            app_parquet: false,
            protocol_parquet: false,
            responses_parquet: false,
            vectors_parquet: false,
        }
    }
}

/// Top-level manifest — one per bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    #[serde(default = "default_bundle_version")]
    pub bundle_version: u32,
    /// `"v0.0"` (legacy pcap-only ingest) or `"v1.0"` (full multi-modal).
    pub shape: String,

    pub corpus_id: String,
    pub attack_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genome_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assessment_id: Option<String>,

    pub family_id: FamilyId,
    pub primitive_id: String,
    pub posture: Posture,
    pub ground_truth_label: GroundTruthLabel,
    pub chain: String,

    pub run_tag: String,
    pub target_env: String,
    #[serde(default = "default_generation_method")]
    pub generation_method: String,

    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,

    #[serde(default)]
    pub attack_parameters: serde_json::Map<String, Value>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_detection_signature: Option<serde_json::Map<String, Value>>,

    #[serde(default)]
    pub files: BundleFiles,

    pub provenance: Provenance,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

fn default_bundle_version() -> u32 {
    BUNDLE_VERSION
}

fn default_generation_method() -> String {
    "hand".to_string()
}

impl BundleManifest {
    /// Run all cross-field invariants that Pydantic enforces via
    /// `@model_validator`. Call this after deserialisation —
    /// `serde_json::from_str` only handles per-field types, not
    /// cross-field rules.
    ///
    /// Rules enforced (mirrors `bundle_v1.py`):
    /// - `ended_at >= started_at`
    /// - non-empty: `corpus_id`, `attack_id`, `primitive_id`,
    ///   `run_tag`, `target_env`, `chain`
    /// - `generation_method` ∈ {hand, rules_v0, llm_v0,
    ///   production_review, backfill_v0}
    /// - `genome_id` required when `ground_truth_label == "attack"`
    /// - `provenance.tooling` non-empty when
    ///   `family_id == "reconnaissance"`
    /// - `provenance.engagement_id` required when
    ///   `target_authorisation == "customer-authorised"` (delegated
    ///   to `Provenance::validate`)
    pub fn validate(&self) -> Result<(), BundleError> {
        if self.ended_at < self.started_at {
            return Err(BundleError::Contract(
                "ended_at must be >= started_at".into(),
            ));
        }

        for (name, value) in [
            ("corpus_id", &self.corpus_id),
            ("attack_id", &self.attack_id),
            ("primitive_id", &self.primitive_id),
            ("run_tag", &self.run_tag),
            ("target_env", &self.target_env),
            ("chain", &self.chain),
        ] {
            if value.trim().is_empty() {
                return Err(BundleError::Contract(format!(
                    "{} must be a non-empty string",
                    name
                )));
            }
        }

        if !matches!(
            self.generation_method.as_str(),
            "hand" | "rules_v0" | "llm_v0" | "production_review" | "backfill_v0",
        ) {
            return Err(BundleError::Contract(format!(
                "generation_method '{}' is not one of \
                 hand / rules_v0 / llm_v0 / production_review / backfill_v0",
                self.generation_method,
            )));
        }

        if matches!(self.ground_truth_label, GroundTruthLabel::Attack)
            && self.genome_id.as_deref().unwrap_or("").is_empty()
        {
            return Err(BundleError::Contract(
                "genome_id is required for bundles with \
                 ground_truth_label='attack'. Use compute_genome_id() \
                 to derive it."
                    .into(),
            ));
        }

        if matches!(self.family_id, FamilyId::Reconnaissance) && self.provenance.tooling.is_empty()
        {
            return Err(BundleError::Contract(
                "provenance.tooling is required (non-empty) for bundles \
                 with family_id='reconnaissance'. Populate with \
                 {tool_name: version} pairs at produce-time."
                    .into(),
            ));
        }

        self.provenance.validate()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_attack_manifest_json() -> Value {
        json!({
            "bundle_version": 1,
            "shape": "v1.0",
            "corpus_id": "crp_test_00000001",
            "attack_id": "atk_test_00000001",
            "genome_id": "aabbccdd11223344",
            "family_id": "response_amp",
            "primitive_id": "sui_F10_multi_get_objects_amp",
            "posture": "saturating",
            "ground_truth_label": "attack",
            "chain": "sui",
            "run_tag": "smoke",
            "target_env": "localnet-sui-multinode4",
            "started_at": "2026-04-25T10:14:30Z",
            "ended_at":   "2026-04-25T10:15:30Z",
            "provenance": {
                "traffic_source": "reproducer-attack",
                "fidelity_class": "lab",
                "target_authorisation": "self-owned"
            }
        })
    }

    #[test]
    fn round_trip_minimal_attack_manifest() {
        let value = valid_attack_manifest_json();
        let m: BundleManifest = serde_json::from_value(value).unwrap();
        m.validate().unwrap();
        assert_eq!(m.bundle_version, 1);
        assert!(matches!(m.family_id, FamilyId::ResponseAmp));
        assert!(matches!(m.ground_truth_label, GroundTruthLabel::Attack));
        assert!(matches!(m.posture, Posture::Saturating));
        assert!(matches!(m.provenance.fidelity_class, FidelityClass::Lab));
    }

    #[test]
    fn rejects_attack_without_genome_id() {
        let mut value = valid_attack_manifest_json();
        value.as_object_mut().unwrap().remove("genome_id");
        let m: BundleManifest = serde_json::from_value(value).unwrap();
        let err = m.validate().unwrap_err();
        assert!(format!("{}", err).contains("genome_id"));
    }

    #[test]
    fn rejects_ended_before_started() {
        let mut value = valid_attack_manifest_json();
        value["ended_at"] = json!("2026-04-25T10:00:00Z");
        let m: BundleManifest = serde_json::from_value(value).unwrap();
        let err = m.validate().unwrap_err();
        assert!(format!("{}", err).contains("ended_at"));
    }

    #[test]
    fn rejects_empty_corpus_id() {
        let mut value = valid_attack_manifest_json();
        value["corpus_id"] = json!("");
        let m: BundleManifest = serde_json::from_value(value).unwrap();
        let err = m.validate().unwrap_err();
        assert!(format!("{}", err).contains("corpus_id"));
    }

    #[test]
    fn rejects_unknown_generation_method() {
        let mut value = valid_attack_manifest_json();
        value["generation_method"] = json!("not_a_method");
        let m: BundleManifest = serde_json::from_value(value).unwrap();
        let err = m.validate().unwrap_err();
        assert!(format!("{}", err).contains("generation_method"));
    }

    #[test]
    fn customer_authorised_requires_engagement_id() {
        let mut value = valid_attack_manifest_json();
        value["provenance"]["target_authorisation"] = json!("customer-authorised");
        let m: BundleManifest = serde_json::from_value(value).unwrap();
        let err = m.validate().unwrap_err();
        assert!(format!("{}", err).contains("engagement_id"));
    }

    #[test]
    fn reconnaissance_requires_tooling() {
        let mut value = valid_attack_manifest_json();
        value["family_id"] = json!("reconnaissance");
        // genome_id no longer needed (recon may be benign-shaped); switch
        // to benign label to avoid the genome_id rule firing first.
        value["ground_truth_label"] = json!("suspicious");
        value.as_object_mut().unwrap().remove("genome_id");
        let m: BundleManifest = serde_json::from_value(value).unwrap();
        let err = m.validate().unwrap_err();
        assert!(format!("{}", err).contains("tooling"));
    }

    #[test]
    fn benign_allows_missing_genome_id() {
        let mut value = valid_attack_manifest_json();
        value["ground_truth_label"] = json!("benign");
        value.as_object_mut().unwrap().remove("genome_id");
        let m: BundleManifest = serde_json::from_value(value).unwrap();
        m.validate().unwrap();
    }

    #[test]
    fn provenance_extras_round_trip() {
        // Pydantic's extra="allow" preserves unknown fields; serde's
        // #[serde(flatten)] does the same. Pin this contract.
        let mut value = valid_attack_manifest_json();
        value["provenance"]["custom_node_pid"] = json!(12345);
        value["provenance"]["tcpdump_returncode"] = json!(0);
        let m: BundleManifest = serde_json::from_value(value.clone()).unwrap();
        let serialised = serde_json::to_value(&m).unwrap();
        assert_eq!(
            serialised["provenance"]["custom_node_pid"],
            json!(12345),
            "provenance extras must round-trip"
        );
        assert_eq!(serialised["provenance"]["tcpdump_returncode"], json!(0),);
    }

    #[test]
    fn fidelity_class_kebab_case_round_trip() {
        for (variant, expected) in [
            (FidelityClass::Stub, "stub"),
            (FidelityClass::Proxy, "proxy"),
            (FidelityClass::Lab, "lab"),
            (FidelityClass::LabTlsFronted, "lab-tls-fronted"),
            (FidelityClass::ProductionCaptured, "production-captured"),
            (FidelityClass::ProductionDerived, "production-derived"),
        ] {
            assert_eq!(serde_json::to_value(variant).unwrap(), json!(expected));
        }
    }

    #[test]
    fn target_authorisation_kebab_case_round_trip() {
        for (variant, expected) in [
            (TargetAuthorisation::SelfOwned, "self-owned"),
            (
                TargetAuthorisation::CustomerAuthorised,
                "customer-authorised",
            ),
            (
                TargetAuthorisation::PublicMainnetPassive,
                "public-mainnet-passive",
            ),
            (TargetAuthorisation::Synthetic, "synthetic"),
        ] {
            assert_eq!(serde_json::to_value(variant).unwrap(), json!(expected));
        }
    }

    #[test]
    fn traffic_source_kebab_case_round_trip() {
        for (variant, expected) in [
            (TrafficSource::SyntheticClient, "synthetic-client"),
            (TrafficSource::MainnetOrganic, "mainnet-organic"),
            (TrafficSource::Mixed, "mixed"),
            (TrafficSource::ReproducerAttack, "reproducer-attack"),
            (TrafficSource::ReproducerBenign, "reproducer-benign"),
            (TrafficSource::ValidatorUnderLoad, "validator-under-load"),
        ] {
            assert_eq!(serde_json::to_value(variant).unwrap(), json!(expected));
        }
    }

    #[test]
    fn posture_mixed_naming_round_trip() {
        // Spot-check the kebab + snake mix.
        for (variant, expected) in [
            (Posture::Saturating, "saturating"),
            (Posture::LowVolume, "low-volume"),
            (Posture::ValidatorCompromised, "validator-compromised"),
            (Posture::HistoricalCve, "historical-cve"),
            (Posture::WalletNormal, "wallet_normal"),
            (Posture::IndexerNormal, "indexer_normal"),
            (Posture::DexSwapBurst, "dex_swap_burst"),
            (Posture::MixedHighLoad, "mixed_high_load"),
        ] {
            assert_eq!(serde_json::to_value(variant).unwrap(), json!(expected));
        }
    }

    #[test]
    fn bundle_files_default_packets_pcap_true() {
        let bf = BundleFiles::default();
        assert!(bf.packets_pcap);
        assert!(!bf.host_parquet);
        assert!(!bf.responses_parquet);
    }
}
