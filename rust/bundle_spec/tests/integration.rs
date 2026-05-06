// SPDX-License-Identifier: MIT
//! End-to-end integration tests for the Rust reference parser.
//!
//! These tests exercise the full path: deserialize a JSON manifest →
//! call `validate()` → confirm structural + cross-field invariants
//! match the Pydantic side.

use bundle_spec::{
    compute_genome_id, validate_manifest_json, BundleManifest, FamilyId, FidelityClass,
    GroundTruthLabel, Posture, TargetAuthorisation, TrafficSource,
};
use serde_json::json;

#[test]
fn round_trip_full_attack_manifest() {
    let m_json = json!({
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
        "run_tag": "saturating_baseline_2026-04-25",
        "target_env": "localnet-sui-multinode4",
        "started_at": "2026-04-25T10:14:30Z",
        "ended_at":   "2026-04-25T10:15:30Z",
        "attack_parameters": {
            "concurrent_requests": 16,
            "duration_sec": 60
        },
        "files": {
            "packets_pcap": true,
            "host_parquet": true,
            "app_parquet": true,
            "protocol_parquet": true,
            "responses_parquet": true,
            "vectors_parquet": false
        },
        "provenance": {
            "traffic_source": "reproducer-attack",
            "fidelity_class": "lab",
            "target_authorisation": "self-owned",
            "tooling": {"reproducer": "v0.4.2"},
            "node_pid": 463106,
            "tcpdump_returncode": 0
        },
        "notes": "saturating baseline, 4-validator localnet"
    });

    // 1) JSON Schema validation passes.
    validate_manifest_json(&m_json).expect("schema validation must pass");

    // 2) Strongly-typed parse + cross-field validation passes.
    let m: BundleManifest = serde_json::from_value(m_json.clone()).unwrap();
    m.validate().expect("cross-field validation must pass");

    // 3) Field values match.
    assert!(matches!(m.family_id, FamilyId::ResponseAmp));
    assert!(matches!(m.posture, Posture::Saturating));
    assert!(matches!(m.ground_truth_label, GroundTruthLabel::Attack));
    assert!(matches!(
        m.provenance.traffic_source,
        TrafficSource::ReproducerAttack,
    ));
    assert!(matches!(m.provenance.fidelity_class, FidelityClass::Lab));
    assert!(matches!(
        m.provenance.target_authorisation,
        TargetAuthorisation::SelfOwned,
    ));
    assert_eq!(
        m.provenance.tooling.get("reproducer").map(|s| s.as_str()),
        Some("v0.4.2")
    );

    // 4) Provenance extras preserved.
    assert_eq!(
        m.provenance.extras.get("node_pid").and_then(|v| v.as_i64()),
        Some(463106),
    );

    // 5) Re-serialise round-trips.
    let serialised = serde_json::to_value(&m).unwrap();
    assert_eq!(serialised["family_id"], json!("response_amp"));
    assert_eq!(serialised["provenance"]["fidelity_class"], json!("lab"));
}

#[test]
fn benign_manifest_round_trips() {
    let m_json = json!({
        "shape": "v1.0",
        "corpus_id": "crp_test_benign",
        "attack_id": "atk_test_benign",
        "family_id": "benign",
        "primitive_id": "sui_BENIGN_reproducer_pipeline",
        "posture": "wallet_normal",
        "ground_truth_label": "benign",
        "chain": "sui",
        "run_tag": "benign_smoke",
        "target_env": "localnet-sui-multinode4",
        "started_at": "2026-04-25T10:00:00Z",
        "ended_at":   "2026-04-25T10:01:00Z",
        "provenance": {
            "traffic_source": "reproducer-benign",
            "fidelity_class": "lab",
            "target_authorisation": "self-owned"
        }
    });
    let m: BundleManifest = serde_json::from_value(m_json).unwrap();
    m.validate().unwrap();
    assert!(matches!(m.family_id, FamilyId::Benign));
    assert!(m.genome_id.is_none(), "benign may omit genome_id");
}

#[test]
fn cross_language_genome_id_pin() {
    // Same vector as the Python tests in tests/test_contracts.py.
    let g = compute_genome_id(&json!({"a": 1, "b": 2, "c": 3}));
    assert_eq!(
        g, "d97e5b9864df8961",
        "genome_id determinism failed — Rust diverged from Python."
    );
}

#[test]
fn lab_tls_fronted_manifest_with_pre_term_pcap() {
    let m_json = json!({
        "shape": "v1.0",
        "corpus_id": "crp_lab_tls",
        "attack_id": "atk_lab_tls",
        "genome_id": "1234567890abcdef",
        "family_id": "response_amp",
        "primitive_id": "sui_F10_multi_get_objects_amp",
        "posture": "saturating",
        "ground_truth_label": "attack",
        "chain": "sui",
        "run_tag": "lab_tls_fronted",
        "target_env": "localnet-sui-multinode4",
        "started_at": "2026-04-25T10:00:00Z",
        "ended_at":   "2026-04-25T10:01:00Z",
        "provenance": {
            "traffic_source": "reproducer-attack",
            "fidelity_class": "lab-tls-fronted",
            "target_authorisation": "self-owned",
            "pcap_path_pre_termination": "pcap_pre_termination.pcap"
        }
    });
    let m: BundleManifest = serde_json::from_value(m_json).unwrap();
    m.validate().unwrap();
    assert!(matches!(
        m.provenance.fidelity_class,
        FidelityClass::LabTlsFronted,
    ));
    assert_eq!(
        m.provenance.pcap_path_pre_termination.as_deref(),
        Some("pcap_pre_termination.pcap"),
    );
}
