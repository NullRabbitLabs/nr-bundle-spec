// SPDX-License-Identifier: MIT
//! JSON Schema validation against the bundled schema artefacts.
//!
//! The schemas under `schema/` in the repo root are embedded into
//! the crate at compile time via `include_str!()` so callers don't
//! need to ship them separately.

use crate::errors::BundleError;

/// Embedded JSON Schema for `BundleManifest` (regenerated from the
/// canonical Pydantic models — see `tools/regen_schema.py`).
pub const BUNDLE_MANIFEST_SCHEMA_JSON: &str =
    include_str!("../../../schema/bundle_v1.schema.json");

/// Embedded JSON Schema for `PrimitiveDescriptor`.
pub const PRIMITIVE_DESCRIPTOR_SCHEMA_JSON: &str =
    include_str!("../../../schema/primitive_v1.schema.json");

/// Validate a manifest JSON value against the bundled JSON Schema.
///
/// This is a *structural* validation — types, required fields, enum
/// values. Cross-field invariants (e.g. `genome_id` required when
/// `ground_truth_label == "attack"`) are not in JSON Schema; use
/// [`crate::manifest::BundleManifest::validate`] for those.
pub fn validate_manifest_json(value: &serde_json::Value) -> Result<(), BundleError> {
    let schema: serde_json::Value = serde_json::from_str(BUNDLE_MANIFEST_SCHEMA_JSON)
        .map_err(|e| BundleError::Schema(format!("schema parse: {}", e)))?;
    let validator = jsonschema::JSONSchema::compile(&schema)
        .map_err(|e| BundleError::Schema(format!("schema compile: {}", e)))?;
    if let Err(errors) = validator.validate(value) {
        let messages: Vec<String> = errors.map(|e| e.to_string()).collect();
        return Err(BundleError::Schema(messages.join("; ")));
    }
    Ok(())
}

/// Validate a primitive descriptor JSON value against the bundled schema.
pub fn validate_primitive_json(value: &serde_json::Value) -> Result<(), BundleError> {
    let schema: serde_json::Value = serde_json::from_str(PRIMITIVE_DESCRIPTOR_SCHEMA_JSON)
        .map_err(|e| BundleError::Schema(format!("schema parse: {}", e)))?;
    let validator = jsonschema::JSONSchema::compile(&schema)
        .map_err(|e| BundleError::Schema(format!("schema compile: {}", e)))?;
    if let Err(errors) = validator.validate(value) {
        let messages: Vec<String> = errors.map(|e| e.to_string()).collect();
        return Err(BundleError::Schema(messages.join("; ")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bundled_manifest_schema_compiles() {
        let schema: serde_json::Value =
            serde_json::from_str(BUNDLE_MANIFEST_SCHEMA_JSON).unwrap();
        let _ = jsonschema::JSONSchema::compile(&schema)
            .expect("bundled manifest schema must compile");
    }

    #[test]
    fn bundled_primitive_schema_compiles() {
        let schema: serde_json::Value =
            serde_json::from_str(PRIMITIVE_DESCRIPTOR_SCHEMA_JSON).unwrap();
        let _ = jsonschema::JSONSchema::compile(&schema)
            .expect("bundled primitive schema must compile");
    }

    #[test]
    fn validates_minimal_attack_manifest() {
        let m = json!({
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
        });
        validate_manifest_json(&m).expect("minimal attack manifest must validate");
    }

    #[test]
    fn rejects_missing_required_field() {
        let m = json!({
            "shape": "v1.0",
            // corpus_id missing
            "attack_id": "atk_test_00000001",
        });
        let err = validate_manifest_json(&m).unwrap_err();
        assert!(format!("{}", err).contains("corpus_id"));
    }

    #[test]
    fn rejects_invalid_enum_value() {
        let m = json!({
            "shape": "v1.0",
            "corpus_id": "crp_test",
            "attack_id": "atk_test",
            "family_id": "not_a_family",
            "primitive_id": "x",
            "posture": "saturating",
            "ground_truth_label": "attack",
            "chain": "sui",
            "run_tag": "x",
            "target_env": "x",
            "started_at": "2026-04-25T10:14:30Z",
            "ended_at":   "2026-04-25T10:15:30Z",
            "provenance": {
                "traffic_source": "reproducer-attack",
                "fidelity_class": "lab",
                "target_authorisation": "self-owned"
            }
        });
        let err = validate_manifest_json(&m).unwrap_err();
        assert!(format!("{}", err).contains("not_a_family") || format!("{}", err).contains("enum"));
    }

    #[test]
    fn validates_minimal_primitive_descriptor() {
        let d = json!({
            "primitive_id": "F10_multi_get_objects_amp",
            "chain": "sui",
            "class_label": "response-amp",
            "default_ground_truth": "attack",
            "supported_postures": ["saturating", "low-volume"],
            "description": "Multi-get-objects response amplification.",
            "reproducer_path": "chains/sui/findings/F10/reproducer.py",
            "requires_lab": "localnet-sui-multinode4"
        });
        validate_primitive_json(&d).expect("minimal primitive descriptor must validate");
    }
}
