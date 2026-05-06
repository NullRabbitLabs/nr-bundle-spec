// SPDX-License-Identifier: MIT
//! Primitive descriptor — declarative spec for an attack primitive.
//!
//! Mirrors `python/bundle_spec/primitive_v1.py`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::errors::BundleError;
use crate::manifest::{GroundTruthLabel, Posture};

/// Tunable-parameter kind. Mirrors Pydantic's
/// `Literal["int", "float", "str", "bool", "enum"]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParameterKind {
    Int,
    Float,
    Str,
    Bool,
    Enum,
}

/// Mutator-hint scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MutatorScale {
    Linear,
    Log,
    Discrete,
}

/// One tunable parameter on a primitive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterSpec {
    pub name: String,
    pub kind: ParameterKind,
    #[serde(default)]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choices: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutator_scale: Option<MutatorScale>,
    #[serde(default = "default_mutator_weight")]
    pub mutator_weight: f64,
}

fn default_mutator_weight() -> f64 {
    1.0
}

impl ParameterSpec {
    /// Validate cross-field rules: `mutator_weight >= 0`,
    /// `choices` non-empty if provided.
    pub fn validate(&self) -> Result<(), BundleError> {
        if self.mutator_weight < 0.0 {
            return Err(BundleError::Contract("mutator_weight must be >= 0".into()));
        }
        if let Some(choices) = &self.choices {
            if choices.is_empty() {
                return Err(BundleError::Contract(
                    "choices, if provided, must be non-empty".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Declarative spec for one attack primitive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrimitiveDescriptor {
    pub primitive_id: String,
    pub chain: String,
    pub class_label: String,
    pub default_ground_truth: GroundTruthLabel,
    pub supported_postures: Vec<Posture>,
    pub description: String,
    pub reproducer_path: String,
    #[serde(default)]
    pub parameters: Vec<ParameterSpec>,
    pub requires_lab: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_detection_signature: Option<serde_json::Map<String, Value>>,
}

impl PrimitiveDescriptor {
    /// Validate cross-field rules: `supported_postures` non-empty;
    /// each parameter passes its own validate.
    pub fn validate(&self) -> Result<(), BundleError> {
        if self.supported_postures.is_empty() {
            return Err(BundleError::Contract(
                "supported_postures must be non-empty".into(),
            ));
        }
        for p in &self.parameters {
            p.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parameter_kind_round_trip() {
        for (variant, expected) in [
            (ParameterKind::Int, "int"),
            (ParameterKind::Float, "float"),
            (ParameterKind::Str, "str"),
            (ParameterKind::Bool, "bool"),
            (ParameterKind::Enum, "enum"),
        ] {
            assert_eq!(serde_json::to_value(variant).unwrap(), json!(expected));
        }
    }

    #[test]
    fn descriptor_round_trip() {
        let v = json!({
            "primitive_id": "F10_multi_get_objects_amp",
            "chain": "sui",
            "class_label": "response-amp",
            "default_ground_truth": "attack",
            "supported_postures": ["saturating", "low-volume"],
            "description": "Multi-get-objects response amplification.",
            "reproducer_path": "chains/sui/findings/F10/reproducer.py",
            "requires_lab": "localnet-sui-multinode4",
            "parameters": [
                {
                    "name": "concurrent_requests",
                    "kind": "int",
                    "description": "n parallel workers",
                    "min": 1,
                    "max": 256,
                    "mutator_scale": "log",
                    "mutator_weight": 0.5
                }
            ]
        });
        let d: PrimitiveDescriptor = serde_json::from_value(v).unwrap();
        d.validate().unwrap();
        assert_eq!(d.primitive_id, "F10_multi_get_objects_amp");
        assert_eq!(d.parameters.len(), 1);
        assert!(matches!(d.parameters[0].kind, ParameterKind::Int));
    }

    #[test]
    fn rejects_empty_postures() {
        let v = json!({
            "primitive_id": "x", "chain": "sui", "class_label": "y",
            "default_ground_truth": "attack",
            "supported_postures": [],
            "description": "",
            "reproducer_path": "p",
            "requires_lab": "lab"
        });
        let d: PrimitiveDescriptor = serde_json::from_value(v).unwrap();
        let err = d.validate().unwrap_err();
        assert!(format!("{}", err).contains("supported_postures"));
    }

    #[test]
    fn rejects_negative_mutator_weight() {
        let v = json!({
            "primitive_id": "x", "chain": "sui", "class_label": "y",
            "default_ground_truth": "attack",
            "supported_postures": ["saturating"],
            "description": "",
            "reproducer_path": "p",
            "requires_lab": "lab",
            "parameters": [
                {"name": "a", "kind": "float", "mutator_weight": -1.0}
            ]
        });
        let d: PrimitiveDescriptor = serde_json::from_value(v).unwrap();
        let err = d.validate().unwrap_err();
        assert!(format!("{}", err).contains("mutator_weight"));
    }

    #[test]
    fn rejects_empty_choices() {
        let v = json!({
            "primitive_id": "x", "chain": "sui", "class_label": "y",
            "default_ground_truth": "attack",
            "supported_postures": ["saturating"],
            "description": "",
            "reproducer_path": "p",
            "requires_lab": "lab",
            "parameters": [
                {"name": "a", "kind": "enum", "choices": []}
            ]
        });
        let d: PrimitiveDescriptor = serde_json::from_value(v).unwrap();
        let err = d.validate().unwrap_err();
        assert!(format!("{}", err).contains("choices"));
    }
}
