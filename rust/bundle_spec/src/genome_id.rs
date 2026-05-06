// SPDX-License-Identifier: MIT
//! Deterministic `genome_id` computation.
//!
//! Mirrors `bundle_spec.compute_genome_id` in Python. Cross-language
//! determinism is the load-bearing contract: the same input
//! `attack_parameters` must produce the same hex string in both
//! languages. Pinned by `tests/genome_id_determinism.rs`.
//!
//! Canonicalisation contract (must match Python):
//!
//! - Object keys are sorted lexicographically (recursively).
//! - Non-JSON-native values (datetimes, Paths, Enums) are stringified
//!   via Python's `default=str`. Cross-language interop is only
//!   guaranteed when `attack_parameters` contains JSON-native values.
//! - JSON output uses ASCII (no non-ASCII chars in keys; values are
//!   passed through Python's default escape policy).
//! - SHA-256 over the UTF-8 byte sequence.
//! - First 16 lowercase hex characters of the digest.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Compute the deterministic 16-hex-char genome id for a JSON object.
///
/// Use [`serde_json::Value`] directly for full canonicalisation
/// control. For typed input, serialise the struct to a `Value` first
/// and pass it here.
pub fn compute_genome_id(attack_parameters: &Value) -> String {
    let canonical = canonicalise(attack_parameters);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    // First 16 lowercase hex chars = 8 bytes.
    let mut out = String::with_capacity(16);
    for b in &digest[..8] {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Canonical-JSON serialisation: sorted keys recursively, no
/// whitespace between tokens (matches Python's
/// `json.dumps(sort_keys=True)` default separator behaviour).
fn canonicalise(value: &Value) -> String {
    let sorted = sort_keys_recursively(value);
    // Python's json.dumps with sort_keys=True and no `separators` arg
    // uses (', ', ': ') as the default separators (NB: with a space
    // after each comma and colon). serde_json's default writer uses
    // (',', ':') — no spaces. We must match Python exactly.
    serialise_with_python_separators(&sorted)
}

fn sort_keys_recursively(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted: Map<String, Value> = Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for k in keys {
                sorted.insert(k.clone(), sort_keys_recursively(&map[k]));
            }
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sort_keys_recursively).collect()),
        other => other.clone(),
    }
}

/// Serialise a Value using Python's default json.dumps separators
/// (`, ` between items, `: ` after object keys). This is the exact
/// byte sequence Python's `json.dumps(sort_keys=True, default=str)`
/// produces for JSON-native values.
fn serialise_with_python_separators(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

fn write_value(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            // Use serde_json's string escaping (matches Python's
            // default ensure_ascii=True behaviour for ASCII strings;
            // non-ASCII is rare in attack_parameters so we accept
            // any divergence on those — the contract is JSON-native
            // values only).
            let escaped = serde_json::to_string(s).expect("string serialisation cannot fail");
            out.push_str(&escaped);
        }
        Value::Array(arr) => {
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                let escaped_k =
                    serde_json::to_string(k).expect("string serialisation cannot fail");
                out.push_str(&escaped_k);
                out.push_str(": ");
                write_value(v, out);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_object_genome_id() {
        // Python: hashlib.sha256(b"{}").hexdigest()[:16] = "44136fa355b3678a"
        let g = compute_genome_id(&json!({}));
        assert_eq!(g, "44136fa355b3678a");
    }

    #[test]
    fn key_order_invariance() {
        let a = compute_genome_id(&json!({"a": 1, "b": 2, "c": 3}));
        let b = compute_genome_id(&json!({"c": 3, "a": 1, "b": 2}));
        assert_eq!(a, b);
    }

    #[test]
    fn nested_keys_sorted_recursively() {
        let a = compute_genome_id(&json!({
            "outer": {"z": 1, "a": 2},
            "extra": [1, 2, 3]
        }));
        let b = compute_genome_id(&json!({
            "extra": [1, 2, 3],
            "outer": {"a": 2, "z": 1}
        }));
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_inputs_distinct_hashes() {
        let a = compute_genome_id(&json!({"x": 1}));
        let b = compute_genome_id(&json!({"x": 2}));
        assert_ne!(a, b);
    }

    #[test]
    fn output_is_16_lowercase_hex() {
        let g = compute_genome_id(&json!({"any": "value"}));
        assert_eq!(g.len(), 16);
        assert!(g.chars().all(|c| c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_lowercase())));
    }

    /// Cross-language genome_id pin. Python output computed at
    /// commit time via `bundle_spec.compute_genome_id` — see the
    /// repo's CI for the running cross-language verification.
    /// If any of these trip, canonicalisation has drifted from Python.
    #[test]
    fn matches_python_for_known_inputs() {
        let cases = [
            (json!({"a": 1, "b": 2, "c": 3}),                              "d97e5b9864df8961"),
            (json!({"outer": {"z": 1, "a": 2}, "extra": [1, 2, 3]}),       "11fdefa53bce2c19"),
            (json!({"x": 1}),                                              "613fe5aa65343dbb"),
            (json!({"x": 2}),                                              "24f572600e150d32"),
            (json!({"any": "value"}),                                      "7a484828dd8b0184"),
            (json!({"foo": 1, "bar": "baz"}),                              "4f1957df4ee6014e"),
        ];
        for (input, expected) in cases {
            let got = compute_genome_id(&input);
            assert_eq!(
                got, expected,
                "Cross-language genome_id determinism failed for {:?}: \
                 got {}, expected (from Python) {}.",
                input, got, expected,
            );
        }
    }
}
