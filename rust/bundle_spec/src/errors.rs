// SPDX-License-Identifier: MIT
//! Error types for the bundle-spec crate.

use thiserror::Error;

/// Errors raised by the bundle-spec parser and validators.
#[derive(Debug, Error)]
pub enum BundleError {
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("manifest contract violation: {0}")]
    Contract(String),

    #[error("schema validation error: {0}")]
    Schema(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
