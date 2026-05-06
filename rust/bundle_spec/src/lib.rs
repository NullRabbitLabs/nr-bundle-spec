// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Simon Morley / NullRabbit
//! Bundle v1 — canonical multi-modal capture format for adversarial
//! blockchain validator research.
//!
//! This crate is the reference Rust parser for the format specified
//! at <https://github.com/NullRabbitLabs/nr-bundle-spec>. It mirrors
//! the canonical Pydantic models in the sister Python package
//! `bundle_spec` and produces identical results for every contract:
//! deserialised manifests, validation rules, parquet schemas, and
//! `genome_id` canonicalisation.
//!
//! ## What's a bundle?
//!
//! A *bundle* is one directory containing the complete trace of one
//! attack (or benign) run against a validator: a manifest, a packet
//! capture, and four time-series Parquet modalities (host, app,
//! protocol, responses) all keyed off a monotonic `t_ns` referenced
//! to the manifest's `started_at`.
//!
//! ## Quick start
//!
//! ```no_run
//! use bundle_spec::manifest::BundleManifest;
//!
//! let json = std::fs::read_to_string("crp_abc123/manifest.json").unwrap();
//! let m: BundleManifest = serde_json::from_str(&json).unwrap();
//! m.validate().unwrap();
//! println!("{:?} {} {:?}", m.family_id, m.primitive_id, m.ground_truth_label);
//! ```
//!
//! ## Stability
//!
//! - `0.1.x`: bug-fix-only patches on the current schema.
//! - `0.2.0`: reserved for the upcoming
//!   `provenance.substrate` × `provenance.traffic_origin`
//!   decomposition (additive).
//! - `1.0.0`: deferred to first set of external citations.

pub mod errors;
pub mod genome_id;
pub mod manifest;
pub mod parquet;
pub mod primitive;
pub mod taxonomy;
pub mod validation;

pub use errors::BundleError;
pub use genome_id::compute_genome_id;
pub use manifest::{
    BundleFiles, BundleManifest, FidelityClass, GroundTruthLabel, Posture, Provenance,
    TargetAuthorisation, TrafficSource, BUNDLE_VERSION,
};
pub use parquet::{
    app_ts_schema, host_ts_schema, protocol_ts_schema, responses_schema, vectors_schema,
};
pub use primitive::{ParameterSpec, ParameterKind, MutatorScale, PrimitiveDescriptor};
pub use taxonomy::{family_definitions, FamilyId};
pub use validation::{validate_manifest_json, validate_primitive_json};

/// Crate version, mirroring `python/bundle_spec/__init__.py::__version__`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
