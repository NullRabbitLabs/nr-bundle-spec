// SPDX-License-Identifier: MIT
//! Parquet schemas — Arrow `Schema` constants matching the Python
//! `bundle_spec.bundle_v1` `*_ts_schema()` helpers byte-for-byte.
//!
//! Cross-language consistency is verified by
//! `tools/compare_arrow_schemas.py` in the spec repo, which loads
//! both sides and compares field names, types, and nullability.

use arrow_schema::{DataType, Field, Schema};
use std::sync::Arc;

/// Host telemetry time-series schema. Mirrors Python `host_ts_schema()`.
pub fn host_ts_schema() -> Schema {
    Schema::new(vec![
        Field::new("t_ns", DataType::Int64, false),
        Field::new("pid", DataType::Int32, true),
        Field::new("rss_bytes", DataType::Int64, true),
        Field::new("vms_bytes", DataType::Int64, true),
        Field::new("cpu_pct", DataType::Float32, true),
        Field::new("num_fds", DataType::Int32, true),
        Field::new("num_threads", DataType::Int32, true),
        Field::new("num_connections", DataType::Int32, true),
        Field::new("io_read_bytes", DataType::Int64, true),
        Field::new("io_write_bytes", DataType::Int64, true),
        Field::new("ctx_switches_voluntary", DataType::Int64, true),
        Field::new("ctx_switches_involuntary", DataType::Int64, true),
    ])
}

/// Application-metric scrape time-series. Mirrors `app_ts_schema()`.
pub fn app_ts_schema() -> Schema {
    Schema::new(vec![
        Field::new("t_ns", DataType::Int64, false),
        Field::new("metric_name", DataType::Utf8, false),
        Field::new("labels_json", DataType::Utf8, false),
        Field::new("value", DataType::Float64, false),
    ])
}

/// Protocol / consensus signal time-series.
pub fn protocol_ts_schema() -> Schema {
    Schema::new(vec![
        Field::new("t_ns", DataType::Int64, false),
        Field::new("signal", DataType::Utf8, false),
        Field::new("value", DataType::Float64, true),
        Field::new("value_str", DataType::Utf8, true),
    ])
}

/// Per-request response semantics.
pub fn responses_schema() -> Schema {
    Schema::new(vec![
        Field::new("t_ns", DataType::Int64, false),
        Field::new("endpoint", DataType::Utf8, false),
        Field::new("request_size_bytes", DataType::Int64, true),
        Field::new("response_size_bytes", DataType::Int64, true),
        Field::new("status_code", DataType::Int32, true),
        Field::new("response_class", DataType::Utf8, true),
        Field::new("duration_ns", DataType::Int64, true),
    ])
}

/// Behavioural / fingerprint vector schema (sixth modality slot).
pub fn vectors_schema() -> Schema {
    Schema::new(vec![
        Field::new("t_ns", DataType::Int64, false),
        Field::new("vector_kind", DataType::Utf8, false),
        Field::new("vector_dim", DataType::Int32, false),
        Field::new(
            "vector_data",
            DataType::List(Arc::new(Field::new("item", DataType::Float32, true))),
            false,
        ),
        Field::new("source_id", DataType::Utf8, false),
        Field::new("metadata_json", DataType::Utf8, true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin: every modality has `t_ns: int64 (nullable=false)` as the
    /// first field. Cross-language equivalent of Python's
    /// `test_schema_has_t_ns_int64_nonnull_first`.
    #[test]
    fn every_schema_starts_with_t_ns_int64_nonnull() {
        for s in [
            host_ts_schema(),
            app_ts_schema(),
            protocol_ts_schema(),
            responses_schema(),
            vectors_schema(),
        ] {
            let f0 = s.field(0);
            assert_eq!(f0.name(), "t_ns");
            assert_eq!(f0.data_type(), &DataType::Int64);
            assert!(!f0.is_nullable());
        }
    }

    #[test]
    fn host_ts_field_count_pinned() {
        assert_eq!(host_ts_schema().fields().len(), 12);
    }

    #[test]
    fn app_ts_field_count_pinned() {
        assert_eq!(app_ts_schema().fields().len(), 4);
    }

    #[test]
    fn protocol_ts_field_count_pinned() {
        assert_eq!(protocol_ts_schema().fields().len(), 4);
    }

    #[test]
    fn responses_field_count_pinned() {
        assert_eq!(responses_schema().fields().len(), 7);
    }

    #[test]
    fn vectors_field_count_pinned() {
        assert_eq!(vectors_schema().fields().len(), 6);
    }

    #[test]
    fn responses_request_size_bytes_is_int64_nullable() {
        let s = responses_schema();
        let f = s.field_with_name("request_size_bytes").unwrap();
        assert_eq!(f.data_type(), &DataType::Int64);
        assert!(f.is_nullable());
    }

    #[test]
    fn vectors_data_is_list_of_float32() {
        let s = vectors_schema();
        let f = s.field_with_name("vector_data").unwrap();
        match f.data_type() {
            DataType::List(inner) => assert_eq!(inner.data_type(), &DataType::Float32),
            other => panic!("expected List<Float32>, got {:?}", other),
        }
    }
}
