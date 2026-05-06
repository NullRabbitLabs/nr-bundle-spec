// SPDX-License-Identifier: MIT
//! Dump every parquet schema as JSON for cross-language consistency
//! checking against the Python reference parser.
//!
//! Used by `tools/compare_arrow_schemas.py` in the spec repo's
//! CI to detect drift between the two languages' schema definitions.

use bundle_spec::{
    app_ts_schema, host_ts_schema, protocol_ts_schema, responses_schema, vectors_schema,
};
use serde_json::{json, Map, Value};

fn schema_to_json(schema: arrow_schema::Schema) -> Value {
    let fields: Vec<Value> = schema
        .fields()
        .iter()
        .map(|f| {
            json!({
                "name": f.name(),
                "type": format!("{}", f.data_type()),
                "nullable": f.is_nullable(),
            })
        })
        .collect();
    Value::Array(fields)
}

fn main() {
    let mut out = Map::new();
    out.insert("host".to_string(), schema_to_json(host_ts_schema()));
    out.insert("app".to_string(), schema_to_json(app_ts_schema()));
    out.insert("protocol".to_string(), schema_to_json(protocol_ts_schema()));
    out.insert("responses".to_string(), schema_to_json(responses_schema()));
    out.insert("vectors".to_string(), schema_to_json(vectors_schema()));

    let j = serde_json::to_string(&Value::Object(out)).expect("serialise");
    println!("{}", j);
}
