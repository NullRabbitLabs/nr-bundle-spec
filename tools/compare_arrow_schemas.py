#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Cross-language Arrow schema consistency check.

Loads each parquet schema from the Python `bundle_spec` package,
runs the equivalent dump from the Rust crate (a small program that
prints each schema's field list as JSON), and asserts byte-for-byte
equivalence on field name, type, and nullability.

If the two languages disagree on any field, the script exits
non-zero with a diff. Run this in CI on every PR.

Usage::

    python tools/compare_arrow_schemas.py

Prerequisites: cargo + rustc must be installed; the Rust crate at
``rust/bundle_spec/`` must build cleanly. The script will invoke
``cargo run -- dump-schemas`` (a small CLI added in the Rust crate
for this purpose) and parse its JSON output.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "python"))

from bundle_spec import (  # noqa: E402
    app_ts_schema,
    host_ts_schema,
    protocol_ts_schema,
    responses_schema,
    vectors_schema,
)


def py_schema_to_normalised(schema) -> list[dict]:
    """Convert pyarrow.Schema → JSON-friendly normalised list."""
    out = []
    for f in schema:
        out.append({
            "name": f.name,
            "type": str(f.type),
            "nullable": f.nullable,
        })
    return out


# pyarrow and arrow-rs use different display string formats. Both
# sides are normalised to a canonical "Tag(inner)" form ignoring
# cosmetic differences (whitespace, field-attribute clutter).
PRIMITIVE_NORMALISERS = {
    # pyarrow forms (left of pipe) → canonical (right of pipe)
    "int8": "Int8",
    "int16": "Int16",
    "int32": "Int32",
    "int64": "Int64",
    "uint8": "UInt8",
    "uint16": "UInt16",
    "uint32": "UInt32",
    "uint64": "UInt64",
    "float": "Float32",     # pyarrow "float" = float32
    "halffloat": "Float16",
    "double": "Float64",    # pyarrow "double" = float64
    "string": "Utf8",
    "binary": "Binary",
    "bool": "Boolean",
    # arrow-rs forms (already canonical)
    "Int8": "Int8", "Int16": "Int16", "Int32": "Int32", "Int64": "Int64",
    "UInt8": "UInt8", "UInt16": "UInt16", "UInt32": "UInt32", "UInt64": "UInt64",
    "Float16": "Float16", "Float32": "Float32", "Float64": "Float64",
    "Utf8": "Utf8", "Binary": "Binary", "Boolean": "Boolean",
}


def normalise_type(t: str) -> str:
    """Canonicalise a pyarrow / arrow-rs type display to a shared form.

    Handles primitive types via the lookup table; for `list<...>` /
    `List(...)` types extracts the inner element type and recurses.
    """
    t = t.strip()
    # arrow-rs's "List(Field { name: ..., data_type: T, ... })" format —
    # extract the inner data_type.
    if t.startswith("List(Field {"):
        # Look for "data_type: T," (comma terminates the field)
        marker = "data_type: "
        i = t.find(marker)
        if i != -1:
            inner_start = i + len(marker)
            # Find the matching comma at the same nesting level. For
            # primitives this is just the next comma.
            comma = t.find(",", inner_start)
            inner = t[inner_start:comma].strip() if comma != -1 else t[inner_start:].strip()
            return f"List({normalise_type(inner)})"
    # arrow-rs "List(T)" simple form
    if t.startswith("List(") and t.endswith(")"):
        inner = t[5:-1].strip()
        return f"List({normalise_type(inner)})"
    # pyarrow "list<item: T>" form
    if t.startswith("list<") and t.endswith(">"):
        # Strip "list<" / ">", then drop optional "item: " prefix.
        inner = t[5:-1].strip()
        if ":" in inner:
            inner = inner.split(":", 1)[1].strip()
        return f"List({normalise_type(inner)})"
    return PRIMITIVE_NORMALISERS.get(t, t)


def _run_rust_dump() -> dict[str, list[dict]]:
    """Invoke the Rust dump-schemas CLI and parse JSON output."""
    result = subprocess.run(
        ["cargo", "run", "--quiet", "--example", "dump_schemas"],
        cwd=REPO_ROOT / "rust" / "bundle_spec",
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def main() -> int:
    py_schemas = {
        "host": py_schema_to_normalised(host_ts_schema()),
        "app": py_schema_to_normalised(app_ts_schema()),
        "protocol": py_schema_to_normalised(protocol_ts_schema()),
        "responses": py_schema_to_normalised(responses_schema()),
        "vectors": py_schema_to_normalised(vectors_schema()),
    }
    rs_schemas = _run_rust_dump()

    failures = []
    for name, py_fields in py_schemas.items():
        rs_fields = rs_schemas.get(name)
        if rs_fields is None:
            failures.append(f"Rust missing schema {name!r}")
            continue
        if len(py_fields) != len(rs_fields):
            failures.append(
                f"{name}: field-count mismatch — "
                f"Python {len(py_fields)}, Rust {len(rs_fields)}"
            )
            continue
        for i, (pf, rf) in enumerate(zip(py_fields, rs_fields)):
            if pf["name"] != rf["name"]:
                failures.append(
                    f"{name}[{i}]: name mismatch — "
                    f"Python {pf['name']!r}, Rust {rf['name']!r}"
                )
            py_type = normalise_type(pf["type"])
            rs_type = normalise_type(rf["type"])
            if py_type != rs_type:
                failures.append(
                    f"{name}[{i}] '{pf['name']}': type mismatch — "
                    f"Python {pf['type']!r} → {py_type!r}, "
                    f"Rust {rf['type']!r} → {rs_type!r}"
                )
            if pf["nullable"] != rf["nullable"]:
                failures.append(
                    f"{name}[{i}] '{pf['name']}': nullability mismatch — "
                    f"Python {pf['nullable']}, Rust {rf['nullable']}"
                )

    if failures:
        print("CROSS-LANGUAGE ARROW SCHEMA DRIFT:", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        return 1

    total_fields = sum(len(s) for s in py_schemas.values())
    print(f"OK {len(py_schemas)} schemas, {total_fields} fields, no drift.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
