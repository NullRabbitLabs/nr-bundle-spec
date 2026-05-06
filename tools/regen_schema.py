#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regenerate JSON Schema artefacts from the canonical Pydantic models.

Run after any change to ``python/bundle_spec/{bundle_v1,primitive_v1}.py``
that affects the schema. Commit the resulting JSON files alongside
the Python change. CI runs this script and diffs against the
committed schema files; any drift fails the build.

Usage::

    python tools/regen_schema.py

Outputs::

    schema/bundle_v1.schema.json
    schema/primitive_v1.schema.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Ensure the local crate is importable when running from the repo root.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "python"))

from bundle_spec import BundleManifest, PrimitiveDescriptor  # noqa: E402

SCHEMA_DIR = REPO_ROOT / "schema"


def _format_json(obj: dict) -> str:
    """Stable formatter — sorted keys, 2-space indent, trailing newline.

    Pinned formatter so the committed file has zero whitespace
    drift across regenerations on different machines.
    """
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def regenerate() -> None:
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    bundle = BundleManifest.model_json_schema(mode="serialization")
    primitive = PrimitiveDescriptor.model_json_schema(mode="serialization")

    bundle_path = SCHEMA_DIR / "bundle_v1.schema.json"
    primitive_path = SCHEMA_DIR / "primitive_v1.schema.json"

    bundle_path.write_text(_format_json(bundle))
    primitive_path.write_text(_format_json(primitive))

    # Friendly path display: prefer relative to REPO_ROOT when the
    # output is inside the repo (the common case); fall back to the
    # absolute path when callers redirect SCHEMA_DIR elsewhere (e.g.
    # tests writing to a tmp dir).
    def _friendly(p: Path) -> str:
        try:
            return str(p.relative_to(REPO_ROOT))
        except ValueError:
            return str(p)

    print(f"wrote {_friendly(bundle_path)}")
    print(f"wrote {_friendly(primitive_path)}")


if __name__ == "__main__":
    regenerate()
