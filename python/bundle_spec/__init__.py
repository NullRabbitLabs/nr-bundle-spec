# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Simon Morley / NullRabbit
"""Bundle v1 — canonical on-disk format for adversarial blockchain
research traces.

A *bundle* is one directory containing the complete trace of one
attack (or benign) run against a validator: a manifest, a packet
capture, and four time-series Parquet modalities (host, app,
protocol, responses) all keyed off a monotonic ``t_ns`` referenced
to the manifest's ``started_at``.

The Pydantic models in this package are the canonical normative
form of the schema. JSON Schema artefacts (under ``schema/`` in the
repo) are generated from these models. A reference Rust parser
lives at ``rust/bundle_spec/``.

Stability:

- v0.1.x: bug-fix-only patches on the current schema.
- v0.2.0: reserved for the upcoming `provenance.substrate` ×
  `provenance.traffic_origin` decomposition (additive).
- v1.0.0: deferred to first set of external citations.

See README.md for the format overview, examples, and adoption notes.
"""

from bundle_spec.bundle_v1 import (
    BUNDLE_VERSION,
    BundleFiles,
    BundleManifest,
    FidelityClass,
    GroundTruthLabel,
    Posture,
    Provenance,
    TargetAuthorisation,
    TrafficSource,
    app_ts_schema,
    compute_genome_id,
    host_ts_schema,
    protocol_ts_schema,
    responses_schema,
    vectors_schema,
)
from bundle_spec.primitive_v1 import (
    ParameterSpec,
    PrimitiveDescriptor,
)
from bundle_spec.taxonomy import FAMILY_DEFINITIONS, FamilyId

__version__ = "0.1.1"

__all__ = [
    "BUNDLE_VERSION",
    "BundleFiles",
    "BundleManifest",
    "FAMILY_DEFINITIONS",
    "FamilyId",
    "FidelityClass",
    "GroundTruthLabel",
    "ParameterSpec",
    "Posture",
    "PrimitiveDescriptor",
    "Provenance",
    "TargetAuthorisation",
    "TrafficSource",
    "__version__",
    "app_ts_schema",
    "compute_genome_id",
    "host_ts_schema",
    "protocol_ts_schema",
    "responses_schema",
    "vectors_schema",
]
