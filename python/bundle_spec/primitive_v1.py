# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Simon Morley / NullRabbit
"""Primitive descriptor v1 — the declarative spec for an attack primitive.

One ``PrimitiveDescriptor`` lives per primitive in a producer's
harness (e.g. ``F10_multi_get_objects_amp``,
``MC_redis_historical-cve``, ``D01_consensus_backpressure``). A
parameter-mutation pipeline reads these to know which parameters it's
allowed to perturb and within what bounds — they are the *safety
rails* around generation.

Descriptors are source-of-truth in the producer's harness; downstream
consumers (training, eval) read them via whatever sync mechanism the
producer chooses (broadcast, shared registry, git submodule, ...).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from bundle_spec.bundle_v1 import GroundTruthLabel, Posture


class ParameterSpec(BaseModel):
    """One tunable parameter on a primitive."""

    model_config = ConfigDict(extra="forbid")

    name: str
    kind: Literal["int", "float", "str", "bool", "enum"]
    description: str = ""
    default: Any = None
    # Numeric bounds (int/float only). Inclusive on both sides.
    min: float | None = None
    max: float | None = None
    # Enum values (enum/str only).
    choices: list[str] | None = None
    # Mutator hints.
    mutator_scale: Literal["linear", "log", "discrete"] | None = None
    mutator_weight: float = Field(default=1.0, ge=0.0)

    @field_validator("choices")
    @classmethod
    def _choices_sanity(cls, v: list[str] | None, info: Any) -> list[str] | None:
        if v is not None and len(v) == 0:
            raise ValueError("choices, if provided, must be non-empty")
        return v


class PrimitiveDescriptor(BaseModel):
    """Declarative spec for one attack primitive."""

    model_config = ConfigDict(extra="forbid")

    primitive_id: str = Field(description="Canonical id, e.g. 'F10_multi_get_objects_amp'.")
    chain: str = Field(description="'sui' | 'solana' | 'cosmos' | 'ethereum' | 'cross-chain'.")
    class_label: str = Field(
        description="Pattern class: 'response-amp', 'async-wedge', 'filter-miss-scan', "
        "'subscription-leak', 'admin-noauth', 'state-sync-flood', 'misconfig-service', "
        "'reconnaissance', ..."
    )
    default_ground_truth: GroundTruthLabel
    supported_postures: list[Posture]

    description: str
    reproducer_path: str = Field(
        description="Repo-relative path to the reproducer script in the harness repo."
    )

    parameters: list[ParameterSpec] = Field(default_factory=list)

    # Runtime hints — used by the scheduler to pick a target_env.
    requires_lab: str = Field(
        description="Env name the scheduler must stand up, e.g. "
        "'localnet-sui-multinode4', 'docker-misconfig-compose'."
    )

    # Optional: declared detection signature. Used in corpus-level
    # audits, not consumed by the model.
    expected_detection_signature: dict[str, Any] | None = None

    @field_validator("supported_postures")
    @classmethod
    def _nonempty_postures(cls, v: list[Posture]) -> list[Posture]:
        if not v:
            raise ValueError("supported_postures must be non-empty")
        return v
