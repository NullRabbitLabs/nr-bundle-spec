"""Contract tests — lock the v1 bundle + primitive shapes.

These assertions are the load-bearing guarantee to every downstream
consumer (ingestion adapters, mutator, feature extractors, trainers):
if a change breaks any of these tests without a BUNDLE_VERSION bump,
it's a contract break.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pyarrow as pa
import pytest
from pydantic import ValidationError

from bundle_spec import (
    BUNDLE_VERSION,
    BundleFiles,
    BundleManifest,
    FamilyId,
    GroundTruthLabel,
    ParameterSpec,
    Posture,
    PrimitiveDescriptor,
    Provenance,
    TrafficSource,
    app_ts_schema,
    compute_genome_id,
    host_ts_schema,
    protocol_ts_schema,
    responses_schema,
    vectors_schema,
)


def _valid_manifest_kwargs() -> dict:
    now = datetime.now(timezone.utc)
    from bundle_spec import FidelityClass, TargetAuthorisation
    return dict(
        shape="v0.0",
        corpus_id="crp_test_00000001",
        attack_id="atk_test_00000001",
        genome_id="aabbccdd11223344",
        family_id=FamilyId.response_amp,
        primitive_id="sui_F10_multi_get_objects_amp",
        posture=Posture.saturating,
        ground_truth_label=GroundTruthLabel.attack,
        chain="sui",
        run_tag="unit_test",
        target_env="localnet-sui-multinode4",
        started_at=now,
        ended_at=now + timedelta(seconds=10),
        provenance=Provenance(
            traffic_source=TrafficSource.reproducer_attack,
            fidelity_class=FidelityClass.lab,
            target_authorisation=TargetAuthorisation.self_owned,
        ),
    )


class TestBundleManifest:
    def test_minimal_manifest_round_trips(self) -> None:
        m = BundleManifest(**_valid_manifest_kwargs())
        payload = m.model_dump(mode="json")
        restored = BundleManifest.model_validate(payload)
        assert restored.corpus_id == m.corpus_id
        assert restored.bundle_version == BUNDLE_VERSION

    def test_rejects_extra_fields(self) -> None:
        kwargs = _valid_manifest_kwargs() | {"not_a_field": 1}
        with pytest.raises(ValidationError):
            BundleManifest(**kwargs)

    def test_rejects_empty_identity_strings(self) -> None:
        kwargs = _valid_manifest_kwargs() | {"corpus_id": "   "}
        with pytest.raises(ValidationError):
            BundleManifest(**kwargs)

    def test_rejects_backwards_time_window(self) -> None:
        kwargs = _valid_manifest_kwargs()
        kwargs["ended_at"] = kwargs["started_at"] - timedelta(seconds=1)
        with pytest.raises(ValidationError):
            BundleManifest(**kwargs)

    def test_defaults_to_pcap_only_files(self) -> None:
        m = BundleManifest(**_valid_manifest_kwargs())
        assert m.files == BundleFiles(packets_pcap=True)

    def test_posture_and_label_are_controlled_vocab(self) -> None:
        kwargs = _valid_manifest_kwargs() | {"posture": "not-a-posture"}
        with pytest.raises(ValidationError):
            BundleManifest(**kwargs)


class TestTrafficSourceAndProvenance:
    """Step 1a contract: provenance.traffic_source required."""

    def test_traffic_source_required(self) -> None:
        kwargs = _valid_manifest_kwargs()
        # Provenance without traffic_source must fail.
        with pytest.raises(ValidationError):
            Provenance()  # type: ignore[call-arg]

    def test_traffic_source_controlled_vocab(self) -> None:
        with pytest.raises(ValidationError):
            Provenance(traffic_source="not-real")  # type: ignore[arg-type]

    def test_provenance_allows_extras(self) -> None:
        from bundle_spec import FidelityClass, TargetAuthorisation
        p = Provenance(
            traffic_source=TrafficSource.reproducer_attack,
            fidelity_class=FidelityClass.lab,
            target_authorisation=TargetAuthorisation.self_owned,
            tcpdump_returncode=0,  # type: ignore[call-arg]
            node_pid=12345,  # type: ignore[call-arg]
        )
        raw = p.model_dump()
        assert raw["tcpdump_returncode"] == 0
        assert raw["node_pid"] == 12345
        assert raw["traffic_source"] == "reproducer-attack"

    def test_manifest_round_trip_preserves_traffic_source(self) -> None:
        m = BundleManifest(**_valid_manifest_kwargs())
        dumped = m.model_dump(mode="json")
        restored = BundleManifest.model_validate(dumped)
        assert restored.provenance.traffic_source == TrafficSource.reproducer_attack


class TestFidelityClassAndTargetAuthorisation:
    """Step 5.7.2 / 5.7.3 contract tests for the new Provenance
    enums. Step-5.7 final tightening (2026-04-25) removed the
    defaults — both fields are now hard-required. Producers
    populate them natively at manifest construction; legacy
    bundles need backfill via scripts/step5_7_backfill.py."""

    def test_fidelity_class_enum_exact_members(self) -> None:
        from bundle_spec import FidelityClass
        assert {f.value for f in FidelityClass} == {
            "stub", "proxy", "lab", "lab-tls-fronted",
            "production-captured", "production-derived",
        }
        assert len(list(FidelityClass)) == 6

    def test_target_authorisation_enum_exact_members(self) -> None:
        from bundle_spec import TargetAuthorisation
        assert {f.value for f in TargetAuthorisation} == {
            "self-owned", "customer-authorised",
            "public-mainnet-passive", "synthetic",
        }
        assert len(list(TargetAuthorisation)) == 4

    def test_fidelity_class_required_no_default(self) -> None:
        # Strict-tightened 2026-04-25: no default; missing field fails.
        with pytest.raises(ValidationError):
            Provenance(  # type: ignore[call-arg]
                traffic_source=TrafficSource.reproducer_attack,
                target_authorisation="self-owned",  # type: ignore[arg-type]
                # fidelity_class omitted — must fail
            )

    def test_target_authorisation_required_no_default(self) -> None:
        with pytest.raises(ValidationError):
            Provenance(  # type: ignore[call-arg]
                traffic_source=TrafficSource.reproducer_attack,
                fidelity_class="lab",  # type: ignore[arg-type]
                # target_authorisation omitted — must fail
            )

    def test_fidelity_class_controlled_vocab(self) -> None:
        with pytest.raises(ValidationError):
            Provenance(
                traffic_source=TrafficSource.reproducer_attack,
                fidelity_class="not-a-fidelity",  # type: ignore[arg-type]
                target_authorisation="self-owned",  # type: ignore[arg-type]
            )

    def test_target_authorisation_controlled_vocab(self) -> None:
        with pytest.raises(ValidationError):
            Provenance(
                traffic_source=TrafficSource.reproducer_attack,
                fidelity_class="lab",  # type: ignore[arg-type]
                target_authorisation="whatever",  # type: ignore[arg-type]
            )

    def test_customer_authorised_requires_engagement_id(self) -> None:
        from bundle_spec import TargetAuthorisation, FidelityClass
        with pytest.raises(ValidationError):
            Provenance(
                traffic_source=TrafficSource.reproducer_attack,
                fidelity_class=FidelityClass.lab,
                target_authorisation=TargetAuthorisation.customer_authorised,
                # engagement_id omitted — must fail
            )

    def test_customer_authorised_with_engagement_id_ok(self) -> None:
        from bundle_spec import TargetAuthorisation, FidelityClass
        p = Provenance(
            traffic_source=TrafficSource.reproducer_attack,
            target_authorisation=TargetAuthorisation.customer_authorised,
            engagement_id="eng_2026_abc123",
            fidelity_class=FidelityClass.lab,
        )
        assert p.engagement_id == "eng_2026_abc123"

    def test_self_owned_does_not_require_engagement_id(self) -> None:
        from bundle_spec import FidelityClass, TargetAuthorisation
        p = Provenance(
            traffic_source=TrafficSource.reproducer_attack,
            fidelity_class=FidelityClass.lab,
            target_authorisation=TargetAuthorisation.self_owned,
        )
        assert p.engagement_id is None

    def test_manifest_round_trip_preserves_new_fields(self) -> None:
        from bundle_spec import FidelityClass, TargetAuthorisation
        kwargs = _valid_manifest_kwargs()
        kwargs["provenance"] = Provenance(
            traffic_source=TrafficSource.reproducer_attack,
            fidelity_class=FidelityClass.stub,
            target_authorisation=TargetAuthorisation.self_owned,
        )
        m = BundleManifest(**kwargs)
        dumped = m.model_dump(mode="json")
        restored = BundleManifest.model_validate(dumped)
        assert restored.provenance.fidelity_class == FidelityClass.stub
        assert restored.provenance.target_authorisation == TargetAuthorisation.self_owned


class TestPcapPathPreTermination:
    """Step-11 D-020 dec 1 + auditor refinement 2 (2026-05-03):
    Provenance.pcap_path_pre_termination supports dual-vantage
    capture for lab-tls-fronted bundles. Optional, default None,
    Step-11 sweep specs reference this field for the wire pcap
    path."""

    def test_pcap_path_pre_termination_default_none(self) -> None:
        from bundle_spec import FidelityClass, TargetAuthorisation
        p = Provenance(
            traffic_source=TrafficSource.reproducer_attack,
            fidelity_class=FidelityClass.lab,
            target_authorisation=TargetAuthorisation.self_owned,
        )
        assert p.pcap_path_pre_termination is None

    def test_pcap_path_pre_termination_settable(self) -> None:
        from bundle_spec import FidelityClass, TargetAuthorisation
        p = Provenance(
            traffic_source=TrafficSource.reproducer_attack,
            fidelity_class=FidelityClass.lab_tls_fronted,
            target_authorisation=TargetAuthorisation.self_owned,
            pcap_path_pre_termination="pcap_pre_termination.pcap",
        )
        assert p.pcap_path_pre_termination == "pcap_pre_termination.pcap"

    def test_pcap_path_pre_termination_round_trip(self) -> None:
        from bundle_spec import FidelityClass, TargetAuthorisation
        kwargs = _valid_manifest_kwargs()
        kwargs["provenance"] = Provenance(
            traffic_source=TrafficSource.reproducer_attack,
            fidelity_class=FidelityClass.lab_tls_fronted,
            target_authorisation=TargetAuthorisation.self_owned,
            pcap_path_pre_termination="pcap_pre_termination.pcap",
        )
        m = BundleManifest(**kwargs)
        dumped = m.model_dump(mode="json")
        restored = BundleManifest.model_validate(dumped)
        assert restored.provenance.pcap_path_pre_termination == "pcap_pre_termination.pcap"
        assert restored.provenance.fidelity_class == FidelityClass.lab_tls_fronted


class TestProvenanceTooling:
    """Step-W2-gate-1 contract: provenance.tooling is a structured
    dict[str, str] field. Required to be non-empty for
    family_id=reconnaissance bundles (off-the-shelf tooling
    drift changes request shape — version pinning is
    load-bearing). Optional but populate-encouraged for other
    families."""

    def test_tooling_field_default_empty(self) -> None:
        from bundle_spec import FidelityClass, TargetAuthorisation
        p = Provenance(
            traffic_source=TrafficSource.reproducer_attack,
            fidelity_class=FidelityClass.lab,
            target_authorisation=TargetAuthorisation.self_owned,
        )
        assert p.tooling == {}

    def test_tooling_field_accepts_dict(self) -> None:
        from bundle_spec import FidelityClass, TargetAuthorisation
        p = Provenance(
            traffic_source=TrafficSource.reproducer_attack,
            fidelity_class=FidelityClass.lab,
            target_authorisation=TargetAuthorisation.self_owned,
            tooling={"nmap_version": "7.95", "masscan_version": "1.3.2"},
        )
        assert p.tooling == {"nmap_version": "7.95", "masscan_version": "1.3.2"}

    def test_tooling_field_round_trips(self) -> None:
        from bundle_spec import FidelityClass, TargetAuthorisation
        kwargs = _valid_manifest_kwargs()
        kwargs["provenance"] = Provenance(
            traffic_source=TrafficSource.reproducer_attack,
            fidelity_class=FidelityClass.lab,
            target_authorisation=TargetAuthorisation.self_owned,
            tooling={"bbot_version": "2.8.4"},
        )
        m = BundleManifest(**kwargs)
        dumped = m.model_dump(mode="json")
        restored = BundleManifest.model_validate(dumped)
        assert restored.provenance.tooling == {"bbot_version": "2.8.4"}

    def test_reconnaissance_requires_non_empty_tooling(self) -> None:
        """family_id=reconnaissance + empty tooling must raise."""
        from bundle_spec import FidelityClass, TargetAuthorisation
        kwargs = _valid_manifest_kwargs()
        kwargs["family_id"] = FamilyId.reconnaissance
        kwargs["primitive_id"] = "sui_RC_nmap_slow"
        # Provenance with empty tooling — must fail
        kwargs["provenance"] = Provenance(
            traffic_source=TrafficSource.reproducer_attack,
            fidelity_class=FidelityClass.lab,
            target_authorisation=TargetAuthorisation.self_owned,
        )
        with pytest.raises(ValidationError):
            BundleManifest(**kwargs)

    def test_reconnaissance_with_tooling_ok(self) -> None:
        """family_id=reconnaissance + populated tooling must validate."""
        from bundle_spec import FidelityClass, TargetAuthorisation
        kwargs = _valid_manifest_kwargs()
        kwargs["family_id"] = FamilyId.reconnaissance
        kwargs["primitive_id"] = "sui_RC_nmap_slow"
        kwargs["provenance"] = Provenance(
            traffic_source=TrafficSource.reproducer_attack,
            fidelity_class=FidelityClass.lab,
            target_authorisation=TargetAuthorisation.self_owned,
            tooling={"nmap_version": "7.95"},
        )
        m = BundleManifest(**kwargs)
        assert m.provenance.tooling == {"nmap_version": "7.95"}

    def test_non_recon_family_does_not_require_tooling(self) -> None:
        """Other families don't need tooling populated — empty is fine."""
        # Default _valid_manifest_kwargs() has family_id=response_amp
        # and empty tooling. Should still validate.
        m = BundleManifest(**_valid_manifest_kwargs())
        assert m.provenance.tooling == {}


class TestCorpusV1_1SchemaExtensions:
    """corpus_v1.1 schema additions: TrafficSource.reproducer_benign +
    four ``*_normal`` Posture values introduced for the
    ``sui_BENIGN_reproducer_pipeline`` primitive (Gate-2 audit
    remediation, Step-8 V2 design)."""

    def test_traffic_source_includes_reproducer_benign(self) -> None:
        # v1.1 introduced reproducer-benign; v1.3 adds
        # validator-under-load. Both must be present.
        values = {t.value for t in TrafficSource}
        for v in (
            "synthetic-client", "mainnet-organic", "mixed",
            "reproducer-attack", "reproducer-benign",
        ):
            assert v in values

    def test_posture_includes_four_normal_values(self) -> None:
        values = {p.value for p in Posture}
        # Original 8 still present.
        for v in (
            "saturating", "low-volume", "distributed", "mimicry",
            "insider", "validator-compromised", "reconnaissance",
            "historical-cve",
        ):
            assert v in values
        # New v1.1 benign postures.
        for v in (
            "wallet_normal", "indexer_normal",
            "light_client_normal", "mixed_normal",
        ):
            assert v in values

    def test_reproducer_benign_provenance_round_trips(self) -> None:
        from bundle_spec import FidelityClass, TargetAuthorisation
        p = Provenance(
            traffic_source=TrafficSource.reproducer_benign,
            fidelity_class=FidelityClass.lab,
            target_authorisation=TargetAuthorisation.self_owned,
        )
        raw = p.model_dump(mode="json")
        restored = Provenance.model_validate(raw)
        assert restored.traffic_source is TrafficSource.reproducer_benign

    def test_benign_reproducer_pipeline_manifest_validates(self) -> None:
        """End-to-end: a manifest matching the design spec
        (sui_BENIGN_reproducer_pipeline, posture=wallet_normal,
        traffic_source=reproducer-benign, label=benign,
        family=benign) round-trips."""
        from bundle_spec import FidelityClass, TargetAuthorisation
        kwargs = _valid_manifest_kwargs() | {
            "primitive_id": "sui_BENIGN_reproducer_pipeline",
            "family_id": FamilyId.benign,
            "ground_truth_label": GroundTruthLabel.benign,
            "posture": Posture.wallet_normal,
            "genome_id": None,  # benign — genome_id optional
            "provenance": Provenance(
                traffic_source=TrafficSource.reproducer_benign,
                fidelity_class=FidelityClass.lab,
                target_authorisation=TargetAuthorisation.self_owned,
            ),
        }
        m = BundleManifest(**kwargs)
        dumped = m.model_dump(mode="json")
        restored = BundleManifest.model_validate(dumped)
        assert restored.posture is Posture.wallet_normal
        assert restored.provenance.traffic_source is TrafficSource.reproducer_benign
        assert restored.family_id is FamilyId.benign
        assert restored.ground_truth_label is GroundTruthLabel.benign

    def test_all_four_normal_postures_validate(self) -> None:
        """Each of the four ``*_normal`` postures accepts a benign
        reproducer-pipeline manifest."""
        from bundle_spec import FidelityClass, TargetAuthorisation
        for posture in (
            Posture.wallet_normal, Posture.indexer_normal,
            Posture.light_client_normal, Posture.mixed_normal,
        ):
            kwargs = _valid_manifest_kwargs() | {
                "primitive_id": "sui_BENIGN_reproducer_pipeline",
                "family_id": FamilyId.benign,
                "ground_truth_label": GroundTruthLabel.benign,
                "posture": posture,
                "genome_id": None,
                "provenance": Provenance(
                    traffic_source=TrafficSource.reproducer_benign,
                    fidelity_class=FidelityClass.lab,
                    target_authorisation=TargetAuthorisation.self_owned,
                ),
            }
            m = BundleManifest(**kwargs)
            assert m.posture is posture

    def test_unknown_traffic_source_still_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Provenance(traffic_source="reproducer-something-new")  # type: ignore[arg-type]

    def test_unknown_posture_still_rejected(self) -> None:
        kwargs = _valid_manifest_kwargs() | {"posture": "invalid_normal"}
        with pytest.raises(ValidationError):
            BundleManifest(**kwargs)


class TestCorpusV1_3SchemaExtensions:
    """corpus_v1.3 schema additions: TrafficSource.validator_under_load
    + four high-load Posture values introduced for the
    sui_BENIGN_validator_under_load primitive (V4 design option II
    remediation; V3-actual single-feature reds host.cpu_mean +
    pcap.mean_packet_size closure)."""

    def test_traffic_source_includes_validator_under_load(self) -> None:
        values = {t.value for t in TrafficSource}
        assert "validator-under-load" in values
        # 6 strata: synthetic-client, mainnet-organic, mixed,
        # reproducer-attack, reproducer-benign, validator-under-load.
        assert len(list(TrafficSource)) == 6

    def test_posture_includes_four_high_load_values(self) -> None:
        values = {p.value for p in Posture}
        # 12 prior values still present.
        for v in (
            "saturating", "low-volume", "distributed", "mimicry",
            "insider", "validator-compromised", "reconnaissance",
            "historical-cve",
            "wallet_normal", "indexer_normal",
            "light_client_normal", "mixed_normal",
        ):
            assert v in values
        # New v1.3 high-load benign postures.
        for v in (
            "dex_swap_burst", "nft_mint_storm",
            "indexer_backfill", "mixed_high_load",
        ):
            assert v in values
        assert len(list(Posture)) == 16

    def test_validator_under_load_provenance_round_trips(self) -> None:
        from bundle_spec import FidelityClass, TargetAuthorisation
        p = Provenance(
            traffic_source=TrafficSource.validator_under_load,
            fidelity_class=FidelityClass.lab,
            target_authorisation=TargetAuthorisation.self_owned,
        )
        raw = p.model_dump(mode="json")
        restored = Provenance.model_validate(raw)
        assert restored.traffic_source is TrafficSource.validator_under_load

    def test_validator_under_load_manifest_validates(self) -> None:
        """End-to-end: a manifest matching the v1.3 design spec
        (sui_BENIGN_validator_under_load, posture=dex_swap_burst,
        traffic_source=validator-under-load, label=benign,
        family=benign) round-trips."""
        from bundle_spec import FidelityClass, TargetAuthorisation
        kwargs = _valid_manifest_kwargs() | {
            "primitive_id": "sui_BENIGN_validator_under_load",
            "family_id": FamilyId.benign,
            "ground_truth_label": GroundTruthLabel.benign,
            "posture": Posture.dex_swap_burst,
            "genome_id": None,
            "provenance": Provenance(
                traffic_source=TrafficSource.validator_under_load,
                fidelity_class=FidelityClass.lab,
                target_authorisation=TargetAuthorisation.self_owned,
            ),
        }
        m = BundleManifest(**kwargs)
        dumped = m.model_dump(mode="json")
        restored = BundleManifest.model_validate(dumped)
        assert restored.posture is Posture.dex_swap_burst
        assert restored.provenance.traffic_source is TrafficSource.validator_under_load

    def test_all_four_high_load_postures_validate(self) -> None:
        """Each of the four v1.3 high-load postures accepts a benign
        validator-under-load manifest."""
        from bundle_spec import FidelityClass, TargetAuthorisation
        for posture in (
            Posture.dex_swap_burst, Posture.nft_mint_storm,
            Posture.indexer_backfill, Posture.mixed_high_load,
        ):
            kwargs = _valid_manifest_kwargs() | {
                "primitive_id": "sui_BENIGN_validator_under_load",
                "family_id": FamilyId.benign,
                "ground_truth_label": GroundTruthLabel.benign,
                "posture": posture,
                "genome_id": None,
                "provenance": Provenance(
                    traffic_source=TrafficSource.validator_under_load,
                    fidelity_class=FidelityClass.lab,
                    target_authorisation=TargetAuthorisation.self_owned,
                ),
            }
            m = BundleManifest(**kwargs)
            assert m.posture is posture


class TestGenomeId:
    """Step 1b contract: genome_id helper + attack-requires-genome_id."""

    def test_compute_genome_id_is_deterministic(self) -> None:
        params = {"n_ids": 50, "workers": 8, "posture": "saturating"}
        assert compute_genome_id(params) == compute_genome_id(dict(params))

    def test_compute_genome_id_is_key_order_invariant(self) -> None:
        a = compute_genome_id({"n_ids": 50, "workers": 8})
        b = compute_genome_id({"workers": 8, "n_ids": 50})
        assert a == b

    def test_compute_genome_id_differs_on_value_change(self) -> None:
        a = compute_genome_id({"n_ids": 50})
        b = compute_genome_id({"n_ids": 51})
        assert a != b

    def test_compute_genome_id_length_is_16(self) -> None:
        assert len(compute_genome_id({})) == 16

    def test_attack_requires_genome_id(self) -> None:
        kwargs = _valid_manifest_kwargs() | {"genome_id": None}
        with pytest.raises(ValidationError, match="genome_id is required"):
            BundleManifest(**kwargs)

    def test_benign_allows_null_genome_id(self) -> None:
        from bundle_spec import FidelityClass, TargetAuthorisation
        kwargs = _valid_manifest_kwargs() | {
            "genome_id": None,
            "ground_truth_label": GroundTruthLabel.benign,
            "family_id": FamilyId.benign,
            "provenance": Provenance(
                traffic_source=TrafficSource.synthetic_client,
                fidelity_class=FidelityClass.lab,
                target_authorisation=TargetAuthorisation.self_owned,
            ),
        }
        m = BundleManifest(**kwargs)
        assert m.genome_id is None


class TestFamilyTaxonomy:
    """Step 1c contract: family_id required, must be in enumeration."""

    def test_family_id_required(self) -> None:
        kwargs = _valid_manifest_kwargs()
        del kwargs["family_id"]
        with pytest.raises(ValidationError):
            BundleManifest(**kwargs)

    def test_family_id_controlled_vocab(self) -> None:
        kwargs = _valid_manifest_kwargs() | {"family_id": "not_a_family"}
        with pytest.raises(ValidationError):
            BundleManifest(**kwargs)

    def test_family_id_enum_is_exactly_11(self) -> None:
        # Contract test: if this number changes, docs/TAXONOMY.md needs
        # updating together. A silent expansion would be a research-
        # scope claim without validation. Locked composition:
        # response_amp, compute_amp, memory_amp, connection_exhaustion,
        # consensus_abuse, gossip_abuse, auth_bypass, rate_limiter_bypass,
        # service_misconfig, reconnaissance, benign.
        # 12 attack + 1 benign. `reconnaissance` was added in Step 5.7
        # as an intentionally unpopulated scaffold — see BACKLOG.md.
        # `subscription_cpu_amp` + `state_import_abuse` promoted in v0.2.0.
        assert len(list(FamilyId)) == 13
        assert {f.value for f in FamilyId} == {
            "response_amp", "compute_amp", "memory_amp",
            "connection_exhaustion", "consensus_abuse", "gossip_abuse",
            "auth_bypass", "rate_limiter_bypass", "service_misconfig",
            "reconnaissance", "subscription_cpu_amp", "state_import_abuse",
            "benign",
        }

    def test_every_family_has_a_definition(self) -> None:
        from bundle_spec import FAMILY_DEFINITIONS

        for f in FamilyId:
            assert f in FAMILY_DEFINITIONS
            assert FAMILY_DEFINITIONS[f].strip(), f"{f} has empty definition"


class TestTimeSeriesSchemas:
    @pytest.mark.parametrize(
        "schema_fn",
        [host_ts_schema, app_ts_schema, protocol_ts_schema,
         responses_schema, vectors_schema],
    )
    def test_schema_has_t_ns_int64_nonnull_first(self, schema_fn) -> None:
        schema = schema_fn()
        first = schema.field(0)
        assert first.name == "t_ns"
        assert first.type == pa.int64()
        assert not first.nullable

    def test_empty_table_round_trips_through_parquet(self, tmp_path) -> None:
        schema = host_ts_schema()
        empty = pa.Table.from_pylist([], schema=schema)
        path = tmp_path / "host.parquet"
        import pyarrow.parquet as pq

        pq.write_table(empty, path)
        back = pq.read_table(path)
        assert back.schema == schema
        assert back.num_rows == 0

    def test_app_ts_wide_schema_uses_json_labels(self) -> None:
        schema = app_ts_schema()
        assert schema.field("labels_json").type == pa.string()
        # A sample row round-trips.
        row = {
            "t_ns": 123_456,
            "metric_name": "process_resident_memory_bytes",
            "labels_json": json.dumps({"instance": "v0:9184"}),
            "value": 42.0,
        }
        tbl = pa.Table.from_pylist([row], schema=schema)
        assert tbl.num_rows == 1

    def test_vectors_schema_row_round_trips(self, tmp_path) -> None:
        schema = vectors_schema()
        row = {
            "t_ns": 987_654_321,
            "vector_kind": "trs_timing_fingerprint",
            "vector_dim": 4,
            "vector_data": [1.0, 2.5, -0.5, 3.25],
            "source_id": "limpet_trs_v0.4.1",
            "metadata_json": json.dumps({"capture_window_ms": 500}),
        }
        tbl = pa.Table.from_pylist([row], schema=schema)
        assert tbl.num_rows == 1
        import pyarrow.parquet as pq
        path = tmp_path / "vectors.parquet"
        pq.write_table(tbl, path)
        back = pq.read_table(path)
        assert back.schema == schema
        assert back.num_rows == 1
        row_back = back.to_pylist()[0]
        assert row_back["vector_kind"] == "trs_timing_fingerprint"
        assert row_back["vector_dim"] == 4
        assert row_back["vector_data"] == [1.0, 2.5, -0.5, 3.25]

    def test_bundle_files_has_vectors_parquet_slot(self) -> None:
        bf = BundleFiles()
        assert bf.vectors_parquet is False
        bf2 = BundleFiles(vectors_parquet=True)
        assert bf2.vectors_parquet is True


class TestPrimitiveDescriptor:
    def _valid(self) -> dict:
        return dict(
            primitive_id="sui_F10_multi_get_objects_amp",
            chain="sui",
            class_label="response-amp",
            default_ground_truth=GroundTruthLabel.attack,
            supported_postures=[Posture.saturating, Posture.low_volume],
            description="multiGetObjects with showBcs=true on framework packages.",
            reproducer_path="chains/sui/findings/F10/reproducer.py",
            requires_lab="localnet-sui-multinode4",
            parameters=[
                ParameterSpec(
                    name="n_ids",
                    kind="int",
                    default=50,
                    min=1,
                    max=50,
                    mutator_scale="linear",
                ),
                ParameterSpec(
                    name="posture",
                    kind="enum",
                    choices=["saturating", "low-volume"],
                    default="saturating",
                ),
            ],
        )

    def test_roundtrip(self) -> None:
        d = PrimitiveDescriptor(**self._valid())
        restored = PrimitiveDescriptor.model_validate(d.model_dump())
        assert restored.primitive_id == d.primitive_id
        assert len(restored.parameters) == 2

    def test_rejects_empty_postures(self) -> None:
        kw = self._valid() | {"supported_postures": []}
        with pytest.raises(ValidationError):
            PrimitiveDescriptor(**kw)

    def test_rejects_empty_choices(self) -> None:
        with pytest.raises(ValidationError):
            ParameterSpec(name="x", kind="enum", choices=[])
