from collections.abc import Callable

import pytest
from rest_framework.exceptions import ValidationError

from shared.listeners.automatic_linkage import resolve_linkage_candidates
from shared.matching_training_data import (
    SCHEMA_VERSION,
    export_proposal,
    import_record,
    normalize_record,
    record_from_dict,
    record_to_dict,
    user_curated_proposals,
)
from shared.matching_training_data.constants import BENCHMARK_CHANNEL_BRANCH
from shared.matching_training_data.importer import ensure_benchmark_evaluation
from shared.matching_training_data.serializers import TrainingRecordSerializer
from shared.models.cve import Container, CveRecord, Tag
from shared.models.linkage import (
    CVEDerivationClusterProposal,
    DerivationClusterProposalLink,
    PackageOverlay,
    ProvenanceFlags,
)
from shared.models.nix_evaluation import NixChannel, NixDerivation, NixEvaluation


def _sample_record() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "cve_id": "CVE-2026-9999",
        "container": {
            "tags": ["exclusively-hosted-service"],
            "affected": [
                {
                    "vendor": "acme",
                    "product": "widget",
                    "package_name": "foo",
                    "cpes": ["cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"],
                },
            ],
        },
        "labels": {
            "status": "accepted",
            "rejection_reason": None,
            "kept_derivations": [
                {
                    "attribute": "foo",
                    "name": "foo-1.0",
                    "system": "x86_64-linux",
                },
            ],
            "ignored_packages": ["foo.tests"],
            "package_overlays": [
                {
                    "package_attribute": "foo.tests",
                    "overlay_type": PackageOverlay.Type.IGNORED,
                },
            ],
            "maintainer_overlays": [],
            "reference_overlays": [],
            "comment": None,
            "rejection_match_count": None,
            "rejection_max_matches_limit": None,
        },
        "derivations": [
            {
                "attribute": "foo",
                "name": "foo-1.0",
                "system": "x86_64-linux",
                "known_vulnerabilities": [],
                "provenance_flags": int(ProvenanceFlags.PACKAGE_NAME_MATCH),
                "was_linked": True,
            },
            {
                "attribute": "foo.tests",
                "name": "foo-tests-1.0",
                "system": "x86_64-linux",
                "known_vulnerabilities": [],
                "provenance_flags": int(ProvenanceFlags.PACKAGE_NAME_MATCH),
                "was_linked": True,
            },
        ],
        "algorithm_version": 1,
    }


def test_schema_dict_roundtrip_preserves_fields() -> None:
    record = _sample_record()
    restored = record_from_dict(record_to_dict(record))
    assert restored == normalize_record(record)

    serializer = TrainingRecordSerializer(data=record_to_dict(record))
    assert serializer.is_valid(), serializer.errors


def test_schema_version_rejected() -> None:
    record = _sample_record()
    record["schema_version"] = SCHEMA_VERSION + 1
    with pytest.raises(ValueError, match="schema_version"):
        record_from_dict(record)

    serializer = TrainingRecordSerializer(data=record)
    with pytest.raises(ValidationError):
        serializer.is_valid(raise_exception=True)


def test_user_curated_proposals_excludes_pending(
    make_container: Callable[..., Container],
) -> None:
    pending_container = make_container(cve_id="CVE-2026-pend")
    accepted_container = make_container(cve_id="CVE-2026-acc")

    pending = CVEDerivationClusterProposal.objects.create(
        cve=pending_container.cve,
        status=CVEDerivationClusterProposal.Status.PENDING,
        algorithm_version=1,
    )
    accepted = CVEDerivationClusterProposal.objects.create(
        cve=accepted_container.cve,
        status=CVEDerivationClusterProposal.Status.ACCEPTED,
        algorithm_version=1,
    )

    curated_pks = set(user_curated_proposals().values_list("pk", flat=True))
    assert pending.pk not in curated_pks
    assert accepted.pk in curated_pks


def test_export_import_export_roundtrip(
    make_container: Callable[..., Container],
    make_channel: Callable[..., NixChannel],
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
) -> None:
    channel = make_channel(
        channel_branch="nixos-unstable",
        state=NixChannel.ChannelState.UNSTABLE,
    )
    evaluation = make_evaluation(channel=channel)
    drv = make_drv(
        evaluation=evaluation,
        pname="foobar",
        version="1.2.3",
        attribute="foobar",
    )
    ignored = make_drv(
        evaluation=evaluation,
        pname="foobar-tests",
        version="1.2.3",
        attribute="foobar.tests",
    )
    container = make_container(
        cve_id="CVE-2026-4242",
        package_name="foobar",
        product="foobar",
        cpes=["cpe:2.3:a:example:foobar:1.2.3:*:*:*:*:*:*:*"],
    )
    proposal = CVEDerivationClusterProposal.objects.create(
        cve=container.cve,
        status=CVEDerivationClusterProposal.Status.ACCEPTED,
        algorithm_version=CVEDerivationClusterProposal.CURRENT_ALGORITHM_VERSION,
    )
    DerivationClusterProposalLink.objects.create(
        proposal=proposal,
        derivation=drv,
        provenance_flags=int(ProvenanceFlags.PACKAGE_NAME_MATCH),
    )
    DerivationClusterProposalLink.objects.create(
        proposal=proposal,
        derivation=ignored,
        provenance_flags=int(ProvenanceFlags.PACKAGE_NAME_MATCH),
    )
    PackageOverlay.objects.create(
        suggestion=proposal,
        package_attribute="foobar.tests",
        type=PackageOverlay.Type.IGNORED,
    )

    original = export_proposal(proposal)
    assert original["schema_version"] == SCHEMA_VERSION
    assert original["cve_id"] == "CVE-2026-4242"
    assert original["labels"]["status"] == "accepted"
    assert original["labels"]["ignored_packages"] == ["foobar.tests"]
    kept = {
        (d["attribute"], d["name"], d["system"])
        for d in original["labels"]["kept_derivations"]
    }
    assert ("foobar", "foobar-1.2.3", "x86_64-linux") in kept
    assert ("foobar.tests", "foobar-tests-1.2.3", "x86_64-linux") not in kept

    CveRecord.objects.filter(cve_id="CVE-2026-4242").delete()
    assert not CVEDerivationClusterProposal.objects.filter(
        cve__cve_id="CVE-2026-4242"
    ).exists()

    imported = import_record(original)
    assert imported.cve.cve_id == "CVE-2026-4242"
    assert imported.status == CVEDerivationClusterProposal.Status.ACCEPTED
    assert imported.derivations.count() == 2
    assert imported.package_overlays.filter(package_attribute="foobar.tests").exists()
    assert NixChannel.objects.filter(channel_branch=BENCHMARK_CHANNEL_BRANCH).exists()

    reexported = export_proposal(imported)
    assert reexported == original

    imported_container = imported.cve.container.first()
    assert imported_container is not None
    outcome = resolve_linkage_candidates(imported_container)
    assert outcome is not None


def test_export_import_auto_reject_without_links(
    make_container: Callable[..., Container],
) -> None:
    container = make_container(cve_id="CVE-2026-0007", package_name="zzz")
    tag, _ = Tag.objects.get_or_create(value="exclusively-hosted-service")
    container.tags.add(tag)

    proposal = CVEDerivationClusterProposal.objects.create(
        cve=container.cve,
        status=CVEDerivationClusterProposal.Status.REJECTED,
        rejection_reason=CVEDerivationClusterProposal.RejectionReason.EXCLUSIVELY_HOSTED_SERVICE,
        algorithm_version=CVEDerivationClusterProposal.CURRENT_ALGORITHM_VERSION,
    )

    original = export_proposal(proposal)
    assert original["labels"]["kept_derivations"] == []
    assert original["derivations"] == []
    assert "exclusively-hosted-service" in original["container"]["tags"]

    CveRecord.objects.filter(cve_id="CVE-2026-0007").delete()
    imported = import_record(original)
    reexported = export_proposal(imported)
    assert reexported == original

    imported_container = imported.cve.container.first()
    assert imported_container is not None
    outcome = resolve_linkage_candidates(imported_container)
    assert outcome.rejection is not None
    assert (
        outcome.rejection.reason
        == CVEDerivationClusterProposal.RejectionReason.EXCLUSIVELY_HOSTED_SERVICE
    )


def test_import_is_idempotent_by_cve_id(
    make_container: Callable[..., Container],
    make_drv: Callable[..., NixDerivation],
) -> None:
    container = make_container(cve_id="CVE-2026-1111", package_name="foo")
    proposal = CVEDerivationClusterProposal.objects.create(
        cve=container.cve,
        status=CVEDerivationClusterProposal.Status.PUBLISHED,
        algorithm_version=1,
    )
    DerivationClusterProposalLink.objects.create(
        proposal=proposal,
        derivation=make_drv(pname="foo", attribute="foo"),
        provenance_flags=int(ProvenanceFlags.PACKAGE_NAME_MATCH),
    )
    record = export_proposal(proposal)

    first = import_record(record)
    second = import_record(record)
    assert first.pk != second.pk
    assert (
        CVEDerivationClusterProposal.objects.filter(cve__cve_id="CVE-2026-1111").count()
        == 1
    )


def test_ensure_benchmark_evaluation_reuses_channel(db: None) -> None:
    first = ensure_benchmark_evaluation()
    second = ensure_benchmark_evaluation()
    assert first.channel.channel_branch == BENCHMARK_CHANNEL_BRANCH
    assert first.channel_id == second.channel_id
    assert first.pk == second.pk
