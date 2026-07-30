"""Import matching training-data records into a local ORM graph."""

from __future__ import annotations

import secrets
import uuid
from typing import Any

from django.db import transaction

from shared.matching_training_data.constants import (
    BENCHMARK_CHANNEL_BRANCH,
    BENCHMARK_RELEASE_BRANCH,
)
from shared.models.cve import (
    AffectedProduct,
    Container,
    Cpe,
    CveRecord,
    Organization,
    Tag,
)
from shared.models.linkage import (
    CVEDerivationClusterProposal,
    DerivationClusterProposalLink,
    MaintainerOverlay,
    PackageOverlay,
    ReferenceUrlOverlay,
)
from shared.models.nix_evaluation import (
    NixChannel,
    NixDerivation,
    NixDerivationMeta,
    NixEvaluation,
    NixMaintainer,
    NixpkgsBranch,
)

# Stable org for imported training CVEs (not a real NVD assigner).
_TRAINING_ORG_UUID = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")


def ensure_benchmark_evaluation() -> NixEvaluation:
    """Create or reuse the synthetic benchmark channel + completed evaluation."""
    release_branch, _ = NixpkgsBranch.objects.get_or_create(
        name=BENCHMARK_RELEASE_BRANCH,
        defaults={"head_sha1_commit": secrets.token_hex(20)},
    )
    channel, _ = NixChannel.objects.get_or_create(
        channel_branch=BENCHMARK_CHANNEL_BRANCH,
        defaults={
            "release_branch": release_branch,
            "state": NixChannel.ChannelState.UNSTABLE,
            "head_sha1_commit": secrets.token_hex(20),
            "variant": None,
        },
    )
    evaluation = (
        NixEvaluation.objects.filter(
            channel=channel,
            state=NixEvaluation.EvaluationState.COMPLETED,
        )
        .order_by("-updated_at")
        .first()
    )
    if evaluation is None:
        evaluation = NixEvaluation.objects.create(
            channel=channel,
            commit_sha1=secrets.token_hex(20),
            state=NixEvaluation.EvaluationState.COMPLETED,
        )
    return evaluation


def _ensure_organization() -> Organization:
    org, _ = Organization.objects.get_or_create(
        uuid=_TRAINING_ORG_UUID,
        defaults={"short_name": "training-data"},
    )
    return org


def _clear_existing_cve(cve_id: str) -> None:
    CveRecord.objects.filter(cve_id=cve_id).delete()


def _create_container(record: dict[str, Any], org: Organization) -> Container:
    cve = CveRecord.objects.create(cve_id=record["cve_id"], assigner=org)
    container = Container.objects.create(
        cve=cve,
        provider=org,
        title=f"Training data for {record['cve_id']}",
    )

    tag_objs = []
    for value in record["container"].get("tags") or []:
        tag, _ = Tag.objects.get_or_create(value=value)
        tag_objs.append(tag)
    if tag_objs:
        container.tags.set(tag_objs)

    for affected_data in record["container"].get("affected") or []:
        affected = AffectedProduct.objects.create(
            vendor=affected_data.get("vendor"),
            product=affected_data.get("product"),
            package_name=affected_data.get("package_name"),
        )
        for cpe_name in affected_data.get("cpes") or []:
            cpe, _ = Cpe.objects.get_or_create(name=cpe_name)
            affected.cpes.add(cpe)
        container.affected.add(affected)

    return container


def _create_derivations(
    record: dict[str, Any], evaluation: NixEvaluation
) -> dict[tuple[str, str, str], NixDerivation]:
    by_fingerprint: dict[tuple[str, str, str], NixDerivation] = {}
    for item in record.get("derivations") or []:
        key = (item["attribute"], item["name"], item["system"])
        if key in by_fingerprint:
            continue
        meta = NixDerivationMeta.objects.create(
            description="Imported training derivation",
            homepage=None,
            insecure=False,
            available=True,
            broken=False,
            unfree=False,
            unsupported=False,
            known_vulnerabilities=list(item.get("known_vulnerabilities") or []),
        )
        drv = NixDerivation.objects.create(
            attribute=item["attribute"],
            derivation_path=f"/nix/store/training-{secrets.token_hex(8)}-{item['name']}.drv",
            name=item["name"],
            metadata=meta,
            system=item["system"],
            parent_evaluation=evaluation,
        )
        by_fingerprint[key] = drv
    return by_fingerprint


def _create_proposal(
    record: dict[str, Any],
    container: Container,
    derivations: dict[tuple[str, str, str], NixDerivation],
) -> CVEDerivationClusterProposal:
    labels = record["labels"]
    proposal = CVEDerivationClusterProposal.objects.create(
        cve=container.cve,
        status=labels["status"],
        rejection_reason=labels.get("rejection_reason"),
        comment=labels.get("comment"),
        rejection_match_count=labels.get("rejection_match_count"),
        rejection_max_matches_limit=labels.get("rejection_max_matches_limit"),
        algorithm_version=record["algorithm_version"],
    )

    links = []
    for item in record.get("derivations") or []:
        if not item.get("was_linked", True):
            continue
        key = (item["attribute"], item["name"], item["system"])
        links.append(
            DerivationClusterProposalLink(
                proposal=proposal,
                derivation=derivations[key],
                provenance_flags=item["provenance_flags"],
            )
        )
    if links:
        DerivationClusterProposalLink.objects.bulk_create(links)

    for overlay in labels.get("package_overlays") or []:
        PackageOverlay.objects.create(
            suggestion=proposal,
            package_attribute=overlay["package_attribute"],
            type=overlay["overlay_type"],
        )

    for overlay in labels.get("maintainer_overlays") or []:
        maintainer, _ = NixMaintainer.objects.get_or_create(
            github_id=overlay["github_id"],
            defaults={
                "github": overlay["github"],
                "email": None,
                "matrix": None,
                "name": None,
            },
        )
        MaintainerOverlay.objects.create(
            suggestion=proposal,
            maintainer=maintainer,
            type=overlay["overlay_type"],
        )

    for overlay in labels.get("reference_overlays") or []:
        ReferenceUrlOverlay.objects.create(
            suggestion=proposal,
            reference_url=overlay["reference_url"],
            type=overlay["overlay_type"],
            deduplicated_name=overlay.get("deduplicated_name") or "",
        )

    return proposal


@transaction.atomic
def import_record(
    record: dict[str, Any],
    *,
    evaluation: NixEvaluation | None = None,
) -> CVEDerivationClusterProposal:
    """
    Materialize a training record as ORM rows on the synthetic benchmark channel.

    Idempotent per ``cve_id``: any existing CVE with that id is replaced.
    Side effects such as pgpubsub listeners may still fire on insert; callers that
    need a quiet import should disconnect listeners around this call.
    """
    if evaluation is None:
        evaluation = ensure_benchmark_evaluation()

    _clear_existing_cve(record["cve_id"])
    org = _ensure_organization()
    container = _create_container(record, org)
    derivations = _create_derivations(record, evaluation)
    return _create_proposal(record, container, derivations)
