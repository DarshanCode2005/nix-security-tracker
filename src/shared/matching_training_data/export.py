"""Export CVE–derivation proposals to the matching training-data schema."""

from __future__ import annotations

from django.db.models import Prefetch, QuerySet

from shared.matching_training_data.schema import (
    SCHEMA_VERSION,
    AffectedProductData,
    ContainerData,
    DerivationData,
    DerivationFingerprint,
    Labels,
    MaintainerOverlayData,
    PackageOverlayData,
    ReferenceOverlayData,
    TrainingRecord,
)
from shared.models.cve import Container
from shared.models.linkage import (
    CVEDerivationClusterProposal,
    DerivationClusterProposalLink,
    PackageOverlay,
)


def user_curated_proposals() -> QuerySet[CVEDerivationClusterProposal]:
    """Proposals touched by users or auto-triage (everything except pending)."""
    return (
        CVEDerivationClusterProposal.objects.exclude(
            status=CVEDerivationClusterProposal.Status.PENDING
        )
        .select_related("cve")
        .prefetch_related(
            "cve__container__tags",
            "cve__container__affected__cpes",
            Prefetch(
                "derivationclusterproposallink_set",
                queryset=DerivationClusterProposalLink.objects.select_related(
                    "derivation__metadata"
                ),
            ),
            "package_overlays",
            "maintainer_overlays__maintainer",
            "reference_url_overlays",
        )
        .order_by("pk")
    )


def _select_container(proposal: CVEDerivationClusterProposal) -> Container | None:
    return (
        proposal.cve.container.filter(affected__package_name__isnull=False).first()
        or proposal.cve.container.first()
    )


def _export_container(container: Container) -> ContainerData:
    affected = tuple(
        AffectedProductData(
            vendor=product.vendor,
            product=product.product,
            package_name=product.package_name,
            cpes=tuple(sorted(cpe.name for cpe in product.cpes.all())),
        )
        for product in container.affected.all()
    )
    return ContainerData(
        tags=tuple(sorted(tag.value for tag in container.tags.all())),
        affected=affected,
    )


def _export_derivations(
    proposal: CVEDerivationClusterProposal,
) -> tuple[DerivationData, ...]:
    links = proposal.derivationclusterproposallink_set.all()
    rows: list[DerivationData] = []
    for link in links:
        drv = link.derivation
        known = ()
        if drv.metadata_id is not None and drv.metadata is not None:
            known = tuple(drv.metadata.known_vulnerabilities or ())
        rows.append(
            DerivationData(
                attribute=drv.attribute,
                name=drv.name,
                system=drv.system,
                known_vulnerabilities=known,
                provenance_flags=int(link.provenance_flags),
                was_linked=True,
            )
        )
    return tuple(rows)


def _kept_derivations(
    derivations: tuple[DerivationData, ...],
    ignored_packages: set[str],
    status: str,
) -> tuple[DerivationFingerprint, ...]:
    if status == CVEDerivationClusterProposal.Status.REJECTED:
        return ()
    return tuple(
        sorted(
            d.fingerprint
            for d in derivations
            if d.attribute not in ignored_packages
        )
    )


def export_proposal(proposal: CVEDerivationClusterProposal) -> TrainingRecord:
    """Serialize a user-curated proposal into a training-data record."""
    container = _select_container(proposal)
    if container is None:
        raise ValueError(
            f"Proposal {proposal.pk} for {proposal.cve.cve_id} has no CVE container"
        )

    package_overlays = tuple(
        PackageOverlayData(
            package_attribute=overlay.package_attribute,
            overlay_type=overlay.type,
        )
        for overlay in proposal.package_overlays.all()
    )
    ignored_packages = {
        overlay.package_attribute
        for overlay in package_overlays
        if overlay.overlay_type == PackageOverlay.Type.IGNORED
    }

    derivations = _export_derivations(proposal)
    labels = Labels(
        status=proposal.status,
        rejection_reason=proposal.rejection_reason,
        kept_derivations=_kept_derivations(
            derivations, ignored_packages, proposal.status
        ),
        ignored_packages=tuple(sorted(ignored_packages)),
        package_overlays=package_overlays,
        maintainer_overlays=tuple(
            MaintainerOverlayData(
                github_id=overlay.maintainer.github_id,
                github=overlay.maintainer.github,
                overlay_type=overlay.type,
            )
            for overlay in proposal.maintainer_overlays.all()
        ),
        reference_overlays=tuple(
            ReferenceOverlayData(
                reference_url=overlay.reference_url,
                overlay_type=overlay.type,
                deduplicated_name=overlay.deduplicated_name or "",
            )
            for overlay in proposal.reference_url_overlays.all()
        ),
        comment=proposal.comment,
        rejection_match_count=proposal.rejection_match_count,
        rejection_max_matches_limit=proposal.rejection_max_matches_limit,
    )

    return TrainingRecord(
        schema_version=SCHEMA_VERSION,
        cve_id=proposal.cve.cve_id,
        container=_export_container(container),
        labels=labels,
        derivations=derivations,
        algorithm_version=proposal.algorithm_version,
    ).normalized()
