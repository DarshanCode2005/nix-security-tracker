"""Versioned schema for matching training-data records."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

SCHEMA_VERSION = 1

# Synthetic channel used when materializing a local benchmark corpus.
BENCHMARK_CHANNEL_BRANCH = "benchmark"


@dataclass(frozen=True, order=True)
class DerivationFingerprint:
    attribute: str
    name: str
    system: str

    def as_tuple(self) -> tuple[str, str, str]:
        return (self.attribute, self.name, self.system)


def derivation_fingerprint(
    *, attribute: str, name: str, system: str
) -> DerivationFingerprint:
    return DerivationFingerprint(attribute=attribute, name=name, system=system)


@dataclass(frozen=True)
class AffectedProductData:
    vendor: str | None
    product: str | None
    package_name: str | None
    cpes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ContainerData:
    tags: tuple[str, ...]
    affected: tuple[AffectedProductData, ...]


@dataclass(frozen=True)
class DerivationData:
    attribute: str
    name: str
    system: str
    known_vulnerabilities: tuple[str, ...]
    provenance_flags: int
    was_linked: bool

    @property
    def fingerprint(self) -> DerivationFingerprint:
        return DerivationFingerprint(
            attribute=self.attribute, name=self.name, system=self.system
        )


@dataclass(frozen=True)
class PackageOverlayData:
    package_attribute: str
    overlay_type: str


@dataclass(frozen=True)
class MaintainerOverlayData:
    github_id: int
    github: str
    overlay_type: str


@dataclass(frozen=True)
class ReferenceOverlayData:
    reference_url: str
    overlay_type: str
    deduplicated_name: str = ""


@dataclass(frozen=True)
class Labels:
    """Ground truth for offline benchmarking (independent of re-running the matcher)."""

    status: str
    rejection_reason: str | None
    kept_derivations: tuple[DerivationFingerprint, ...]
    ignored_packages: tuple[str, ...] = ()
    package_overlays: tuple[PackageOverlayData, ...] = ()
    maintainer_overlays: tuple[MaintainerOverlayData, ...] = ()
    reference_overlays: tuple[ReferenceOverlayData, ...] = ()
    comment: str | None = None
    rejection_match_count: int | None = None
    rejection_max_matches_limit: int | None = None


@dataclass(frozen=True)
class TrainingRecord:
    schema_version: int
    cve_id: str
    container: ContainerData
    labels: Labels
    derivations: tuple[DerivationData, ...]
    algorithm_version: int

    def normalized(self) -> TrainingRecord:
        """Return a copy with stably sorted collections for equality checks."""
        return TrainingRecord(
            schema_version=self.schema_version,
            cve_id=self.cve_id,
            container=ContainerData(
                tags=tuple(sorted(self.container.tags)),
                affected=tuple(
                    sorted(
                        self.container.affected,
                        key=lambda a: (
                            a.package_name or "",
                            a.product or "",
                            a.vendor or "",
                            a.cpes,
                        ),
                    )
                ),
            ),
            labels=Labels(
                status=self.labels.status,
                rejection_reason=self.labels.rejection_reason,
                kept_derivations=tuple(sorted(self.labels.kept_derivations)),
                ignored_packages=tuple(sorted(self.labels.ignored_packages)),
                package_overlays=tuple(
                    sorted(
                        self.labels.package_overlays,
                        key=lambda o: (o.package_attribute, o.overlay_type),
                    )
                ),
                maintainer_overlays=tuple(
                    sorted(
                        self.labels.maintainer_overlays,
                        key=lambda o: (o.github_id, o.overlay_type),
                    )
                ),
                reference_overlays=tuple(
                    sorted(
                        self.labels.reference_overlays,
                        key=lambda o: (o.reference_url, o.overlay_type),
                    )
                ),
                comment=self.labels.comment,
                rejection_match_count=self.labels.rejection_match_count,
                rejection_max_matches_limit=self.labels.rejection_max_matches_limit,
            ),
            derivations=tuple(
                sorted(
                    self.derivations,
                    key=lambda d: (d.attribute, d.name, d.system),
                )
            ),
            algorithm_version=self.algorithm_version,
        )


def record_to_dict(record: TrainingRecord) -> dict[str, Any]:
    return asdict(record.normalized())


def _fingerprint_from_dict(data: dict[str, Any]) -> DerivationFingerprint:
    return DerivationFingerprint(
        attribute=data["attribute"],
        name=data["name"],
        system=data["system"],
    )


def record_from_dict(data: dict[str, Any]) -> TrainingRecord:
    version = data.get("schema_version", SCHEMA_VERSION)
    if version != SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported matching training-data schema_version={version}; "
            f"expected {SCHEMA_VERSION}"
        )

    container_raw = data["container"]
    labels_raw = data["labels"]
    return TrainingRecord(
        schema_version=version,
        cve_id=data["cve_id"],
        container=ContainerData(
            tags=tuple(container_raw.get("tags") or ()),
            affected=tuple(
                AffectedProductData(
                    vendor=item.get("vendor"),
                    product=item.get("product"),
                    package_name=item.get("package_name"),
                    cpes=tuple(item.get("cpes") or ()),
                )
                for item in container_raw.get("affected") or ()
            ),
        ),
        labels=Labels(
            status=labels_raw["status"],
            rejection_reason=labels_raw.get("rejection_reason"),
            kept_derivations=tuple(
                _fingerprint_from_dict(item)
                for item in labels_raw.get("kept_derivations") or ()
            ),
            ignored_packages=tuple(labels_raw.get("ignored_packages") or ()),
            package_overlays=tuple(
                PackageOverlayData(
                    package_attribute=item["package_attribute"],
                    overlay_type=item["overlay_type"],
                )
                for item in labels_raw.get("package_overlays") or ()
            ),
            maintainer_overlays=tuple(
                MaintainerOverlayData(
                    github_id=item["github_id"],
                    github=item["github"],
                    overlay_type=item["overlay_type"],
                )
                for item in labels_raw.get("maintainer_overlays") or ()
            ),
            reference_overlays=tuple(
                ReferenceOverlayData(
                    reference_url=item["reference_url"],
                    overlay_type=item["overlay_type"],
                    deduplicated_name=item.get("deduplicated_name") or "",
                )
                for item in labels_raw.get("reference_overlays") or ()
            ),
            comment=labels_raw.get("comment"),
            rejection_match_count=labels_raw.get("rejection_match_count"),
            rejection_max_matches_limit=labels_raw.get(
                "rejection_max_matches_limit"
            ),
        ),
        derivations=tuple(
            DerivationData(
                attribute=item["attribute"],
                name=item["name"],
                system=item["system"],
                known_vulnerabilities=tuple(item.get("known_vulnerabilities") or ()),
                provenance_flags=int(item.get("provenance_flags") or 0),
                was_linked=bool(item.get("was_linked", True)),
            )
            for item in data.get("derivations") or ()
        ),
        algorithm_version=int(data.get("algorithm_version") or 0),
    )
