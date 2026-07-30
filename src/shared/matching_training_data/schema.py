"""Versioned schema for matching training-data records."""

from __future__ import annotations

from typing import Any, cast

from shared.matching_training_data.constants import (
    BENCHMARK_CHANNEL_BRANCH,
    SCHEMA_VERSION,
)

# Re-export for existing callers that import constants from schema.
__all__ = [
    "BENCHMARK_CHANNEL_BRANCH",
    "SCHEMA_VERSION",
    "derivation_fingerprint",
    "normalize_record",
    "record_from_dict",
    "record_to_dict",
]


def derivation_fingerprint(*, attribute: str, name: str, system: str) -> dict[str, str]:
    return {"attribute": attribute, "name": name, "system": system}


def normalize_record(data: dict[str, Any]) -> dict[str, Any]:
    """Return a copy with stably sorted collections for equality checks."""
    container = data.get("container") or {}
    labels = data.get("labels") or {}

    affected = [
        {
            "vendor": item.get("vendor"),
            "product": item.get("product"),
            "package_name": item.get("package_name"),
            "cpes": sorted(item.get("cpes") or []),
        }
        for item in (container.get("affected") or [])
    ]

    kept = [
        {
            "attribute": item["attribute"],
            "name": item["name"],
            "system": item["system"],
        }
        for item in (labels.get("kept_derivations") or [])
    ]
    package_overlays = [
        {
            "package_attribute": item["package_attribute"],
            "overlay_type": item["overlay_type"],
        }
        for item in (labels.get("package_overlays") or [])
    ]
    maintainer_overlays = [
        {
            "github_id": item["github_id"],
            "github": item["github"],
            "overlay_type": item["overlay_type"],
        }
        for item in (labels.get("maintainer_overlays") or [])
    ]
    reference_overlays = [
        {
            "reference_url": item["reference_url"],
            "overlay_type": item["overlay_type"],
            "deduplicated_name": item.get("deduplicated_name") or "",
        }
        for item in (labels.get("reference_overlays") or [])
    ]

    derivations = [
        {
            "attribute": item["attribute"],
            "name": item["name"],
            "system": item["system"],
            "known_vulnerabilities": list(item.get("known_vulnerabilities") or []),
            "provenance_flags": int(item.get("provenance_flags") or 0),
            "was_linked": bool(item.get("was_linked", True)),
        }
        for item in (data.get("derivations") or [])
    ]

    return {
        "schema_version": data["schema_version"],
        "cve_id": data["cve_id"],
        "container": {
            "tags": sorted(container.get("tags") or []),
            "affected": sorted(
                affected,
                key=lambda a: (
                    a.get("package_name") or "",
                    a.get("product") or "",
                    a.get("vendor") or "",
                    tuple(a.get("cpes") or []),
                ),
            ),
        },
        "labels": {
            "status": labels["status"],
            "rejection_reason": labels.get("rejection_reason"),
            "kept_derivations": sorted(
                kept,
                key=lambda d: (d["attribute"], d["name"], d["system"]),
            ),
            "ignored_packages": sorted(labels.get("ignored_packages") or []),
            "package_overlays": sorted(
                package_overlays,
                key=lambda o: (o["package_attribute"], o["overlay_type"]),
            ),
            "maintainer_overlays": sorted(
                maintainer_overlays,
                key=lambda o: (o["github_id"], o["overlay_type"]),
            ),
            "reference_overlays": sorted(
                reference_overlays,
                key=lambda o: (o["reference_url"], o["overlay_type"]),
            ),
            "comment": labels.get("comment"),
            "rejection_match_count": labels.get("rejection_match_count"),
            "rejection_max_matches_limit": labels.get("rejection_max_matches_limit"),
        },
        "derivations": sorted(
            derivations,
            key=lambda d: (d["attribute"], d["name"], d["system"]),
        ),
        "algorithm_version": data["algorithm_version"],
    }


def record_to_dict(record: dict[str, Any]) -> dict[str, Any]:
    """Serialize a training record through the DRF schema (normalized)."""
    from shared.matching_training_data.serializers import TrainingRecordSerializer

    return cast(
        dict[str, Any],
        TrainingRecordSerializer(normalize_record(record)).data,
    )


def record_from_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize a training-data dict via the DRF schema."""
    from rest_framework.exceptions import ValidationError

    from shared.matching_training_data.serializers import TrainingRecordSerializer

    serializer = TrainingRecordSerializer(data=data)
    try:
        serializer.is_valid(raise_exception=True)
    except ValidationError as exc:
        # Preserve a clear schema_version message for callers/tests.
        version_errors = (exc.detail or {}).get("schema_version")  # type: ignore[union-attr]
        if version_errors:
            raise ValueError(str(version_errors[0])) from exc
        raise
    # validated_data is a nested OrderedDict; normalize to plain sorted dicts.
    return normalize_record(cast(dict[str, Any], serializer.validated_data))
