"""DRF serializers for matching training-data records (round-tripping schema)."""

from __future__ import annotations

from rest_framework import serializers

from shared.matching_training_data.constants import SCHEMA_VERSION


class DerivationFingerprintSerializer(serializers.Serializer):
    attribute = serializers.CharField()
    name = serializers.CharField()
    system = serializers.CharField()


class AffectedProductDataSerializer(serializers.Serializer):
    vendor = serializers.CharField(allow_null=True)
    product = serializers.CharField(allow_null=True)
    package_name = serializers.CharField(allow_null=True)
    cpes = serializers.ListField(child=serializers.CharField(), required=False)


class ContainerDataSerializer(serializers.Serializer):
    tags = serializers.ListField(child=serializers.CharField(), required=False)
    affected = AffectedProductDataSerializer(many=True, required=False)


class DerivationDataSerializer(serializers.Serializer):
    attribute = serializers.CharField()
    name = serializers.CharField()
    system = serializers.CharField()
    known_vulnerabilities = serializers.ListField(
        child=serializers.CharField(), required=False
    )
    provenance_flags = serializers.IntegerField()
    was_linked = serializers.BooleanField()


class PackageOverlayDataSerializer(serializers.Serializer):
    package_attribute = serializers.CharField()
    overlay_type = serializers.CharField()


class MaintainerOverlayDataSerializer(serializers.Serializer):
    github_id = serializers.IntegerField()
    github = serializers.CharField()
    overlay_type = serializers.CharField()


class ReferenceOverlayDataSerializer(serializers.Serializer):
    reference_url = serializers.CharField()
    overlay_type = serializers.CharField()
    deduplicated_name = serializers.CharField(required=False, allow_blank=True)


class LabelsSerializer(serializers.Serializer):
    status = serializers.CharField()
    rejection_reason = serializers.CharField(allow_null=True, required=False)
    kept_derivations = DerivationFingerprintSerializer(many=True, required=False)
    ignored_packages = serializers.ListField(
        child=serializers.CharField(), required=False
    )
    package_overlays = PackageOverlayDataSerializer(many=True, required=False)
    maintainer_overlays = MaintainerOverlayDataSerializer(many=True, required=False)
    reference_overlays = ReferenceOverlayDataSerializer(many=True, required=False)
    comment = serializers.CharField(allow_null=True, allow_blank=True, required=False)
    rejection_match_count = serializers.IntegerField(allow_null=True, required=False)
    rejection_max_matches_limit = serializers.IntegerField(
        allow_null=True, required=False
    )


class TrainingRecordSerializer(serializers.Serializer):
    """Versioned matching training-data record (export/import wire format)."""

    schema_version = serializers.IntegerField()
    cve_id = serializers.CharField()
    container = ContainerDataSerializer()
    labels = LabelsSerializer()
    derivations = DerivationDataSerializer(many=True, required=False)
    algorithm_version = serializers.IntegerField()

    def validate_schema_version(self, value: int) -> int:
        if value != SCHEMA_VERSION:
            raise serializers.ValidationError(
                f"Unsupported matching training-data schema_version={value}; "
                f"expected {SCHEMA_VERSION}"
            )
        return value
