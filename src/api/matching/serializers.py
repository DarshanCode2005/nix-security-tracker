"""OpenAPI serializers for matching training-data records.

Wire format comes from export_proposal / record_to_dict, these fields
exist so drf-spectacular documents the shared schema without re-mapping data.
"""

from rest_framework import serializers

from shared.matching_training_data import export_proposal, record_to_dict
from shared.models.linkage import CVEDerivationClusterProposal


class DerivationFingerprintSerializer(serializers.Serializer):
    attribute = serializers.CharField()
    name = serializers.CharField()
    system = serializers.CharField()


class AffectedProductDataSerializer(serializers.Serializer):
    vendor = serializers.CharField(allow_null=True)
    product = serializers.CharField(allow_null=True)
    package_name = serializers.CharField(allow_null=True)
    cpes = serializers.ListField(child=serializers.CharField())


class ContainerDataSerializer(serializers.Serializer):
    tags = serializers.ListField(child=serializers.CharField())
    affected = AffectedProductDataSerializer(many=True)


class DerivationDataSerializer(serializers.Serializer):
    attribute = serializers.CharField()
    name = serializers.CharField()
    system = serializers.CharField()
    known_vulnerabilities = serializers.ListField(child=serializers.CharField())
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
    deduplicated_name = serializers.CharField()


class LabelsSerializer(serializers.Serializer):
    status = serializers.CharField()
    rejection_reason = serializers.CharField(allow_null=True)
    kept_derivations = DerivationFingerprintSerializer(many=True)
    ignored_packages = serializers.ListField(child=serializers.CharField())
    package_overlays = PackageOverlayDataSerializer(many=True)
    maintainer_overlays = MaintainerOverlayDataSerializer(many=True)
    reference_overlays = ReferenceOverlayDataSerializer(many=True)
    comment = serializers.CharField(allow_null=True, required=False)
    rejection_match_count = serializers.IntegerField(allow_null=True, required=False)
    rejection_max_matches_limit = serializers.IntegerField(
        allow_null=True, required=False
    )


class MatchingTrainingRecordSerializer(serializers.Serializer):
    """Serialize a curated proposal via the shared training-data export."""

    schema_version = serializers.IntegerField()
    cve_id = serializers.CharField()
    container = ContainerDataSerializer()
    labels = LabelsSerializer()
    derivations = DerivationDataSerializer(many=True)
    algorithm_version = serializers.IntegerField()

    def to_representation(self, instance: CVEDerivationClusterProposal) -> dict:
        return record_to_dict(export_proposal(instance))
