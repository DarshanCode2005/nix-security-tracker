"""API adapter for matching training-data export.

Wire format lives in ``shared.matching_training_data.serializers``;
this subclass is only a named API entrypoint for OpenAPI / views.
"""

from shared.matching_training_data.serializers import CVEDerivationClusterProposal


class MatchingTrainingRecordSerializer(CVEDerivationClusterProposal):
    """Serialize a curated proposal via the shared training-data ModelSerializer."""
