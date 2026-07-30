"""API adapter for matching training-data export.

Field schema lives in ``shared.matching_training_data.serializers``;
this wrapper maps ORM proposals onto that round-tripping wire format.
"""

from shared.matching_training_data import export_proposal, record_to_dict
from shared.matching_training_data.serializers import TrainingRecordSerializer
from shared.models.linkage import CVEDerivationClusterProposal


class MatchingTrainingRecordSerializer(TrainingRecordSerializer):
    """Serialize a curated proposal via the shared training-data export."""

    def to_representation(self, instance: CVEDerivationClusterProposal) -> dict:
        return record_to_dict(export_proposal(instance))
