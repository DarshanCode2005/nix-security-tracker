"""Matching training-data roundtrip.

Export and import share one versioned schema so the offline benchmark corpus
stays in sync with the data model.
"""

from shared.matching_training_data.export import (
    export_proposal,
    user_curated_proposals,
)
from shared.matching_training_data.importer import import_record
from shared.matching_training_data.schema import (
    SCHEMA_VERSION,
    derivation_fingerprint,
    normalize_record,
    record_from_dict,
    record_to_dict,
)
from shared.matching_training_data.serializers import TrainingRecordSerializer

__all__ = [
    "SCHEMA_VERSION",
    "TrainingRecordSerializer",
    "derivation_fingerprint",
    "export_proposal",
    "import_record",
    "normalize_record",
    "record_from_dict",
    "record_to_dict",
    "user_curated_proposals",
]
