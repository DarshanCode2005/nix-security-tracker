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
    TrainingRecord,
    derivation_fingerprint,
    record_from_dict,
    record_to_dict,
)

__all__ = [
    "SCHEMA_VERSION",
    "TrainingRecord",
    "derivation_fingerprint",
    "export_proposal",
    "import_record",
    "record_from_dict",
    "record_to_dict",
    "user_curated_proposals",
]
