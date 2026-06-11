from dataclasses import dataclass

from shared.models.nix_evaluation import NixChannel, NixEvaluation


@dataclass(frozen=True)
class ChannelEvaluationStatus:
    channel: NixChannel
    latest: NixEvaluation | None
    latest_successful: NixEvaluation | None
