from dataclasses import dataclass

from django.db.models import F, Q, QuerySet, Window
from django.db.models.functions import RowNumber

from shared.models.nix_evaluation import NixChannel, NixEvaluation


@dataclass(frozen=True)
class ChannelEvaluationStatus:
    channel: NixChannel
    latest: NixEvaluation | None
    latest_successful: NixEvaluation | None


def _latest_evaluations_per_channel(
    *,
    channel_filter: Q | None = None,
    completed_only: bool = False,
) -> QuerySet[NixEvaluation]:
    qs = NixEvaluation.objects.all()
    if completed_only:
        qs = qs.filter(state=NixEvaluation.EvaluationState.COMPLETED)
    if channel_filter is not None:
        qs = qs.filter(channel_filter)
    return qs.annotate(
        row_num=Window(
            expression=RowNumber(),
            partition_by=[F("channel")],
            order_by=F("updated_at").desc(),
        ),
    ).filter(row_num=1)


def latest_completed_evaluations(
    channel_filter: Q | None = None,
) -> QuerySet[NixEvaluation]:
    return _latest_evaluations_per_channel(
        channel_filter=channel_filter,
        completed_only=True,
    )
