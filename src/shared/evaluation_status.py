from django.db.models import F, Q, QuerySet, Window
from django.db.models.functions import RowNumber

from shared.models.nix_evaluation import NixEvaluation


def latest_completed_evaluations(channel_filter: Q | None = None) -> QuerySet[NixEvaluation]:
    qs = NixEvaluation.objects.filter(state=NixEvaluation.EvaluationState.COMPLETED)
    if channel_filter is not None:
        qs = qs.filter(channel_filter)
    return qs.annotate(
        row_num=Window(
            expression=RowNumber(),
            partition_by=[F("channel")],
            order_by=F("updated_at").desc(),
        ),
    ).filter(row_num=1)
