from dataclasses import dataclass

from django.db.models import F, Q, QuerySet, Window
from django.db.models.functions import RowNumber

from shared.models.nix_evaluation import NixChannel, NixEvaluation


@dataclass(frozen=True)
class ChannelEvaluationStatus:
    channel: NixChannel
    latest: NixEvaluation | None
    latest_successful: NixEvaluation | None

    @property
    def is_healthy(self) -> bool:
        if self.latest is None:
            return False

        if self.latest.commit_sha1 != self.channel.head_sha1_commit:
            return False

        if self.latest.state == NixEvaluation.EvaluationState.COMPLETED:
            return True

        if self.latest.state in (
            NixEvaluation.EvaluationState.WAITING,
            NixEvaluation.EvaluationState.IN_PROGRESS,
        ):
            return True

        return False


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


def get_channel_evaluation_statuses(
    channels: QuerySet[NixChannel] | None = None,
) -> list[ChannelEvaluationStatus]:
    if channels is None:
        channels = NixChannel.objects.order_by("channel_branch")

    latest_by_channel = {
        evaluation.channel_id: evaluation
        for evaluation in _latest_evaluations_per_channel()
    }
    latest_successful_by_channel = {
        evaluation.channel_id: evaluation
        for evaluation in _latest_evaluations_per_channel(completed_only=True)
    }

    return [
        ChannelEvaluationStatus(
            channel=channel,
            latest=latest_by_channel.get(channel.pk),
            latest_successful=latest_successful_by_channel.get(channel.pk),
        )
        for channel in channels
    ]
