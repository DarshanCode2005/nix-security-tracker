from collections.abc import Callable
from datetime import timedelta

from shared.evaluation_status import (
    ChannelEvaluationStatus,
    get_channel_evaluation_statuses,
)
from shared.models.nix_evaluation import NixChannel, NixEvaluation


def _status_for(
    statuses: list[ChannelEvaluationStatus],
    channel: NixChannel,
) -> ChannelEvaluationStatus:
    return next(s for s in statuses if s.channel.pk == channel.pk)


def test_latest_and_latest_successful_selected_by_updated_at(
    make_channel: Callable[..., NixChannel],
    make_evaluation: Callable[..., NixEvaluation],
) -> None:
    channel = make_channel(branch="nixpkgs-unstable")
    older_completed = make_evaluation(
        channel=channel,
        state=NixEvaluation.EvaluationState.COMPLETED,
        commit_sha1="completed-old",
        age=timedelta(days=2),
    )
    newer_crashed = make_evaluation(
        channel=channel,
        state=NixEvaluation.EvaluationState.CRASHED,
        commit_sha1="crashed-new",
        age=timedelta(days=0),
    )

    status = _status_for(get_channel_evaluation_statuses(), channel)

    assert status.latest == newer_crashed
    assert status.latest_successful == older_completed


def test_healthy_when_completed_at_head(
    make_channel: Callable[..., NixChannel],
    make_evaluation: Callable[..., NixEvaluation],
) -> None:
    channel = make_channel(branch="nixpkgs-unstable")
    head = "head-commit-abc"
    channel.head_sha1_commit = head
    channel.save(update_fields=["head_sha1_commit"])

    make_evaluation(
        channel=channel,
        state=NixEvaluation.EvaluationState.COMPLETED,
        commit_sha1="older-commit",
        age=timedelta(days=1),
    )
    latest = make_evaluation(
        channel=channel,
        state=NixEvaluation.EvaluationState.COMPLETED,
        commit_sha1=head,
        age=timedelta(days=0),
    )

    status = _status_for(get_channel_evaluation_statuses(), channel)

    assert status.is_healthy
    assert status.latest == latest
    assert status.latest_successful == latest


def test_healthy_when_in_progress_at_head(
    make_channel: Callable[..., NixChannel],
    make_evaluation: Callable[..., NixEvaluation],
) -> None:
    channel = make_channel(branch="nixpkgs-unstable")
    head = "head-commit-in-progress"
    channel.head_sha1_commit = head
    channel.save(update_fields=["head_sha1_commit"])

    make_evaluation(
        channel=channel,
        state=NixEvaluation.EvaluationState.COMPLETED,
        commit_sha1="older-successful",
        age=timedelta(days=1),
    )
    make_evaluation(
        channel=channel,
        state=NixEvaluation.EvaluationState.IN_PROGRESS,
        commit_sha1=head,
        age=timedelta(days=0),
    )

    status = _status_for(get_channel_evaluation_statuses(), channel)

    assert status.is_healthy
    assert status.latest.state == NixEvaluation.EvaluationState.IN_PROGRESS
    assert status.latest_successful.commit_sha1 == "older-successful"


def test_unhealthy_when_crashed_at_head_with_stale_successful(
    make_channel: Callable[..., NixChannel],
    make_evaluation: Callable[..., NixEvaluation],
) -> None:
    channel = make_channel(branch="nixpkgs-unstable")
    head = "head-commit-crashed"
    channel.head_sha1_commit = head
    channel.save(update_fields=["head_sha1_commit"])

    make_evaluation(
        channel=channel,
        state=NixEvaluation.EvaluationState.COMPLETED,
        commit_sha1="stale-successful",
        age=timedelta(days=30),
    )
    make_evaluation(
        channel=channel,
        state=NixEvaluation.EvaluationState.CRASHED,
        commit_sha1=head,
        age=timedelta(days=0),
    )

    status = _status_for(get_channel_evaluation_statuses(), channel)

    assert not status.is_healthy
    assert status.latest.state == NixEvaluation.EvaluationState.CRASHED
    assert status.latest_successful.commit_sha1 == "stale-successful"


def test_unhealthy_when_channel_has_no_evaluations(
    make_channel: Callable[..., NixChannel],
) -> None:
    channel = make_channel(branch="nixpkgs-empty")

    status = _status_for(get_channel_evaluation_statuses(), channel)

    assert status.latest is None
    assert status.latest_successful is None
    assert not status.is_healthy


def test_unhealthy_when_never_completed(
    make_channel: Callable[..., NixChannel],
    make_evaluation: Callable[..., NixEvaluation],
) -> None:
    channel = make_channel(branch="nixpkgs-never-completed")
    head = "head-commit-never-completed"
    channel.head_sha1_commit = head
    channel.save(update_fields=["head_sha1_commit"])

    make_evaluation(
        channel=channel,
        state=NixEvaluation.EvaluationState.FAILED,
        commit_sha1=head,
    )

    status = _status_for(get_channel_evaluation_statuses(), channel)

    assert status.latest is not None
    assert status.latest_successful is None
    assert not status.is_healthy


def test_returns_channels_ordered_by_branch(
    make_channel: Callable[..., NixChannel],
) -> None:
    channel_b = make_channel(branch="nixpkgs-b")
    channel_a = make_channel(branch="nixpkgs-a")

    statuses = get_channel_evaluation_statuses(
        NixChannel.objects.filter(
            channel_branch__in=[channel_a.pk, channel_b.pk],
        ).order_by("channel_branch"),
    )

    assert [status.channel.pk for status in statuses] == [channel_a.pk, channel_b.pk]
