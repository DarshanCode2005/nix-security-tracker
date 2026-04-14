import io
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from django.core.management import call_command

from shared.management.commands.fetch_all_channels import (
    MonitoredChannel,
    format_channel_report,
)
from shared.models.nix_evaluation import NixChannel

STABLE_BRANCH_INFO = {
    "channel_branch": "nixos-25.11",
    "staging_branch": "release-25.11",
    "state": NixChannel.ChannelState.STABLE,
    "head_sha1_commit": "aabbcc001122ddef",
    "release_version": "25.11",
}


def test_report_newly_fetched_commit() -> None:
    line = format_channel_report(STABLE_BRANCH_INFO, True)
    assert "fetched" in line


def test_report_commit_already_present() -> None:
    line = format_channel_report(STABLE_BRANCH_INFO, False)
    assert "already present" in line


def test_report_failed_fetch_shows_error_and_reason() -> None:
    line = format_channel_report(STABLE_BRANCH_INFO, RuntimeError("connection refused"))
    assert "ERROR" in line
    assert "connection refused" in line


def test_report_none_release_version_falls_back_to_unstable_label() -> None:
    unstable_info = {**STABLE_BRANCH_INFO, "channel_branch": "nixos-unstable", "release_version": None}
    assert "unstable" in format_channel_report(unstable_info, False)


@pytest.mark.django_db
@patch("shared.management.commands.fetch_all_channels.fetch_from_monitoring")
@patch("shared.management.commands.fetch_all_channels.GitRepo")
def test_command_upserts_channels_and_reports_fetch_results(
    mock_git_repo_class: MagicMock,
    mock_fetch_monitoring: MagicMock,
) -> None:
    mock_fetch_monitoring.return_value = {
        "nixos-24.11": MonitoredChannel(name="nixos-24.11", revision="1234567890abcdef", status="stable"),
        "nixos-unstable": MonitoredChannel(name="nixos-unstable", revision="aabbcc0011223344", status="rolling"),
    }
    mock_git_repo_class.return_value.update_from_ref = AsyncMock(side_effect=[True, False])

    out = io.StringIO()
    call_command("fetch_all_channels", stdout=out)

    assert NixChannel.objects.get(channel_branch="nixos-24.11").state == NixChannel.ChannelState.STABLE
    assert NixChannel.objects.get(channel_branch="nixos-unstable").state == NixChannel.ChannelState.UNSTABLE

    output = out.getvalue()
    assert "nixos-24.11" in output and "fetched" in output
    assert "nixos-unstable" in output and "already present" in output
