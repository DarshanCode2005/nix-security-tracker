import io
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from django.core.management import call_command

from shared.management.commands.fetch_all_channels import MonitoredChannel
from shared.models.nix_evaluation import NixChannel


@pytest.mark.django_db
@patch("shared.management.commands.fetch_all_channels.fetch_from_monitoring")
@patch("shared.management.commands.fetch_all_channels.GitRepo")
@patch(
    "shared.management.commands.fetch_all_channels.asyncio.gather",
    new_callable=AsyncMock,
)
def test_command_upserts_channels_and_reports_fetch_results(
    mock_gather: AsyncMock,
    mock_git_repo_class: MagicMock,
    mock_fetch_monitoring: MagicMock,
) -> None:
    mock_fetch_monitoring.return_value = {
        "nixos-24.11": MonitoredChannel(
            name="nixos-24.11", revision="1234567890abcdef", status="stable"
        ),
        "nixos-unstable": MonitoredChannel(
            name="nixos-unstable", revision="aabbcc0011223344", status="rolling"
        ),
    }
    
    mock_gather.return_value = [True, False]

    out = io.StringIO()
    call_command("fetch_all_channels", stdout=out)

    assert (
        NixChannel.objects.get(channel_branch="nixos-24.11").state
        == NixChannel.ChannelState.STABLE
    )
    assert (
        NixChannel.objects.get(channel_branch="nixos-unstable").state
        == NixChannel.ChannelState.UNSTABLE
    )

    output = out.getvalue()
    assert "nixos-24.11" in output and "True" in output
    assert "nixos-unstable" in output and "False" in output
