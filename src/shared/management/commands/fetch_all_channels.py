import asyncio
import sys
from collections.abc import Coroutine
from typing import Any

import requests
from django.conf import settings
from django.core.management.base import BaseCommand

from shared.git import GitRepo
from shared.models.nix_evaluation import NixChannel


class MonitoredChannel:
    def __init__(self, name: str, revision: str, status: str) -> None:
        self.name = name
        self.revision = revision
        self.status = status


def release_from_branch(branch: str) -> str | None:
    """
    >>> release_from_branch("nixpkgs-23.05-darwin")
    23.05
    >>> release_from_branch("nixpkgs-23.11-darwin")
    23.11
    >>> release_from_branch("nixpkgs-23.05")
    23.05
    >>> release_from_branch("nixpkgs-unstable")
    None
    >>> release_from_branch("nixpkgs-unstable-small")
    None
    """
    parts = branch.split("-")
    if len(parts) < 2:
        return None

    ver = parts[1]
    if "." not in ver:
        return None

    return ver


def state_from_status(status: str) -> NixChannel.ChannelState:
    if status == "unmaintained":
        return NixChannel.ChannelState.END_OF_LIFE
    elif status == "deprecated":
        return NixChannel.ChannelState.DEPRECATED
    elif status == "beta":
        return NixChannel.ChannelState.BETA
    elif status == "stable":
        return NixChannel.ChannelState.STABLE
    elif status == "rolling":
        return NixChannel.ChannelState.UNSTABLE
    else:
        return NixChannel.ChannelState.STAGING


def staging_from_branch(branch: str) -> str:
    release_ver = release_from_branch(branch)
    if release_ver is None:
        return "master"
    else:
        return f"release-{release_ver}"


def aggregate_by_channels(data: list[dict[str, Any]]) -> dict[str, MonitoredChannel]:
    channels = {}
    for metric in data:
        m = metric["metric"]
        channels[m["channel"]] = MonitoredChannel(
            name=m["channel"], revision=m["revision"], status=m["status"]
        )
    return channels


def fetch_from_monitoring() -> dict[str, MonitoredChannel]:
    resp = requests.get(
        # XXX(@fricklerhandwerk): The sources for this are declared in the `NixOS/infra` repo. [tag:channel-structure]
        # exporter logic:
        # https://github.com/NixOS/infra/blob/795508213eb35eee099b1b8d12dd46a9f7b03697/build/pluto/prometheus/exporters/channel-exporter.py#L13-L17
        # systemd service:
        # https://github.com/NixOS/infra/blob/795508213eb35eee099b1b8d12dd46a9f7b03697/build/pluto/prometheus/exporters/channel.nix#L4-L6
        # channel structure:
        # https://github.com/NixOS/infra/blob/795508213eb35eee099b1b8d12dd46a9f7b03697/channels.nix
        settings.CHANNEL_MONITORING_URL
    )
    resp.raise_for_status()
    return aggregate_by_channels(resp.json()["data"]["result"])


async def wait_for_parallel_fetches(
    parallel_fetches: list[Coroutine[Any, Any, bool]],
) -> list[Any]:
    return await asyncio.gather(*parallel_fetches, return_exceptions=True)


def format_channel_report(
    branch_info: dict[str, Any], fetch_result: bool | BaseException
) -> str:
    channel = branch_info["channel_branch"]
    sha = branch_info["head_sha1_commit"][:12]
    state = branch_info["state"]
    release = branch_info.get("release_version") or "unstable"

    if isinstance(fetch_result, BaseException):
        status = f"ERROR ({fetch_result})"
    elif fetch_result:
        status = "fetched"
    else:
        status = "already present"

    return f"[{channel}] release={release} state={state} commit={sha} -> {status}"


class Command(BaseCommand):
    help = "Register Nix channels"

    def handle(self, *args: Any, **kwargs: Any) -> str | None:
        fresh_channels = fetch_from_monitoring()

        # Step 1: register/update all channels in the DB, collect for reporting.
        registered: list[tuple[NixChannel, dict[str, Any]]] = []
        for monitored in fresh_channels.values():
            branch_info: dict[str, Any] = {
                "channel_branch": monitored.name,
                "staging_branch": staging_from_branch(monitored.name),
                "state": state_from_status(monitored.status),
                "head_sha1_commit": monitored.revision,
                "release_version": release_from_branch(monitored.name),
            }
            channel, _ = NixChannel.objects.update_or_create(
                {
                    "staging_branch": branch_info["staging_branch"],
                    "state": branch_info["state"],
                    "head_sha1_commit": branch_info["head_sha1_commit"],
                    "release_version": branch_info["release_version"],
                },
                channel_branch=monitored.name,
            )
            registered.append((channel, branch_info))

        # Step 2: fetch all commits in parallel, preserving insertion order so
        # the results list aligns with `registered` for the zip below.
        repo = GitRepo(
            settings.LOCAL_NIXPKGS_CHECKOUT,
            stderr=sys.stderr.fileno(),
        )
        coros = [repo.update_from_ref(ch.head_sha1_commit) for ch, _ in registered]
        results = asyncio.run(wait_for_parallel_fetches(coros))

        # Step 3: unified per-channel report (one line per channel).
        for (_channel, branch_info), result in zip(registered, results):
            self.stdout.write(format_channel_report(branch_info, result))
