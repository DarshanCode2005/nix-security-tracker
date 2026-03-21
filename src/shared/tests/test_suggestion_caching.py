from collections.abc import Callable
from datetime import timedelta

import pytest

from shared.listeners.cache_suggestions import (
    cache_new_suggestions,
    is_version_affected,
)
from shared.models.cached import CachedSuggestions
from shared.models.cve import Container, Version
from shared.models.linkage import (
    CVEDerivationClusterProposal,
    DerivationClusterProposalLink,
    ProvenanceFlags,
)
from shared.models.nix_evaluation import (
    NixChannel,
    NixDerivation,
    NixEvaluation,
)


# The Pydantic class for the cached value gives us some assurance about the shape of the data, but ultimately we probabyly want property tests here.
def test_caching_newest_package(
    cve: Container,
    make_channel: Callable[..., NixChannel],
    make_evaluation: Callable[..., NixEvaluation],
    make_drv: Callable[..., NixDerivation],
    suggestion: CVEDerivationClusterProposal,
) -> None:
    """
    Check that when aggregating derivations from a suggestion, only the newest one for a given package name (== attribute path) is used.
    """

    # Order of creation matters for triggering the bug.
    # This is brittle because it assumes things about the database, but it seems that derivations are scanned in insertion order of their evaluations.
    eval_new = make_evaluation()
    eval_old = make_evaluation()
    # Overwrite the timestamp without triggering the `save()` hook that would write the current time again
    target_time = eval_old.created_at - timedelta(hours=1)
    NixEvaluation.objects.filter(pk=eval_old.pk).update(
        created_at=target_time,
        updated_at=target_time,
    )
    # Use different versions. We'll assert over those since that's what's primarily visible to users
    drv2 = make_drv(evaluation=eval_new, version="2.0")
    drv1 = make_drv(evaluation=eval_old, version="1.0")

    suggestion = CVEDerivationClusterProposal.objects.create(
        status="pending",
        cve=cve.cve,
    )

    DerivationClusterProposalLink.objects.create(
        proposal=suggestion,
        derivation=drv1,
        provenance_flags=ProvenanceFlags.PACKAGE_NAME_MATCH,
    )

    DerivationClusterProposalLink.objects.create(
        proposal=suggestion,
        derivation=drv2,
        provenance_flags=ProvenanceFlags.PACKAGE_NAME_MATCH,
    )

    cached = CachedSuggestions.objects.filter(proposal=suggestion)
    assert not cached.exists()
    cache_new_suggestions(suggestion)
    value = cached.get()
    assert cve.cve.cve_id == value.payload["cve_id"]

    channel, package = next(
        iter(value.payload["packages"][drv1.attribute]["channels"].items())
    )

    assert package["major_version"] == "2.0"


@pytest.mark.parametrize(
    "statuses, expected",
    [
        ([], Version.Status.UNKNOWN),
        ([Version.Status.AFFECTED], Version.Status.AFFECTED),
        ([Version.Status.UNAFFECTED], Version.Status.UNKNOWN),
        ([Version.Status.UNKNOWN], Version.Status.UNKNOWN),
        ([Version.Status.AFFECTED, Version.Status.AFFECTED], Version.Status.AFFECTED),
        ([Version.Status.AFFECTED, Version.Status.UNAFFECTED], Version.Status.AFFECTED),
        ([Version.Status.AFFECTED, Version.Status.UNKNOWN], Version.Status.AFFECTED),
        ([Version.Status.UNAFFECTED, Version.Status.AFFECTED], Version.Status.AFFECTED),
        (
            [Version.Status.UNAFFECTED, Version.Status.UNAFFECTED],
            Version.Status.UNKNOWN,
        ),
        ([Version.Status.UNAFFECTED, Version.Status.UNKNOWN], Version.Status.UNKNOWN),
        ([Version.Status.UNKNOWN, Version.Status.AFFECTED], Version.Status.AFFECTED),
        ([Version.Status.UNKNOWN, Version.Status.UNAFFECTED], Version.Status.UNKNOWN),
        ([Version.Status.UNKNOWN, Version.Status.UNKNOWN], Version.Status.UNKNOWN),
        (
            [
                Version.Status.AFFECTED,
                Version.Status.UNAFFECTED,
                Version.Status.UNKNOWN,
            ],
            Version.Status.AFFECTED,
        ),
        (
            [
                Version.Status.UNAFFECTED,
                Version.Status.UNAFFECTED,
                Version.Status.UNAFFECTED,
            ],
            Version.Status.UNKNOWN,
        ),
    ],
)
def test_is_version_affected(statuses: list[str], expected: Version.Status) -> None:
    assert is_version_affected(statuses) == expected
