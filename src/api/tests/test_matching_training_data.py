from collections.abc import Callable

import pytest
from django.contrib.auth.models import User
from rest_framework.reverse import reverse
from rest_framework.test import APIClient

from shared.matching_training_data import (
    SCHEMA_VERSION,
    export_proposal,
    record_to_dict,
)
from shared.models.cve import Container
from shared.models.linkage import (
    CVEDerivationClusterProposal,
    PackageOverlay,
)


@pytest.fixture
def url() -> str:
    return reverse("matching-training-data")


@pytest.fixture
def curated_proposals(
    make_container: Callable[..., Container],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> dict[str, CVEDerivationClusterProposal]:
    pending = make_suggestion(
        container=make_container(cve_id="CVE-2026-pend"),
        status=CVEDerivationClusterProposal.Status.PENDING,
    )
    accepted = make_suggestion(
        container=make_container(cve_id="CVE-2026-acc"),
        status=CVEDerivationClusterProposal.Status.ACCEPTED,
        algorithm_version=1,
    )
    rejected = make_suggestion(
        container=make_container(cve_id="CVE-2026-rej"),
        status=CVEDerivationClusterProposal.Status.REJECTED,
        rejection_reason=CVEDerivationClusterProposal.RejectionReason.NOT_IN_NIXPKGS,
        algorithm_version=1,
    )
    auto_reject = make_suggestion(
        container=make_container(cve_id="CVE-2026-auto"),
        status=CVEDerivationClusterProposal.Status.REJECTED,
        rejection_reason=CVEDerivationClusterProposal.RejectionReason.NO_MATCHES,
        algorithm_version=1,
        drvs={},
    )
    PackageOverlay.objects.create(
        suggestion=accepted,
        package_attribute="foo.tests",
        type=PackageOverlay.Type.IGNORED,
    )
    return {
        "pending": pending,
        "accepted": accepted,
        "rejected": rejected,
        "auto_reject": auto_reject,
    }


def test_training_data_unauthenticated(url: str) -> None:
    response = APIClient().get(url)
    assert response.status_code == 401


@pytest.mark.parametrize("actor_fixture", ["user", "committer", "staff"])
def test_training_data_without_group_forbidden(
    url: str,
    actor_fixture: str,
    request: pytest.FixtureRequest,
) -> None:
    actor: User = request.getfixturevalue(actor_fixture)
    client = APIClient()
    client.force_login(actor)
    response = client.get(url)
    assert response.status_code == 403


def test_training_data_group_member_lists_curated_only(
    url: str,
    matching_training_user: User,
    curated_proposals: dict[str, CVEDerivationClusterProposal],
) -> None:
    client = APIClient()
    client.force_login(matching_training_user)
    response = client.get(url)
    assert response.status_code == 200
    assert response.data["count"] == 3

    cve_ids = {row["cve_id"] for row in response.data["results"]}
    assert "CVE-2026-pend" not in cve_ids
    assert cve_ids == {"CVE-2026-acc", "CVE-2026-rej", "CVE-2026-auto"}

    by_cve = {row["cve_id"]: row for row in response.data["results"]}
    assert by_cve["CVE-2026-auto"]["labels"]["status"] == "rejected"
    assert (
        by_cve["CVE-2026-auto"]["labels"]["rejection_reason"]
        == CVEDerivationClusterProposal.RejectionReason.NO_MATCHES
    )
    assert by_cve["CVE-2026-acc"]["schema_version"] == SCHEMA_VERSION
    assert by_cve["CVE-2026-acc"] == record_to_dict(
        export_proposal(curated_proposals["accepted"])
    )


def test_training_data_pagination(
    url: str,
    matching_training_user: User,
    make_container: Callable[..., Container],
    make_suggestion: Callable[..., CVEDerivationClusterProposal],
) -> None:
    for i in range(3):
        make_suggestion(
            container=make_container(cve_id=f"CVE-2026-page-{i}"),
            status=CVEDerivationClusterProposal.Status.ACCEPTED,
            algorithm_version=1,
        )

    client = APIClient()
    client.force_login(matching_training_user)

    page1 = client.get(url, {"page_size": 2, "page": 1})
    assert page1.status_code == 200
    assert page1.data["count"] == 3
    assert len(page1.data["results"]) == 2
    assert page1.data["next"] is not None

    page2 = client.get(url, {"page_size": 2, "page": 2})
    assert page2.status_code == 200
    assert len(page2.data["results"]) == 1
    assert page2.data["previous"] is not None
