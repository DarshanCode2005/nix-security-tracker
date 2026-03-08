import pytest

from shared.github import cvss_summary, severity_from_score


@pytest.mark.parametrize(
    "score,expected",
    [
        (9.0, "CRITICAL"),
        (8.9, "HIGH"),
        (7.0, "HIGH"),
        (6.9, "MEDIUM"),
        (4.0, "MEDIUM"),
        (3.9, "LOW"),
        (0.1, "LOW"),
        (0.0, "NONE"),
    ],
)
def test_severity_from_score(score: float, expected: str) -> None:
    assert severity_from_score(score) == expected


def test_cvss_summary_fallback_severity_from_score() -> None:
    summary = cvss_summary(
        {
            "baseScore": 7.5,
        }
    )

    assert summary == "> **Severity:** 🟠 High (7.5)\n\n"


def test_cvss_summary_uses_one_decimal_score_formatting() -> None:
    summary = cvss_summary(
        {
            "baseScore": 9.83,
            "baseSeverity": "CRITICAL",
        }
    )

    assert summary == "> **Severity:** 🔴 Critical (9.8)\n\n"


def test_cvss_summary_none_score_is_still_rendered_with_fallback() -> None:
    summary = cvss_summary(
        {
            "baseScore": 0.0,
        }
    )

    assert summary == "> **Severity:** ⚪ None (0.0)\n\n"


def test_cvss_summary_is_empty_without_usable_score() -> None:
    assert cvss_summary({}) == ""
    assert cvss_summary({"baseSeverity": "HIGH"}) == ""
    assert cvss_summary({"baseScore": "not-a-number", "baseSeverity": "HIGH"}) == ""
