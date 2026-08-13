"""
Audit history: compact storage and diffing between runs.

`history.json` previously stored four fields per run - org, timestamp, and a
single flat score - with no per-repository detail. That answers "did the
score change" but not "did *this* repository get better", which is what a
recurring audit is actually for: tracking progress on specific repositories
and specific checks over time.

This module builds a compact per-run record (check *statuses* only, not full
messages or guidance text, to keep history.json a reasonable size across many
runs) and computes the diff between two runs for the same organization.
"""

from typing import Any, Dict, List, Optional


def _repo_status_map(repo_checks: Dict[str, Any]) -> Dict[str, str]:
    """check_name -> status ('pass'/'fail'/'unknown'/'not_applicable') for one repository."""
    statuses = {}
    for name, result in repo_checks.get("details", {}).items():
        statuses[name] = result.get(
            "status", "pass" if result.get("passed") else "fail"
        )
    return statuses


def summarize_repository(repo_checks: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compact per-repository summary for one audit run: counts, weighted score,
    and the check-by-check status map that later runs are diffed against.
    """
    from compliance_mapping import severity_for, SEVERITY_WEIGHT

    statuses = _repo_status_map(repo_checks)
    passed = sum(1 for s in statuses.values() if s == "pass")
    failed = sum(1 for s in statuses.values() if s == "fail")
    evaluated = passed + failed

    weighted_passed = weighted_evaluated = 0
    for name, status in statuses.items():
        if status not in ("pass", "fail"):
            continue
        weight = SEVERITY_WEIGHT[severity_for(name)]
        weighted_evaluated += weight
        if status == "pass":
            weighted_passed += weight

    weighted_score = (
        round(weighted_passed / weighted_evaluated * 100, 2)
        if weighted_evaluated else 0.0
    )

    return {
        "passed": passed,
        "failed": failed,
        "evaluated": evaluated,
        "weighted_score": weighted_score,
        "statuses": statuses,
    }


def build_history_entry(results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compact record of one completed audit, suitable for `history.json`.

    Deliberately excludes full check messages, guidance text, and the access
    inventory (usernames) - history is for tracking trends across many runs,
    not for re-deriving a full report, and every field added here is
    multiplied by every run ever stored.
    """
    checks = results.get("checks", {})
    summary = results.get("summary", {})

    repositories = {
        name: summarize_repository(repo_checks)
        for name, repo_checks in checks.get("repositories", {}).items()
    }

    return {
        "org": results.get("organization"),
        "account_type": results.get("account_type"),
        "standard": results.get("standard_requested", "all"),
        "repository_scope": results.get("repository_scope"),
        "repository_visibility": results.get("repository_visibility"),
        "timestamp": results.get("timestamp"),
        "tool_version": results.get("tool_version"),
        "summary": {
            "compliance_score": summary.get("compliance_score"),
            "weighted_score": summary.get("weighted_score"),
            "risk_level": summary.get("risk_level"),
            "coverage_percent": summary.get("coverage_percent"),
            "severity_breakdown": summary.get("severity_breakdown"),
        },
        "repositories": repositories,
    }


def find_previous_run(
    history: Dict[str, Any],
    org_name: str,
    account_type: Optional[str],
    exclude_session_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Most recent prior run for the same organization, if any.

    Matches on organization name case-insensitively. Does not require the
    same account_type or the same repository scope to match - a run scoped
    to two repositories can still usefully be compared against a full-account
    run for the repositories they have in common; `diff_runs` reports the
    scope difference explicitly rather than refusing to compare.

    Entries with no "repositories" key (written by a version before this
    module existed) are skipped - there is nothing to diff against.
    """
    if not org_name:
        return None
    target = org_name.strip().lower()
    candidates = [
        (sid, entry) for sid, entry in history.items()
        if sid != exclude_session_id
        and isinstance(entry, dict)
        and "repositories" in entry
        and str(entry.get("org", "")).strip().lower() == target
        and entry.get("timestamp")
    ]
    if not candidates:
        return None
    sid, entry = max(candidates, key=lambda pair: pair[1]["timestamp"])
    return {"session_id": sid, **entry}


def diff_repository_statuses(
    previous: Dict[str, str], current: Dict[str, str]
) -> Dict[str, List[str]]:
    """
    Per-check status changes for one repository between two runs.

    Only "pass" and "fail" transitions are classified as regressions or
    improvements - a check moving to or from "unknown"/"not_applicable" is a
    coverage change (permissions, plan, or scope changed), not a security
    finding, and is reported separately rather than alongside real
    regressions.
    """
    newly_failing, newly_passing, coverage_changed = [], [], []
    all_checks = set(previous) | set(current)
    for name in sorted(all_checks):
        before = previous.get(name)
        after = current.get(name)
        if before == after:
            continue
        if after == "fail" and before in ("pass", None) and before != "fail":
            if before == "pass":
                newly_failing.append(name)
            elif before is None:
                coverage_changed.append(f"{name}: newly evaluated, currently failing")
        elif after == "pass" and before == "fail":
            newly_passing.append(name)
        elif before is not None and after is not None:
            coverage_changed.append(f"{name}: {before} \u2192 {after}")
    return {
        "newly_failing": newly_failing,
        "newly_passing": newly_passing,
        "coverage_changed": coverage_changed,
    }


def diff_runs(previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    """
    Full comparison between two audit runs for the same organization.

    Returns repository-level diffs plus which repositories are new or gone
    from the audited set since the previous run (distinct from a check
    regression - a repository disappearing from the list usually means it
    was archived, renamed, or the audit scope changed, not that its
    controls broke).
    """
    prev_repos = previous.get("repositories", {})
    curr_repos = current.get("repositories", {})

    new_repositories = sorted(set(curr_repos) - set(prev_repos))
    removed_repositories = sorted(set(prev_repos) - set(curr_repos))

    repository_diffs = {}
    for name in sorted(set(prev_repos) & set(curr_repos)):
        diff = diff_repository_statuses(
            prev_repos[name]["statuses"], curr_repos[name]["statuses"]
        )
        score_delta = round(
            curr_repos[name]["weighted_score"] - prev_repos[name]["weighted_score"], 2
        )
        if diff["newly_failing"] or diff["newly_passing"] or diff["coverage_changed"]:
            repository_diffs[name] = {**diff, "score_delta": score_delta}

    prev_summary = previous.get("summary", {})
    curr_summary = current.get("summary", {})
    weighted_delta = None
    if prev_summary.get("weighted_score") is not None and curr_summary.get("weighted_score") is not None:
        weighted_delta = round(curr_summary["weighted_score"] - prev_summary["weighted_score"], 2)

    return {
        "previous_session_id": previous.get("session_id"),
        "previous_timestamp": previous.get("timestamp"),
        "weighted_score_delta": weighted_delta,
        "new_repositories": new_repositories,
        "removed_repositories": removed_repositories,
        "repository_diffs": repository_diffs,
        "unchanged_repository_count": len(set(prev_repos) & set(curr_repos)) - len(repository_diffs),
    }
