"""
Regression tests for the check engine.

The single most important assertion in this file is
`test_hardened_repo_scores_100_percent`. Every P0 defect found in the v1.2.2
review would have been caught by it alone.
"""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checks import (  # noqa: E402
    SecurityChecker, PASS, FAIL, UNKNOWN, NOT_APPLICABLE,
)
from github_auditor import GitHubAuditor  # noqa: E402


# ---------------------------------------------------------------------------
# Fakes shaped like the PyGithub objects the checker actually touches
# ---------------------------------------------------------------------------

class FakeContent:
    def __init__(self, text: str):
        self.decoded_content = text.encode()


class FakeReviews:
    def __init__(self, count=2, dismiss_stale=True, code_owner=True):
        self.required_approving_review_count = count
        self.dismiss_stale_reviews = dismiss_stale
        self.require_code_owner_reviews = code_owner


class FakeStatusChecks:
    def __init__(self, contexts=("ci/build",)):
        self.contexts = list(contexts)


class FakeProtection:
    def __init__(self, reviews=None, status_checks=None, enforce_admins=True,
                 linear=True, force_push=False, deletions=False):
        self.required_pull_request_reviews = reviews
        self.required_status_checks = status_checks
        self.enforce_admins = enforce_admins
        self.required_linear_history = linear
        self.raw_data = {
            "allow_force_pushes": {"enabled": force_push},
            "allow_deletions": {"enabled": deletions},
        }


class FakeBranch:
    def __init__(self, protected=True, protection=None, signatures=True):
        self.name = "main"
        self.protected = protected
        self._protection = protection
        self._signatures = signatures

    def get_protection(self):
        if self._protection is None:
            raise Exception("404")
        return self._protection

    def get_required_signatures(self):
        return self._signatures


class FakeRequester:
    def __init__(self, rules=None, actions=None, rulesets=None):
        self._rules = rules
        self._actions = actions or {}
        self._rulesets = rulesets

    def requestJsonAndCheck(self, _method, url):
        if url.endswith("/rulesets"):
            if self._rulesets is None:
                raise Exception("403")
            return {}, self._rulesets
        if "/actions/permissions/workflow" in url:
            if "workflow" not in self._actions:
                raise Exception("403")
            return {}, self._actions["workflow"]
        if "/actions/permissions" in url:
            if "permissions" not in self._actions:
                raise Exception("403")
            return {}, self._actions["permissions"]
        if "/rules/branches/" in url:
            if self._rules is None:
                raise Exception("404")
            return {}, self._rules
        raise Exception("404")


class FakeDirEntry:
    def __init__(self, path, text):
        self.path = path
        self.decoded_content = text.encode()


class FakeRepo:
    def __init__(self, name="app", private=True, branch=None, files=None,
                 security=None, vuln_alerts=True, archived=False, pushed_days_ago=3,
                 rules=None, workflows=None, actions=None, rulesets=None,
                 collaborators=None, direct=(), teams=()):
        self.name = name
        self.private = private
        self.archived = archived
        self.default_branch = "main"
        self.pushed_at = datetime.now(timezone.utc) - timedelta(days=pushed_days_ago)
        self._branch = branch
        self._files = files or {}
        self.raw_data = {"security_and_analysis": security} if security else {}
        self._vuln_alerts = vuln_alerts
        self.url = f"https://api.github.com/repos/acme/{name}"
        self._requester = FakeRequester(rules, actions, rulesets)
        self._workflows = workflows or {}
        self._collaborators = collaborators
        self._direct = set(direct)
        self._teams = list(teams)

    def get_branch(self, _name):
        if self._branch is None:
            raise Exception("404")
        return self._branch

    def get_contents(self, path):
        if path == ".github/workflows":
            if not self._workflows:
                raise Exception("404")
            return [FakeDirEntry(f".github/workflows/{n}", c)
                    for n, c in self._workflows.items()]
        if path in self._files:
            return FakeContent(self._files[path])
        raise Exception("404")

    def get_vulnerability_alert(self):
        return self._vuln_alerts

    def get_collaborators(self, affiliation=None):
        if self._collaborators is None:
            raise Exception("403")
        if affiliation == "direct":
            return [c for c in self._collaborators if c.login in self._direct]
        return list(self._collaborators)

    def get_teams(self):
        return list(self._teams)


class FakePermissions:
    def __init__(self, level):
        for name in ("pull", "triage", "push", "maintain", "admin"):
            setattr(self, name, False)
        order = ("pull", "triage", "push", "maintain", "admin")
        for name in order[: order.index(level) + 1]:
            setattr(self, name, True)


class FakeCollaborator:
    def __init__(self, login, level="pull", account_type="User"):
        self.login = login
        self.type = account_type
        self.permissions = FakePermissions(level)


class FakeTeam:
    def __init__(self, slug, permission="push"):
        self.slug = slug
        self.name = slug
        self.permission = permission


class FakeOrg:
    url = "https://api.github.com/orgs/acme"

    def __init__(self, two_factor=True, default_permission="read", can_create=False,
                 actions=None, owners=("alice", "bob"), outside=()):
        self._requester = FakeRequester(actions=actions)
        self._owners = owners
        self._outside = outside
        self.two_factor_requirement_enabled = two_factor
        self.default_repository_permission = default_permission
        self.members_can_create_repositories = can_create

    def get_members(self, role=None):
        if role == "admin":
            if self._owners is None:
                raise Exception("403")
            return [FakeCollaborator(login) for login in self._owners]
        return []

    def get_outside_collaborators(self):
        if self._outside is None:
            raise Exception("403")
        return [FakeCollaborator(login) for login in self._outside]


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

SAFE_WORKFLOW = """
name: CI
on:
  pull_request:
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: tj-actions/changed-files@2f7c5bfce28377bc069a65ba478de0a74aa0ca32
"""

SAFE_RELEASE_WORKFLOW = """
name: Release
on:
  release:
    types: [published]
permissions:
  contents: read
  id-token: write
  attestations: write
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/attest-build-provenance@897ed5eab6ed058a474202017ada7f40bfa52940
"""

RISKY_WORKFLOW = """
name: CI
on:
  pull_request_target:
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: tj-actions/changed-files@v35
"""

RISKY_RELEASE_WORKFLOW = """
name: Release
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
"""


def hardened_repo() -> FakeRepo:
    """A repository with every auditable control correctly configured."""
    return FakeRepo(
        branch=FakeBranch(
            protected=True,
            protection=FakeProtection(
                reviews=FakeReviews(),
                status_checks=FakeStatusChecks(),
            ),
        ),
        files={
            "SECURITY.md": "# Security policy",
            "CODEOWNERS": "* @team",
            ".gitignore": ".env\n*.pem\n",
        },
        security={
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "enabled"},
        },
        vuln_alerts=True,
        actions={"workflow": {"default_workflow_permissions": "read",
                              "can_approve_pull_request_reviews": False},
                 "permissions": {"enabled": True, "allowed_actions": "selected",
                                 "sha_pinning_required": True,
                                 "fork_pr_workflows_policy": False}},
        workflows={"ci.yml": SAFE_WORKFLOW, "release.yml": SAFE_RELEASE_WORKFLOW},
        rulesets=[{"name": "main", "enforcement": "active"}],
    )


def wide_open_repo() -> FakeRepo:
    """A public repository with nothing configured."""
    return FakeRepo(
        name="internal-deploy",
        private=False,
        branch=FakeBranch(protected=False),
        files={},
        security={
            "secret_scanning": {"status": "disabled"},
            "secret_scanning_push_protection": {"status": "disabled"},
        },
        vuln_alerts=False,
        pushed_days_ago=900,
        actions={"workflow": {"default_workflow_permissions": "write",
                              "can_approve_pull_request_reviews": True},
                 "permissions": {"enabled": True, "allowed_actions": "all",
                                 "sha_pinning_required": False,
                                 "approval_policy": "first_time_contributors_new_to_github"}},
        workflows={"ci.yml": RISKY_WORKFLOW, "release.yml": RISKY_RELEASE_WORKFLOW},
        rulesets=[{"name": "draft", "enforcement": "disabled"}],
    )


def score(bucket) -> float:
    evaluated = bucket["passed"] + bucket["failed"]
    return round(bucket["passed"] / evaluated * 100, 2) if evaluated else 0.0


# ---------------------------------------------------------------------------
# The tests that matter
# ---------------------------------------------------------------------------

def test_hardened_repo_scores_100_percent():
    """No check may be unreachable. A perfect repo must score 100%."""
    result = SecurityChecker(org=None).check_repository(hardened_repo())
    failures = {
        name: r["message"]
        for name, r in result["details"].items()
        if r["status"] == FAIL
    }
    assert failures == {}, f"hardened repo should not fail anything: {failures}"
    assert score(result) == 100.0


def test_wide_open_repo_scores_near_zero():
    result = SecurityChecker(org=None).check_repository(wide_open_repo())
    assert score(result) <= 10.0, result["details"]


def test_score_range_is_meaningful():
    """Guards against the v1.2.2 defect where the range collapsed to 28-56%."""
    high = score(SecurityChecker(org=None).check_repository(hardened_repo()))
    low = score(SecurityChecker(org=None).check_repository(wide_open_repo()))
    assert high - low >= 80.0


def test_no_check_is_hardcoded_to_a_constant():
    """Every check must distinguish the hardened repo from the open one."""
    good = SecurityChecker(org=None).check_repository(hardened_repo())["details"]
    bad = SecurityChecker(org=None).check_repository(wide_open_repo())["details"]
    constant = [
        name for name in good
        if good[name]["status"] == bad[name]["status"] not in (UNKNOWN, NOT_APPLICABLE)
    ]
    assert constant == [], f"checks that never change verdict: {constant}"


def test_missing_permission_is_unknown_not_failure():
    """A 403 must not be reported as a security finding."""
    repo = FakeRepo(branch=None)  # get_branch raises
    result = SecurityChecker(org=None).check_repository(repo)
    for name in ["Pull Request Reviews", "Status Checks Before Merge",
                 "Admin Bypass Prevention", "Linear History Required"]:
        assert result["details"][name]["status"] == UNKNOWN, name


DEPENDENT_CHECKS = [
    "Pull Request Reviews", "Status Checks Before Merge", "Commit Signing",
    "Dismiss Stale PR Reviews", "Code Owner Reviews", "Admin Bypass Prevention",
    "Linear History Required", "Force Push Protection", "Branch Deletion Protection",
]


def test_missing_protection_produces_one_finding_not_ten():
    """
    A single missing setting must not be counted ten times. The root cause
    fails; the nine controls that depend on it are excluded from the score.
    """
    repo = FakeRepo(branch=FakeBranch(protected=False))
    details = SecurityChecker(org=None).check_repository(repo)["details"]

    assert details["Branch Protection Rules"]["status"] == FAIL
    for name in DEPENDENT_CHECKS:
        assert details[name]["status"] == NOT_APPLICABLE, name
        assert "Branch Protection Rules" in details[name]["message"] or \
               "branch protection" in details[name]["message"].lower()


def test_dependent_checks_do_not_dominate_the_score():
    """Regression: branch protection used to drive 10 of 18 repo checks."""
    repo = FakeRepo(branch=FakeBranch(protected=False))
    r = SecurityChecker(org=None).check_repository(repo)
    details = r["details"]

    excluded = sum(
        1 for n in DEPENDENT_CHECKS if details[n]["status"] == NOT_APPLICABLE
    )
    assert excluded == len(DEPENDENT_CHECKS)

    evaluated = r["passed"] + r["failed"]
    scored_from_protection = sum(
        1 for n in DEPENDENT_CHECKS + ["Branch Protection Rules"]
        if details[n]["status"] in (PASS, FAIL)
    )
    assert scored_from_protection == 1, "one setting must produce one scored finding"
    assert scored_from_protection / evaluated < 0.3


def test_ruleset_only_repo_is_recognised_as_protected():
    """A repo governed by a ruleset used to read as completely unprotected."""
    repo = FakeRepo(
        branch=FakeBranch(protected=True, protection=None),
        rules=[
            {"type": "pull_request", "parameters": {
                "required_approving_review_count": 2,
                "dismiss_stale_reviews_on_push": True,
                "require_code_owner_review": True}},
            {"type": "required_status_checks", "parameters": {
                "required_status_checks": [{"context": "ci/build"}]}},
            {"type": "required_linear_history"},
            {"type": "required_signatures"},
            {"type": "non_fast_forward"},
            {"type": "deletion"},
        ],
    )
    details = SecurityChecker(org=None).check_repository(repo)["details"]
    assert details["Branch Protection Rules"]["status"] == PASS
    assert "ruleset" in details["Branch Protection Rules"]["message"]
    for name in ["Pull Request Reviews", "Status Checks Before Merge",
                 "Commit Signing", "Linear History Required",
                 "Force Push Protection", "Branch Deletion Protection",
                 "Code Owner Reviews", "Dismiss Stale PR Reviews"]:
        assert details[name]["status"] == PASS, (name, details[name]["message"])


def test_free_plan_private_repo_is_not_applicable():
    """
    Branch protection cannot be configured on a private repo under GitHub Free.
    Blaming the user for it is the same defect as counting a 403 as a failure.
    """
    repo = FakeRepo(private=True, branch=FakeBranch(protected=False))
    details = SecurityChecker(org=None, plan_name="free").check_repository(repo)["details"]
    assert details["Branch Protection Rules"]["status"] == NOT_APPLICABLE
    for name in DEPENDENT_CHECKS:
        assert details[name]["status"] == NOT_APPLICABLE, name


def test_free_plan_public_repo_is_still_graded():
    repo = FakeRepo(private=False, branch=FakeBranch(protected=False))
    details = SecurityChecker(org=None, plan_name="free").check_repository(repo)["details"]
    assert details["Branch Protection Rules"]["status"] == FAIL


def test_unknown_checks_are_excluded_from_score():
    summary = GitHubAuditor._calculate_summary(
        GitHubAuditor.__new__(GitHubAuditor),
        {"organization": {"passed": 3, "failed": 1, "unknown": 6,
                          "not_applicable": 9}},
    )
    assert summary["compliance_score"] == 75.0
    assert summary["evaluated_checks"] == 4
    assert summary["unknown_checks"] == 6
    assert summary["not_applicable_checks"] == 9


def test_risk_bands_are_reachable():
    assert GitHubAuditor._get_risk_level(100.0) == "LOW RISK"
    assert GitHubAuditor._get_risk_level(75.0) == "MEDIUM RISK"
    assert GitHubAuditor._get_risk_level(10.0) == "CRITICAL RISK"


# -- organization ------------------------------------------------------------

def test_org_checks_react_to_settings():
    good = SecurityChecker(FakeOrg()).check_organization_settings()["details"]
    bad = SecurityChecker(
        FakeOrg(two_factor=False, default_permission="write", can_create=True)
    ).check_organization_settings()["details"]

    assert good["2FA Enforcement"]["status"] == PASS
    assert bad["2FA Enforcement"]["status"] == FAIL
    assert good["Default Repository Permission"]["status"] == PASS
    assert bad["Default Repository Permission"]["status"] == FAIL
    assert good["Member Repository Creation"]["status"] == PASS
    assert bad["Member Repository Creation"]["status"] == FAIL


def test_org_settings_invisible_to_non_owner_are_unknown():
    org = FakeOrg(two_factor=None, default_permission=None, can_create=None)
    details = SecurityChecker(org).check_organization_settings()["details"]
    assert details["2FA Enforcement"]["status"] == UNKNOWN
    assert details["Default Repository Permission"]["status"] == UNKNOWN


# -- individual controls -----------------------------------------------------

@pytest.mark.parametrize("enabled,expected", [(True, PASS), (False, FAIL)])
def test_secret_scanning_reflects_api(enabled, expected):
    repo = FakeRepo(
        security={"secret_scanning": {"status": "enabled" if enabled else "disabled"}}
    )
    result = SecurityChecker(org=None)._check_secrets_scanning(repo)
    assert result["status"] == expected


def test_secret_scanning_without_admin_is_unknown():
    result = SecurityChecker(org=None)._check_secrets_scanning(FakeRepo(security=None))
    assert result["status"] == UNKNOWN


@pytest.mark.parametrize("enabled,expected", [(True, PASS), (False, FAIL)])
def test_dependency_alerts_reflect_api(enabled, expected):
    repo = FakeRepo(vuln_alerts=enabled)
    assert SecurityChecker(org=None)._check_dependency_scanning(repo)["status"] == expected


def test_stale_repository_is_flagged():
    active = SecurityChecker(org=None)._check_activity(FakeRepo(pushed_days_ago=10))
    stale = SecurityChecker(org=None)._check_activity(FakeRepo(pushed_days_ago=800))
    archived = SecurityChecker(org=None)._check_activity(FakeRepo(archived=True))
    assert active["status"] == PASS
    assert stale["status"] == FAIL
    assert archived["status"] == PASS


def test_gitignore_requires_secret_patterns():
    with_secrets = FakeRepo(files={".gitignore": "__pycache__/\n.env\n"})
    without = FakeRepo(files={".gitignore": "__pycache__/\n*.pyc\n"})
    assert SecurityChecker(org=None)._check_gitignore(with_secrets)["status"] == PASS
    assert SecurityChecker(org=None)._check_gitignore(without)["status"] == FAIL


def test_security_md_found_in_github_directory():
    repo = FakeRepo(files={".github/SECURITY.md": "policy"})
    assert SecurityChecker(org=None)._check_security_md(repo)["status"] == PASS


def test_public_repo_with_sensitive_name_fails_visibility():
    checker = SecurityChecker(org=None)
    assert checker._check_visibility(FakeRepo(private=True))["status"] == PASS
    assert checker._check_visibility(
        FakeRepo(name="internal-secrets", private=False)
    )["status"] == FAIL


# -- compliance mapping ------------------------------------------------------

def test_every_check_has_a_compliance_mapping():
    """A check with no mapping is silently dropped from the report."""
    from compliance_mapping import COMPLIANCE_MAPPING

    checker = SecurityChecker(FakeOrg())
    names = set(checker.check_organization_settings()["details"])
    names |= set(checker.check_repository(hardened_repo())["details"])

    missing = sorted(names - set(COMPLIANCE_MAPPING))
    assert missing == [], f"checks with no compliance mapping: {missing}"

    orphaned = sorted(set(COMPLIANCE_MAPPING) - names)
    assert orphaned == [], f"mappings for checks that do not exist: {orphaned}"


def test_iso_mapping_uses_2022_numbering():
    """ISO 27001:2013 used A.5-A.18; the 2022 revision uses A.5-A.8 only."""
    from compliance_mapping import COMPLIANCE_MAPPING

    stale = []
    for name, mapping in COMPLIANCE_MAPPING.items():
        for control in mapping.get("iso27001", {}).get("controls", []):
            clause = int(control.split(".")[1])
            if clause > 8:
                stale.append(f"{name}: {control}")
    assert stale == [], f"ISO 27001:2013 control numbers still present: {stale}"


def test_unknown_results_are_not_compliance_gaps():
    from compliance_mapping import calculate_compliance_scores

    audit = {"checks": {"organization": {"details": {
        "2FA Enforcement": {"status": UNKNOWN, "passed": False, "message": ""},
        "Audit Logging": {"status": PASS, "passed": True, "message": ""},
    }}}}
    scores = calculate_compliance_scores(audit)
    assert scores["soc2"]["total"] == 1
    assert scores["soc2"]["percentage"] == 100.0


# -- report rendering --------------------------------------------------------

def test_html_report_renders_from_a_real_result_shape():
    """
    Regression: `html` the module was shadowed by `html` the local variable,
    so every HTML report raised UnboundLocalError and the endpoint returned 500.
    """
    from report_generator import ReportGenerator

    checker = SecurityChecker(FakeOrg())
    results = {
        "organization": "acme",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": {
            "organization": checker.check_organization_settings(),
            "repositories": {
                "hardened": checker.check_repository(hardened_repo()),
                "wide-open": checker.check_repository(wide_open_repo()),
            },
        },
    }
    results["summary"] = GitHubAuditor._calculate_summary(
        GitHubAuditor.__new__(GitHubAuditor), results["checks"]
    )

    class Cfg:
        org_name = "acme"

    report = ReportGenerator(Cfg())
    assert len(report.generate_html_report(results)) > 1000
    assert len(report.generate_json_report(results)) > 100


def test_html_report_escapes_hostile_names():
    """A GitHub display name accepts arbitrary characters."""
    from report_generator import ReportGenerator

    checker = SecurityChecker(FakeOrg())
    payload = '<img src=x onerror=alert(1)>'
    results = {
        "organization": payload,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": {
            "organization": checker.check_organization_settings(),
            "repositories": {payload: checker.check_repository(hardened_repo())},
        },
    }
    results["summary"] = GitHubAuditor._calculate_summary(
        GitHubAuditor.__new__(GitHubAuditor), results["checks"]
    )

    class Cfg:
        org_name = payload

    html_out = ReportGenerator(Cfg()).generate_html_report(results)
    assert "<img src=x onerror" not in html_out
    assert "&lt;img src=x onerror" in html_out


# -- GitHub Actions supply chain ---------------------------------------------

def actions_checker(**org_kwargs):
    return SecurityChecker(FakeOrg(**org_kwargs))


def test_unpinned_third_party_action_fails():
    """The tj-actions/changed-files compromise ran through exactly this."""
    checker = SecurityChecker(org=None)
    bad = checker._check_action_pinning({"ci.yml": RISKY_WORKFLOW})
    good = checker._check_action_pinning({"ci.yml": SAFE_WORKFLOW})
    assert bad["status"] == FAIL
    assert "tj-actions/changed-files@v35" in bad["message"]
    assert good["status"] == PASS


def test_first_party_tag_does_not_fail_pinning():
    """A GitHub-owned action on a tag is noted, not counted as a finding."""
    wf = "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n"
    r = SecurityChecker(org=None)._check_action_pinning({"ci.yml": wf})
    assert r["status"] == PASS
    assert "GitHub-owned" in r["message"]


def test_pull_request_target_with_pr_checkout_fails():
    checker = SecurityChecker(org=None)
    assert checker._check_untrusted_triggers({"ci.yml": RISKY_WORKFLOW})["status"] == FAIL
    assert checker._check_untrusted_triggers({"ci.yml": SAFE_WORKFLOW})["status"] == PASS


def test_self_hosted_runner_only_fails_on_public_repos():
    checker = SecurityChecker(org=None)
    public = FakeRepo(private=False, workflows={"ci.yml": RISKY_WORKFLOW})
    private = FakeRepo(private=True, workflows={"ci.yml": RISKY_WORKFLOW})
    assert checker._check_self_hosted_runners(
        public, {"ci.yml": RISKY_WORKFLOW})["status"] == FAIL
    assert checker._check_self_hosted_runners(
        private, {"ci.yml": RISKY_WORKFLOW})["status"] == PASS


def test_missing_permissions_block_fails():
    checker = SecurityChecker(org=None)
    assert checker._check_workflow_permissions_declared(
        {"ci.yml": RISKY_WORKFLOW})["status"] == FAIL
    assert checker._check_workflow_permissions_declared(
        {"ci.yml": SAFE_WORKFLOW})["status"] == PASS


def test_build_provenance_only_applies_to_publishing_workflows():
    checker = SecurityChecker(org=None)
    assert checker._check_build_provenance(
        {"r.yml": RISKY_RELEASE_WORKFLOW})["status"] == FAIL
    assert checker._check_build_provenance(
        {"r.yml": SAFE_RELEASE_WORKFLOW})["status"] == PASS
    assert checker._check_build_provenance(
        {"ci.yml": SAFE_WORKFLOW})["status"] == NOT_APPLICABLE


def test_repo_without_workflows_is_not_penalised():
    """No Actions usage is not a security failure."""
    details = SecurityChecker(org=None).check_repository(FakeRepo())["details"]
    for name in ["Action Version Pinning", "Workflow Permissions Declared",
                 "Untrusted Workflow Triggers", "Self-Hosted Runner Exposure",
                 "Build Provenance Attestation"]:
        assert details[name]["status"] == NOT_APPLICABLE, name


def test_org_actions_policy_reacts_to_settings():
    good = actions_checker(actions={
        "permissions": {"allowed_actions": "selected"},
        "workflow": {"default_workflow_permissions": "read",
                     "can_approve_pull_request_reviews": False},
    }).check_organization_settings()["details"]
    bad = actions_checker(actions={
        "permissions": {"allowed_actions": "all"},
        "workflow": {"default_workflow_permissions": "write",
                     "can_approve_pull_request_reviews": True},
    }).check_organization_settings()["details"]

    for name in ["Actions Allowed Actions Policy", "Actions Default Token Permissions",
                 "Actions Pull Request Approval"]:
        assert good[name]["status"] == PASS, name
        assert bad[name]["status"] == FAIL, name


def test_org_actions_without_owner_access_is_unknown():
    details = actions_checker().check_organization_settings()["details"]
    assert details["Actions Allowed Actions Policy"]["status"] == UNKNOWN


# -- framework labels --------------------------------------------------------

def test_framework_labels_are_current():
    """
    Regression guard for stale standard references:
      - SOC 2 Type I/II is a report type, not a criteria set
      - ISO 27001:2013 Annex A numbering was retired in October 2025
      - CIS Controls v8.1 superseded v8 in June 2024
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    offenders = []
    for path in list(root.glob("*.py")) + list(root.glob("*.md")):
        if path.name == "CHANGELOG.md":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for bad in ("SOC 2 Type II", "SOC2 Type II", "ISO/IEC 27001:2013",
                    "GitHub Advanced Security"):
            if bad in text:
                offenders.append(f"{path.name}: {bad}")
    assert offenders == [], offenders


def test_check_count_claims_match_the_code():
    """Documentation drifted to a wrong count once already."""
    import pathlib
    import re as _re

    checker = SecurityChecker(FakeOrg())
    total = (checker.check_organization_settings()["total"]
             + checker.check_repository(hardened_repo())["total"])

    root = pathlib.Path(__file__).resolve().parent.parent
    wrong = []
    for path in list(root.glob("*.py")) + list(root.glob("*.md")):
        if path.name in ("CHANGELOG.md",) or path.name.startswith("test_"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in _re.finditer(r"(\d+)\s+security (?:checks|controls)", text):
            if int(match.group(1)) != total:
                wrong.append(f"{path.name}: claims {match.group(1)}, actual {total}")
    assert wrong == [], wrong


# -- rulesets verified against live GitHub responses -------------------------
#
# The fixtures in tests/fixtures/ are real /repos/{o}/{r}/rules/branches/{b}
# responses captured from public repositories. Previous versions of these tests
# asserted against invented payloads, which proves only that the code agrees
# with itself.

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def load_fixture(name):
    return json.loads((FIXTURES / f"rules_{name}.json").read_text())


@pytest.mark.parametrize("name", [
    "rust-lang_rust", "github_docs", "microsoft_vscode",
    "actions_checkout", "cli_cli",
])
def test_live_ruleset_payloads_parse(name):
    """Every rule type seen in the wild must be understood, not skipped."""
    from checks import ProtectionFacts

    facts = ProtectionFacts()
    assert facts.apply_rules(load_fixture(name)) is True, name


def test_live_payload_pull_request_parameters():
    """Field names taken from the real microsoft/vscode response."""
    from checks import ProtectionFacts

    facts = ProtectionFacts()
    facts.apply_rules(load_fixture("microsoft_vscode"))
    assert facts.review_count == 1
    assert facts.code_owner_review is True
    assert facts.last_push_approval is True
    assert facts.block_deletion is True       # "deletion" rule present
    assert facts.block_force_push is True     # "non_fast_forward" rule present
    assert facts.org_enforced is True         # ruleset_source_type: Organization


def test_live_payload_status_check_contexts():
    from checks import ProtectionFacts

    facts = ProtectionFacts()
    facts.apply_rules(load_fixture("github_docs"))
    assert facts.status_contexts, "required_status_checks contexts were not extracted"
    assert all(isinstance(c, str) for c in facts.status_contexts)


def test_repository_scoped_rules_are_not_branch_protection():
    """
    Regression from live data: /rules/branches/{b} also returns organization
    repository rules (repository_visibility, repository_create, ...). Treating
    those as branch protection marked the branch protected and then failed
    every dependent control. Shape observed on hashicorp/terraform.
    """
    from checks import ProtectionFacts

    facts = ProtectionFacts()
    assert facts.apply_rules(load_fixture("repository_rules_only")) is False


def test_ruleset_without_classic_protection_is_detected():
    """
    microsoft/vscode has active ruleset rules while the branch reports
    protected=None and exposes no classic protection URL.
    """
    repo = FakeRepo(
        branch=FakeBranch(protected=False),
        rules=load_fixture("microsoft_vscode"),
    )
    details = SecurityChecker(org=None).check_repository(repo)["details"]
    assert details["Branch Protection Rules"]["status"] == PASS
    assert "ruleset" in details["Branch Protection Rules"]["message"]
    assert details["Pull Request Reviews"]["status"] == PASS
    assert details["Code Owner Reviews"]["status"] == PASS


# -- plan-based enforcement (verified from the GitHub UI) --------------------
#
# GitHub allows a ruleset to be created on a private repository under a free
# plan and then does not enforce it:
#   "Your rulesets won't be enforced on this private repository until you
#    move to GitHub Team organization account."

def test_configured_but_unenforced_ruleset_is_a_finding_not_a_pass():
    """
    The dangerous case: rules exist, the API returns them, the branch is not
    actually protected. Reporting PASS here would manufacture false confidence.
    """
    repo = FakeRepo(
        private=True,
        branch=FakeBranch(protected=False),
        rules=load_fixture("microsoft_vscode"),
    )
    details = SecurityChecker(org=None, plan_name="free").check_repository(repo)["details"]
    root = details["Branch Protection Rules"]

    assert root["status"] == FAIL
    assert "NOT ENFORCED" in root["message"]
    for name in DEPENDENT_CHECKS:
        assert details[name]["status"] == NOT_APPLICABLE, name


def test_private_repo_with_no_rules_on_free_plan_is_not_blamed():
    repo = FakeRepo(private=True, branch=FakeBranch(protected=False), rules=None)
    details = SecurityChecker(org=None, plan_name="free").check_repository(repo)["details"]
    assert details["Branch Protection Rules"]["status"] == NOT_APPLICABLE


def test_public_repo_on_free_plan_is_fully_enforced():
    """Rulesets are enforced on public repositories regardless of plan."""
    repo = FakeRepo(
        private=False,
        branch=FakeBranch(protected=False),
        rules=load_fixture("microsoft_vscode"),
    )
    details = SecurityChecker(org=None, plan_name="free").check_repository(repo)["details"]
    assert details["Branch Protection Rules"]["status"] == PASS
    assert details["Pull Request Reviews"]["status"] == PASS


def test_unknown_plan_on_private_repo_carries_a_caveat():
    """Never silently assume enforcement we could not confirm."""
    repo = FakeRepo(
        private=True,
        branch=FakeBranch(protected=False),
        rules=load_fixture("microsoft_vscode"),
    )
    details = SecurityChecker(org=None, plan_name=None).check_repository(repo)["details"]
    root = details["Branch Protection Rules"]
    assert root["status"] == PASS
    assert "confirm enforcement" in root["message"]


# -- Actions settings observed in the GitHub UI ------------------------------
#
# Settings > Actions > General on a private personal repository exposes
# controls the engine did not know about: a native "Require actions to be
# pinned to a full-length commit SHA" checkbox and a fork pull request workflow
# toggle. Their JSON key names are not confirmed, so the engine probes for
# candidates and reports unknown when none is present.

def test_repo_actions_policy_reacts_to_allowed_actions():
    checker = SecurityChecker(org=None)
    permissive = FakeRepo(actions={"permissions": {"enabled": True, "allowed_actions": "all"}})
    restricted = FakeRepo(actions={"permissions": {"enabled": True, "allowed_actions": "selected"}})
    local = FakeRepo(actions={"permissions": {"enabled": True, "allowed_actions": "local_only"}})

    assert checker._check_repo_actions_policy(permissive)["status"] == FAIL
    assert checker._check_repo_actions_policy(restricted)["status"] == PASS
    assert checker._check_repo_actions_policy(local)["status"] == PASS


def test_disabled_actions_is_a_pass_not_a_gap():
    repo = FakeRepo(actions={"permissions": {"enabled": False}})
    r = SecurityChecker(org=None)._check_repo_actions_policy(repo)
    assert r["status"] == PASS


def test_personal_account_still_gets_actions_coverage():
    """
    Regression: with organization-only Actions checks, a personal account
    received no Actions policy coverage at all.
    """
    repo = FakeRepo(actions={"permissions": {"enabled": True, "allowed_actions": "all"}})
    details = SecurityChecker(org=None).check_repository(repo)["details"]
    assert details["Repository Actions Policy"]["status"] == FAIL


@pytest.mark.parametrize("key", [
    "sha_pinning_required", "require_sha_pinning",
    "actions_sha_pinning_required", "require_actions_pinned_to_sha",
])
def test_sha_pinning_policy_probes_candidate_key_names(key):
    checker = SecurityChecker(org=None)
    on = FakeRepo(actions={"permissions": {"allowed_actions": "all", key: True}})
    off = FakeRepo(actions={"permissions": {"allowed_actions": "all", key: False}})
    assert checker._check_sha_pinning_policy(on)["status"] == PASS
    assert checker._check_sha_pinning_policy(off)["status"] == FAIL


def test_unknown_sha_pinning_field_is_never_guessed():
    """An absent field must not become a pass or a failure."""
    repo = FakeRepo(actions={"permissions": {"allowed_actions": "all"}})
    r = SecurityChecker(org=None)._check_sha_pinning_policy(repo)
    assert r["status"] == UNKNOWN
    assert "verify manually" in r["message"]


def test_fork_pr_workflows_differ_by_visibility():
    checker = SecurityChecker(org=None)
    # A public repository has no run/do-not-run toggle, so an absent approval
    # policy field must be unknown rather than silently skipped.
    public = FakeRepo(private=False, actions={"permissions": {"allowed_actions": "all"}})
    assert checker._check_fork_pr_workflows(public)["status"] == UNKNOWN

    private_off = FakeRepo(private=True, actions={"permissions": {
        "allowed_actions": "all", "fork_pr_workflows_policy": False}})
    private_on = FakeRepo(private=True, actions={"permissions": {
        "allowed_actions": "all", "fork_pr_workflows_policy": True}})
    assert checker._check_fork_pr_workflows(private_off)["status"] == PASS
    assert checker._check_fork_pr_workflows(private_on)["status"] == FAIL


def test_no_raw_interpolation_of_repo_or_check_data():
    """
    Escaping was added in one pass and missed a section. This asserts on the
    source: any f-string field holding repository, check or message data must
    go through _esc().
    """
    import re as _re

    source = (Path(__file__).resolve().parent.parent / "report_generator.py").read_text()
    risky = _re.findall(
        r"\{(?!_esc)([a-z_]*(?:repo|check_name|message|org_name)[a-z_]*"
        r"(?:\[[^\]]+\])?)\}",
        source,
    )
    assert risky == [], f"unescaped interpolations: {sorted(set(risky))}"


# -- ruleset enforcement status ----------------------------------------------
#
# The new-ruleset form defaults Enforcement status to "Disabled". A ruleset
# saved without changing it looks configured and enforces nothing.

def test_disabled_ruleset_is_a_finding():
    repo = FakeRepo(rulesets=[
        {"name": "main protection", "enforcement": "disabled"},
        {"name": "tags", "enforcement": "active"},
    ])
    r = SecurityChecker(org=None)._check_ruleset_enforcement(repo)
    assert r["status"] == FAIL
    assert "DISABLED" in r["message"]
    assert "main protection" in r["message"]


def test_evaluate_mode_ruleset_is_a_finding():
    repo = FakeRepo(rulesets=[{"name": "trial", "enforcement": "evaluate"}])
    r = SecurityChecker(org=None)._check_ruleset_enforcement(repo)
    assert r["status"] == FAIL
    assert "evaluate" in r["message"]


def test_all_active_rulesets_pass():
    repo = FakeRepo(rulesets=[{"name": "main", "enforcement": "active"}])
    assert SecurityChecker(org=None)._check_ruleset_enforcement(repo)["status"] == PASS


def test_no_rulesets_is_not_applicable_here():
    """Absence of rulesets is reported by Branch Protection Rules, not twice."""
    repo = FakeRepo(rulesets=[])
    assert SecurityChecker(org=None)._check_ruleset_enforcement(repo)["status"] == NOT_APPLICABLE


# -- fork pull request approval on public repositories -----------------------

def test_public_repo_fork_approval_policy_is_graded():
    """Public repositories were previously skipped entirely for this control."""
    checker = SecurityChecker(org=None)

    weak = FakeRepo(private=False, actions={"permissions": {
        "approval_policy": "first_time_contributors_new_to_github"}})
    good = FakeRepo(private=False, actions={"permissions": {
        "approval_policy": "first_time_contributors"}})
    strongest = FakeRepo(private=False, actions={"permissions": {
        "approval_policy": "all_external_contributors"}})

    assert checker._check_fork_pr_workflows(weak)["status"] == FAIL
    assert checker._check_fork_pr_workflows(good)["status"] == PASS
    assert checker._check_fork_pr_workflows(strongest)["status"] == PASS


# -- forward compatibility with new rule types -------------------------------

def test_unknown_rule_types_do_not_read_as_unprotected():
    """
    GitHub added code quality and code coverage rules after this engine was
    written. An unfamiliar ruleset must report unknown, never "unprotected".
    """
    repo = FakeRepo(branch=FakeBranch(protected=False), rules=[
        {"type": "code_quality", "parameters": {}},
        {"type": "code_coverage", "parameters": {}},
    ])
    r = SecurityChecker(org=None).check_repository(repo)["details"]["Branch Protection Rules"]
    assert r["status"] == UNKNOWN
    assert "code_quality" in r["message"]


def test_repository_scoped_rules_still_read_as_unprotected():
    """Repository rules are known-irrelevant, so they must not trigger unknown."""
    repo = FakeRepo(branch=FakeBranch(protected=False),
                    rules=load_fixture("repository_rules_only"))
    r = SecurityChecker(org=None).check_repository(repo)["details"]["Branch Protection Rules"]
    assert r["status"] == FAIL


# -- coverage --------------------------------------------------------------

def test_coverage_is_reported_alongside_the_score():
    """
    On the reference organization only 63 of 120 checks could be scored. A 57%
    score over half the control set is a weaker claim than the same number over
    all of it, and the summary must say so rather than leave it to be inferred.
    """
    summary = GitHubAuditor._calculate_summary(
        GitHubAuditor.__new__(GitHubAuditor),
        {"organization": {"passed": 5, "failed": 4, "unknown": 6, "not_applicable": 10}},
    )
    assert summary["evaluated_checks"] == 9
    assert summary["total_checks"] == 25
    assert summary["coverage_percent"] == 36.0
    assert summary["low_coverage"] is True


def test_full_coverage_is_not_flagged():
    summary = GitHubAuditor._calculate_summary(
        GitHubAuditor.__new__(GitHubAuditor),
        {"organization": {"passed": 8, "failed": 2, "unknown": 0, "not_applicable": 0}},
    )
    assert summary["coverage_percent"] == 100.0
    assert summary["low_coverage"] is False


def test_api_errors_name_the_endpoint_they_came_from():
    """
    A rulesets 403 was being reported as "Actions settings: token lacks the
    required permission", which sends the reader to the wrong settings page.
    """
    repo = FakeRepo(rulesets=None)  # requester raises 403 for /rulesets
    r = SecurityChecker(org=None)._check_ruleset_enforcement(repo)
    assert r["status"] == UNKNOWN
    assert "Actions" not in r["message"]
    assert "Rulesets" in r["message"]


def test_free_org_private_repo_suppression_names_the_remediation():
    """
    Confirmed from the UI on a free organization:
    "Your rulesets won't be enforced on this private repository until you
     upgrade this organization account to GitHub Team."

    Suppressing these controls is correct, but the finding must still tell the
    reader what would bring them into scope.
    """
    repo = FakeRepo(private=True, branch=FakeBranch(protected=False), rules=None)
    root = SecurityChecker(org=None, plan_name="free").check_repository(repo)["details"][
        "Branch Protection Rules"
    ]
    assert root["status"] == NOT_APPLICABLE
    assert "GitHub Team" in root["message"]
    assert "public" in root["message"]


# -- account type ------------------------------------------------------------
#
# Organization-scoped controls do not exist on a personal account. Reporting
# them as "unknown" implied the setting existed and the token merely could not
# read it, which sent the reader to look for a page that is not there.

class FakeUserRequester:
    def requestJsonAndCheck(self, _method, _url):
        raise Exception("404")


class FakePersonalAccount:
    """What PyGithub returns for a personal account: no org-only attributes."""
    url = "https://api.github.com/users/someone"
    login = "someone"

    def __init__(self):
        self._requester = FakeUserRequester()


def test_personal_account_is_detected():
    assert SecurityChecker(FakePersonalAccount()).is_organization is False
    assert SecurityChecker(FakeOrg()).is_organization is True


def test_org_only_controls_are_not_applicable_on_a_personal_account():
    result = SecurityChecker(FakePersonalAccount()).check_organization_settings()
    assert result["unknown"] == 0
    assert result["not_applicable"] == result["total"] == 9
    for name, detail in result["details"].items():
        assert ("organization setting" in detail["message"]
                or "personal account" in detail["message"]), name
        assert "only visible to organization owners" not in detail["message"], name


def test_personal_account_org_checks_do_not_distort_the_score():
    """Eight unscored checks must not drag a personal account's score."""
    summary = GitHubAuditor._calculate_summary(
        GitHubAuditor.__new__(GitHubAuditor),
        {"organization": SecurityChecker(FakePersonalAccount()).check_organization_settings()},
    )
    assert summary["evaluated_checks"] == 0
    assert summary["risk_level"] == "UNSCORED"


def test_paid_personal_plan_does_not_assume_ruleset_enforcement():
    """
    The non-enforcement banner names a GitHub Team *organization*. A paid
    personal plan is not established to lift the restriction, so a private
    personal repository must not be assumed enforced.
    """
    repo = FakeRepo(private=True, branch=FakeBranch(protected=False),
                    rules=load_fixture("microsoft_vscode"))
    checker = SecurityChecker(FakePersonalAccount(), plan_name="pro")
    root = checker.check_repository(repo)["details"]["Branch Protection Rules"]
    assert root["status"] == PASS
    assert "confirm enforcement" in root["message"]


def test_organization_on_a_paid_plan_is_treated_as_enforced():
    repo = FakeRepo(private=True, branch=FakeBranch(protected=False),
                    rules=load_fixture("microsoft_vscode"))
    checker = SecurityChecker(FakeOrg(), plan_name="team")
    root = checker.check_repository(repo)["details"]["Branch Protection Rules"]
    assert root["status"] == PASS
    assert "confirm enforcement" not in root["message"]


# -- account type selection --------------------------------------------------

def test_config_validates_account_type():
    from config import Config

    for value in ("auto", "organization", "user", "ORGANIZATION"):
        assert Config(github_token="x", org_name="y", account_type=value)

    with pytest.raises(ValueError, match="Unknown account type"):
        Config(github_token="x", org_name="y", account_type="team")


def test_config_defaults_to_auto():
    from config import Config

    assert Config(github_token="x", org_name="y").account_type == "auto"


def test_explicit_account_type_overrides_detection():
    """
    The caller's selection wins. Auditing an organization as a personal account
    should not silently invent organization settings, and vice versa.
    """
    checker = SecurityChecker(FakePersonalAccount(), account_type="Organization")
    assert checker.is_organization is True

    checker = SecurityChecker(FakeOrg(), account_type="User")
    assert checker.is_organization is False
    result = checker.check_organization_settings()
    assert result["not_applicable"] == 9


def test_applicability_doc_lists_every_check():
    """The published matrix must not fall behind the engine."""
    doc = (Path(__file__).resolve().parent.parent / "APPLICABILITY.md").read_text()

    checker = SecurityChecker(FakeOrg())
    names = set(checker.check_organization_settings()["details"])
    names |= set(checker.check_repository(hardened_repo())["details"])

    missing = sorted(n for n in names if n not in doc)
    assert missing == [], f"checks absent from APPLICABILITY.md: {missing}"


# -- access review -----------------------------------------------------------
#
# An access review is the evidence auditors sample. These tests assert on the
# patterns that draw questions, not merely that the roster was retrieved.

def review(org=None, **kw):
    from access_review import AccessReview
    return AccessReview(org if org is not None else FakeOrg(**kw))


def test_inventory_distinguishes_direct_from_team_derived_access():
    """The distinction is the entire basis of a team-based access review."""
    repo = FakeRepo(
        collaborators=[
            FakeCollaborator("alice", "admin"),
            FakeCollaborator("bob", "push"),
            FakeCollaborator("carol", "pull"),
        ],
        direct=["bob"],
        teams=[FakeTeam("platform", "push")],
    )
    inv = review().repository_inventory(repo)
    by_name = {p["name"]: p for p in inv["principals"]}

    assert by_name["bob"]["affiliation"] == "direct"
    assert by_name["alice"]["affiliation"] == "via team or organization"
    assert by_name["platform"]["kind"] == "team"
    # highest permission first
    assert inv["principals"][0]["permission"] == "admin"


def test_direct_elevated_grant_is_flagged():
    repo = FakeRepo(collaborators=[FakeCollaborator("bob", "push")], direct=["bob"])
    r = review().check_direct_grants(review().repository_inventory(repo))
    assert r["status"] == FAIL
    assert "bob (Write)" in r["message"]
    assert "team roster" in r["message"]


def test_team_only_access_passes():
    repo = FakeRepo(collaborators=[FakeCollaborator("alice", "push")], direct=[])
    rev = review()
    assert rev.check_direct_grants(rev.repository_inventory(repo))["status"] == PASS


def test_outside_collaborator_with_write_is_flagged():
    org = FakeOrg(outside=["contractor"])
    rev = review(org)
    repo = FakeRepo(private=True, collaborators=[
        FakeCollaborator("contractor", "push"),
        FakeCollaborator("alice", "pull"),
    ])
    inv = rev.repository_inventory(repo)
    assert {p["name"]: p["affiliation"] for p in inv["principals"]}["contractor"] \
        == "outside collaborator"

    r = rev.check_outside_collaborators(repo, inv)
    assert r["status"] == FAIL
    assert "contractor (Write)" in r["message"]
    assert "private" in r["message"]


def test_no_outside_collaborators_passes():
    rev = review(FakeOrg(outside=[]))
    repo = FakeRepo(collaborators=[FakeCollaborator("alice", "push")])
    r = rev.check_outside_collaborators(repo, rev.repository_inventory(repo))
    assert r["status"] == PASS


def test_admin_concentration_flags_too_many_admins():
    rev = review()
    many = FakeRepo(collaborators=[
        FakeCollaborator(n, "admin") for n in ("a", "b", "c", "d", "e")
    ])
    few = FakeRepo(collaborators=[FakeCollaborator("a", "admin")])
    assert rev.check_admin_concentration(rev.repository_inventory(many))["status"] == FAIL
    assert rev.check_admin_concentration(rev.repository_inventory(few))["status"] == PASS


def test_team_level_admin_is_flagged():
    rev = review()
    repo = FakeRepo(collaborators=[], teams=[FakeTeam("everyone", "admin")])
    r = rev.check_admin_concentration(rev.repository_inventory(repo))
    assert r["status"] == FAIL
    assert "every current and future member" in r["message"]


def test_owner_count_flags_both_extremes():
    """A single owner is a continuity risk; many owners is standing privilege."""
    assert review(FakeOrg(owners=["solo"])).check_owner_count()["status"] == FAIL
    assert review(FakeOrg(owners=list("abcdefg"))).check_owner_count()["status"] == FAIL
    assert review(FakeOrg(owners=["a", "b", "c"])).check_owner_count()["status"] == PASS


def test_unreadable_collaborators_are_unknown_not_findings():
    rev = review()
    repo = FakeRepo(collaborators=None)  # raises 403
    inv = rev.repository_inventory(repo)
    assert inv["readable"] is False
    for result in (rev.check_direct_grants(inv),
                   rev.check_admin_concentration(inv)):
        assert result["status"] == UNKNOWN


def test_access_checks_are_not_applicable_on_a_personal_account():
    from access_review import AccessReview

    rev = AccessReview(FakePersonalAccount(), is_organization=False)
    repo = FakeRepo(collaborators=[FakeCollaborator("bob", "push")], direct=["bob"])
    inv = rev.repository_inventory(repo)
    assert rev.check_direct_grants(inv)["status"] == NOT_APPLICABLE
    assert rev.check_owner_count()["status"] == NOT_APPLICABLE


def test_report_renders_the_access_inventory_with_usernames_escaped():
    from report_generator import ReportGenerator

    repos = {"app": {
        "access_inventory": {
            "readable": True,
            "principals": [{
                "name": "<img src=x onerror=alert(1)>", "kind": "user",
                "account_type": "User", "affiliation": "outside collaborator",
                "permission": "admin", "permission_label": "Admin",
            }],
        }
    }}

    class Cfg:
        org_name = "acme"

    out = ReportGenerator(Cfg())._render_access_inventory(repos)
    assert "Access Inventory" in out
    assert "external party with write access" in out
    assert "<img src=x onerror" not in out
    assert "&lt;img src=x onerror" in out


# -- single-standard reports -------------------------------------------------
#
# A SOC 2 report that also scores NIST is not a SOC 2 report. The reader has to
# work out which number applies to them, and the wrong one is right there.

def sample_results():
    org = FakeOrg(owners=["anton"], outside=["contractor"])
    repo = FakeRepo(
        name="app", branch=FakeBranch(protected=False),
        collaborators=[FakeCollaborator("anton", "admin"),
                       FakeCollaborator("contractor", "push")],
        direct=["contractor"], teams=[FakeTeam("platform", "admin")],
    )
    checker = SecurityChecker(org)
    results = {
        "organization": "acme", "account_type": "Organization",
        "target_warning": None, "timestamp": "2026-08-10T21:00:00",
        "checks": {"organization": checker.check_organization_settings(),
                   "repositories": {"app": checker.check_repository(repo)}},
    }
    results["summary"] = GitHubAuditor._calculate_summary(
        GitHubAuditor.__new__(GitHubAuditor), results["checks"]
    )
    return results


class Cfg:
    org_name = "acme"


OTHER_STANDARD_MARKERS = {
    "soc2": ["SOC 2", "Trust Services"],
    "nist": ["NIST SP 800-53", "AC-6"],
    "iso27001": ["ISO/IEC 27001", "A.5.", "A.8."],
    "cis": ["CIS Controls", "Safeguard"],
}


@pytest.mark.parametrize("standard", ["soc2", "nist", "iso27001", "cis"])
def test_single_standard_report_excludes_every_other_standard(standard):
    from report_generator import ReportGenerator

    html = ReportGenerator(Cfg(), standard=standard).generate_html_report(sample_results())

    leaked = []
    for key, markers in OTHER_STANDARD_MARKERS.items():
        if key == standard:
            continue
        leaked += [m for m in markers if m in html]
    assert leaked == [], f"{standard} report leaked: {leaked}"


@pytest.mark.parametrize("standard", ["soc2", "nist", "iso27001", "cis"])
def test_single_standard_report_still_names_its_own_standard(standard):
    from compliance_mapping import resolve_standard
    from report_generator import ReportGenerator

    html = ReportGenerator(Cfg(), standard=standard).generate_html_report(sample_results())
    assert resolve_standard(standard)["name"] in html


@pytest.mark.parametrize("standard", ["soc2", "nist", "iso27001", "cis", "all", None])
def test_access_inventory_is_present_in_every_report(standard):
    """The roster is not a per-standard extra; every report carries it."""
    from report_generator import ReportGenerator

    html = ReportGenerator(Cfg(), standard=standard).generate_html_report(sample_results())
    assert "Access Inventory" in html
    assert "contractor" in html
    assert "platform" in html


def test_standard_scoping_recomputes_the_score_over_its_own_checks():
    from compliance_mapping import resolve_standard, scope_results_to_standard

    results = sample_results()
    scoped = scope_results_to_standard(results, resolve_standard("soc2"))
    summary = scoped["summary"]
    assert summary["evaluated_checks"] == (
        summary["passed_checks"] + summary["failed_checks"]
    )
    assert summary["total_checks"] <= results["summary"]["total_checks"]


def test_unknown_standard_is_rejected():
    from compliance_mapping import resolve_standard

    assert resolve_standard("all") is None
    assert resolve_standard("SOC-2")["key"] == "soc2"
    with pytest.raises(ValueError, match="Unknown standard"):
        resolve_standard("pci-dss")


def test_json_report_is_scoped_too():
    """An auditor given the JSON must see the same control set as the HTML."""
    from report_generator import ReportGenerator

    payload = json.loads(
        ReportGenerator(Cfg(), standard="cis").generate_json_report(sample_results())
    )
    assert payload["standard"]["name"] == "CIS Controls v8.1"


# -- permission vocabulary ---------------------------------------------------

def test_both_github_permission_vocabularies_are_understood():
    """
    The collaborators endpoint returns push/pull; get_collaborator_permission
    returns write/read. A lookup that knows only one silently mislabels the
    other as Read.
    """
    from access_review import normalise_permission, capabilities_for

    assert normalise_permission("write") == "push"
    assert normalise_permission("read") == "pull"
    assert normalise_permission("admin") == "admin"
    assert normalise_permission("none") is None
    assert capabilities_for("admin")["delete"] is True
    assert capabilities_for("push")["settings"] is False
    assert capabilities_for("maintain")["settings"] is True
    assert capabilities_for("maintain")["delete"] is False


def test_inventory_carries_capability_columns():
    repo = FakeRepo(collaborators=[FakeCollaborator("alice", "maintain")])
    inv = review().repository_inventory(repo)
    caps = inv["principals"][0]["capabilities"]
    assert caps["push"] and caps["settings"] and not caps["delete"]
    assert caps["risk"] == "High"


# -- report rendering completeness -------------------------------------------

@pytest.mark.parametrize("standard", ["soc2", "nist", "iso27001", "cis", "all"])
def test_no_unrendered_placeholders_in_the_report(standard):
    """
    A section was built with a plain string containing {self._framework_blocks()},
    so the call was printed literally in the published report. Any f-string
    placeholder reaching the output is a rendering bug.
    """
    import re as _re
    from report_generator import ReportGenerator

    html = ReportGenerator(Cfg(), standard=standard).generate_html_report(sample_results())
    leftovers = _re.findall(r"\{self\.\w+[^}]*\}|\{[a-z_]+\}", html)
    assert leftovers == [], f"unrendered placeholders: {sorted(set(leftovers))}"


def test_no_hardcoded_control_counts_in_report_prose():
    """'Why These 21 Controls' survived three count changes."""
    import re as _re

    source = (Path(__file__).resolve().parent.parent / "report_generator.py").read_text()
    hardcoded = _re.findall(r"(?:These |the )(\d+)\s+[Cc]ontrols", source)
    assert hardcoded == [], f"hardcoded control counts in prose: {hardcoded}"


@pytest.mark.parametrize("standard", ["soc2", "nist", "iso27001", "cis"])
def test_mapping_table_carries_requirement_and_recommendation(standard):
    from compliance_mapping import CONTROL_GUIDANCE, resolve_standard
    from report_generator import ReportGenerator

    gen = ReportGenerator(Cfg(), standard=standard)
    html = gen._render_compliance_details_by_check(
        gen._scoped(sample_results())
    )
    assert "Security control" in html
    assert "Recommendation" in html
    assert resolve_standard(standard)["name"] in html

    guidance = CONTROL_GUIDANCE["Branch Protection Rules"]
    assert guidance["verifies"][:40] in html
    assert guidance["remediation"][:40] in html


def test_gap_table_lists_only_failures_with_observation_and_fix():
    from report_generator import ReportGenerator

    gen = ReportGenerator(Cfg(), standard="soc2")
    scoped = gen._scoped(sample_results())
    html = gen._render_compliance_gaps(scoped)

    all_checks = gen._collect_checks(scoped)
    failing = {n for n, r in all_checks.items() if r.get("status") == "fail"}
    passing = {n for n, r in all_checks.items() if r.get("status") == "pass"}

    assert "Failing control" in html and "Observed" in html
    for name in failing:
        assert name in html, f"missing failing control {name}"
    for name in passing:
        # a passing control has no place on a work list
        assert f'<strong style="color: var(--danger);">{name}</strong>' not in html


def test_every_mapped_check_has_guidance():
    """A row with an empty recommendation column is a row nobody can act on."""
    from compliance_mapping import COMPLIANCE_MAPPING, CONTROL_GUIDANCE

    missing = sorted(set(COMPLIANCE_MAPPING) - set(CONTROL_GUIDANCE))
    assert missing == [], f"checks without guidance: {missing}"

    empty = sorted(
        name for name, g in CONTROL_GUIDANCE.items()
        if not g.get("verifies") or not g.get("remediation")
    )
    assert empty == [], f"checks with empty guidance: {empty}"
