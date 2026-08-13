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
        #: Every URL requested, in order - lets tests assert exactly how many
        #: real calls were made to a given endpoint, to prove deduplication
        #: rather than only inferring it from correct results.
        self.calls = []

    def requestJsonAndCheck(self, _method, url):
        self.calls.append(url)
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
        for match in _re.finditer(r"(\d+)\s+security (?:checks?|controls?)", text):
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
    permissive = FakeRepo(name="permissive", actions={"permissions": {"enabled": True, "allowed_actions": "all"}})
    restricted = FakeRepo(name="restricted", actions={"permissions": {"enabled": True, "allowed_actions": "selected"}})
    local = FakeRepo(name="local", actions={"permissions": {"enabled": True, "allowed_actions": "local_only"}})

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
    on = FakeRepo(name=f"on-{key}", actions={"permissions": {"allowed_actions": "all", key: True}})
    off = FakeRepo(name=f"off-{key}", actions={"permissions": {"allowed_actions": "all", key: False}})
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
    public = FakeRepo(name="public", private=False, actions={"permissions": {"allowed_actions": "all"}})
    assert checker._check_fork_pr_workflows(public)["status"] == UNKNOWN

    private_off = FakeRepo(name="private-off", private=True, actions={"permissions": {
        "allowed_actions": "all", "fork_pr_workflows_policy": False}})
    private_on = FakeRepo(name="private-on", private=True, actions={"permissions": {
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

    weak = FakeRepo(name="weak", private=False, actions={"permissions": {
        "approval_policy": "first_time_contributors_new_to_github"}})
    good = FakeRepo(name="good", private=False, actions={"permissions": {
        "approval_policy": "first_time_contributors"}})
    strongest = FakeRepo(name="strongest", private=False, actions={"permissions": {
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

    rows_data = gen._collect_check_rows(scoped)
    failing = {n for n, _, r in rows_data if r.get("status") == "fail"}
    passing = {n for n, _, r in rows_data if r.get("status") == "pass"}

    assert "Failing control" in html and "Observed" in html and "Repository" in html
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


# -- Organization-Level Findings and Failed Checks Summary as tables --------

@pytest.mark.parametrize("standard", ["soc2", "nist", "iso27001", "cis", "all"])
def test_organization_findings_is_a_table_with_requirement_and_fix(standard):
    from compliance_mapping import CONTROL_GUIDANCE
    from report_generator import ReportGenerator

    gen = ReportGenerator(Cfg(), standard=standard)
    scoped = gen._scoped(sample_results())
    html = gen._render_checks(scoped["checks"]["organization"])

    assert "<table" in html
    assert "Recommendation" in html
    # a control known to be in the sample organization checks
    assert "Organization Owner Count" in html
    guidance = CONTROL_GUIDANCE["Organization Owner Count"]
    assert guidance["remediation"][:30] in html


def test_organization_findings_shows_observed_message():
    from report_generator import ReportGenerator

    gen = ReportGenerator(Cfg())
    scoped = gen._scoped(sample_results())
    org_checks = scoped["checks"]["organization"]
    html = gen._render_checks(org_checks)
    owner_message = org_checks["details"]["Organization Owner Count"]["message"]
    assert owner_message in html


@pytest.mark.parametrize("standard", ["soc2", "nist", "iso27001", "cis", "all"])
def test_failed_checks_summary_is_a_table_with_repo_name(standard):
    from report_generator import ReportGenerator

    gen = ReportGenerator(Cfg(), standard=standard)
    scoped = gen._scoped(sample_results())
    html = gen._render_failed_checks_summary(scoped["checks"]["repositories"])

    assert "<table" in html
    assert "Repository" in html
    assert "Recommendation" in html
    assert "app" in html  # the repo name from sample_results()


def test_failed_checks_summary_lists_only_failures():
    from report_generator import ReportGenerator

    gen = ReportGenerator(Cfg())
    scoped = gen._scoped(sample_results())
    repos = scoped["checks"]["repositories"]
    html = gen._render_failed_checks_summary(repos)

    for repo_checks in repos.values():
        for name, result in repo_checks.get("details", {}).items():
            status = result.get("status", "pass" if result.get("passed") else "fail")
            if status == "pass":
                assert f'<strong style="color: var(--danger);">{name}</strong>' not in html


def test_failed_checks_summary_handles_multiple_repositories():
    from report_generator import ReportGenerator
    from checks import SecurityChecker

    org = FakeOrg()
    checker = SecurityChecker(org)
    repo_a = FakeRepo(name="a", branch=FakeBranch(protected=False))
    repo_b = FakeRepo(name="b", branch=FakeBranch(protected=False))
    checks = {"a": checker.check_repository(repo_a), "b": checker.check_repository(repo_b)}

    gen = ReportGenerator(Cfg())
    html = gen._render_failed_checks_summary(checks)
    import re as _re
    repo_names_in_table = _re.findall(
        r'<td style="padding: 12px; vertical-align: top; font-weight: 600; color: var\(--primary\);">\s*(\w+)\s*</td>',
        html,
    )
    assert set(repo_names_in_table) == {"a", "b"}
    assert "2 repositor" in html


def test_all_checks_passing_shows_no_failures_message():
    from report_generator import ReportGenerator

    gen = ReportGenerator(Cfg())
    html = gen._render_failed_checks_summary(
        {"clean": {"details": {"X": {"status": PASS, "message": "ok"}}}}
    )
    assert "No failed checks" in html


# -- version --------------------------------------------------------------

def test_version_is_a_single_source_of_truth():
    from version import __version__, version_string

    assert __version__
    assert __version__ in version_string()


def test_version_reaches_the_audit_results():
    results = sample_results()
    # sample_results uses GitHubAuditor._calculate_summary directly and does
    # not go through audit_organization(), so this documents where the field
    # is expected rather than asserting on the fixture.
    from github_auditor import GitHubAuditor
    import inspect
    source = inspect.getsource(GitHubAuditor.audit_organization)
    assert "tool_version" in source


def test_version_appears_on_every_page():
    import app as app_module

    client = app_module.create_app().test_client()
    for path in ["/", "/start", "/wiki", "/wiki/faq", "/history"]:
        body = client.get(path).get_data(as_text=True)
        from version import __version__
        assert __version__ in body, path


# -- repository scope --------------------------------------------------------

def test_cli_accepts_repository_scope():
    import github_auditor

    parser_source = open(
        Path(github_auditor.__file__)
    ).read()
    assert "--repos" in parser_source


def test_scope_banner_states_full_account_by_default():
    from report_generator import ReportGenerator

    results = sample_results()
    results["repository_scope"] = None
    results["scope_warning"] = None
    results["target_warning"] = None
    results["tool_version"] = "1.11.0"
    html = ReportGenerator(Cfg())._render_scope_banner(results)
    assert "Full account" in html
    assert "1.11.0" in html


def test_scope_banner_states_restricted_scope_and_warnings():
    from report_generator import ReportGenerator

    results = sample_results()
    results["repository_scope"] = ["app", "other-repo"]
    results["scope_warning"] = "1 requested repository name(s) were not found and were skipped: typo-repo"
    results["target_warning"] = None
    results["tool_version"] = "1.11.0"
    html = ReportGenerator(Cfg())._render_scope_banner(results)
    assert "Restricted scope: 2 repositories" in html
    assert "app, other-repo" in html
    assert "typo-repo" in html


def test_audit_organization_restricts_to_named_repositories():
    """Scoped audit runs checks only on the requested repositories."""
    import sys
    from github_auditor import GitHubAuditor
    from config import Config

    class FakeOrgWithRepos(FakeOrg):
        def __init__(self, repos):
            super().__init__()
            self._repos = repos

        def get_repos(self):
            return self._repos

    auditor = GitHubAuditor.__new__(GitHubAuditor)
    auditor.config = Config(github_token="x", org_name="acme")
    auditor.gh = None
    auditor.target_warning = None
    auditor.org = FakeOrgWithRepos([
        FakeRepo(name="keep", branch=FakeBranch(protected=True)),
        FakeRepo(name="skip", branch=FakeBranch(protected=True)),
    ])

    results = auditor.audit_organization(verbose=False, repo_names=["keep"])
    assert list(results["checks"]["repositories"].keys()) == ["keep"]
    assert results["repository_scope"] == ["keep"]
    assert results["scope_warning"] is None


def test_audit_organization_reports_unmatched_repository_names():
    from github_auditor import GitHubAuditor
    from config import Config

    class FakeOrgWithRepos(FakeOrg):
        def __init__(self, repos):
            super().__init__()
            self._repos = repos

        def get_repos(self):
            return self._repos

    auditor = GitHubAuditor.__new__(GitHubAuditor)
    auditor.config = Config(github_token="x", org_name="acme")
    auditor.gh = None
    auditor.target_warning = None
    auditor.org = FakeOrgWithRepos([FakeRepo(name="keep", branch=FakeBranch(protected=True))])

    results = auditor.audit_organization(verbose=False, repo_names=["keep", "typo"])
    assert results["scope_warning"] is not None
    assert "typo" in results["scope_warning"]


def test_web_form_passes_repository_scope_through():
    app_source = (Path(__file__).resolve().parent.parent / "app.py").read_text()
    assert "repo_names" in app_source
    assert "id=\"findReposBtn\"" in app_source
    assert "id=\"repoPicker\"" in app_source
    assert "/api/list-repositories" in app_source


# -- logic bugs found in a full re-read (this session) ----------------------

def test_classic_branch_protection_is_trusted_even_when_rulesets_are_not_enforced():
    """
    The non-enforcement banner, captured live twice, names rulesets
    specifically ("Your rulesets won't be enforced..."). It never mentions
    classic branch protection. Suppressing classic protection under the same
    restriction had no evidence behind it and hid a genuinely enforced setting.
    """
    protection = FakeProtection(
        reviews=FakeReviews(count=2), status_checks=FakeStatusChecks(),
    )
    repo = FakeRepo(
        private=True,
        branch=FakeBranch(protected=True, protection=protection),
        rules=None,
    )
    details = SecurityChecker(org=None, plan_name="free").check_repository(repo)["details"]
    root = details["Branch Protection Rules"]
    assert root["status"] == PASS
    assert "classic branch protection" in root["message"]
    # dependent checks must be scored from the trusted classic facts, not
    # suppressed as if protection were unenforced
    assert details["Pull Request Reviews"]["status"] == PASS


def test_ruleset_only_protection_is_still_suppressed_on_free_private_repos():
    """The free-plan suppression still applies where it has evidence: rulesets."""
    repo = FakeRepo(
        private=True, branch=FakeBranch(protected=False),
        rules=load_fixture("microsoft_vscode"),
    )
    details = SecurityChecker(org=None, plan_name="free").check_repository(repo)["details"]
    root = details["Branch Protection Rules"]
    assert root["status"] == FAIL
    assert "NOT ENFORCED" in root["message"]


def test_ruleset_enforcement_ignores_non_branch_rulesets():
    """
    A disabled tag or push ruleset says nothing about branch protection.
    Counting it here would fail this check while Branch Protection Rules
    correctly passes from an unrelated active branch ruleset.
    """
    repo = FakeRepo(rulesets=[
        {"name": "release-tags", "enforcement": "disabled", "target": "tag"},
        {"name": "main-branch", "enforcement": "active", "target": "branch"},
    ])
    r = SecurityChecker(org=None)._check_ruleset_enforcement(repo)
    assert r["status"] == PASS


def test_ruleset_enforcement_still_fails_for_disabled_branch_rulesets():
    repo = FakeRepo(rulesets=[
        {"name": "release-tags", "enforcement": "active", "target": "tag"},
        {"name": "main-branch", "enforcement": "disabled", "target": "branch"},
    ])
    r = SecurityChecker(org=None)._check_ruleset_enforcement(repo)
    assert r["status"] == FAIL
    assert "main-branch" in r["message"]
    assert "release-tags" not in r["message"]


def test_ruleset_enforcement_keeps_missing_target_in_scope():
    """An unrecognised or absent target must not be silently excluded."""
    repo = FakeRepo(rulesets=[{"name": "unspecified", "enforcement": "disabled"}])
    r = SecurityChecker(org=None)._check_ruleset_enforcement(repo)
    assert r["status"] == FAIL


def test_2fa_fail_message_makes_no_completed_rollout_claim():
    """Both branches must avoid the disproven 'since 2024' framing, not just one."""
    org = FakeOrg(two_factor=False)
    r = SecurityChecker(org)._check_2fa_enforcement()
    assert r["status"] == FAIL
    assert "since 2024" not in r["message"]
    assert "covers github.com contributors" not in r["message"]


def test_admin_concentration_message_has_no_false_ellipsis():
    """An ellipsis must not appear when every admin name is already shown."""
    from access_review import AccessReview

    repo = FakeRepo(collaborators=[
        FakeCollaborator(n, "admin") for n in ("a", "b", "c", "d")
    ])
    rev = review()
    r = rev.check_admin_concentration(rev.repository_inventory(repo))
    assert r["status"] == FAIL
    assert "..." not in r["message"]


def test_admin_concentration_message_truncates_with_ellipsis_past_five():
    from access_review import AccessReview

    repo = FakeRepo(collaborators=[
        FakeCollaborator(n, "admin") for n in "abcdefg"
    ])
    rev = review()
    r = rev.check_admin_concentration(rev.repository_inventory(repo))
    assert r["status"] == FAIL
    assert "..." in r["message"]


# -- documentation / UI drift guards -----------------------------------------

def test_no_stale_token_flag_or_scopes_in_docs():
    """
    -t was removed in v1.3.0 (shell history / ps aux exposure), and the
    read-only fine-grained token replaced 'repo, admin:org_hook, read:org'
    (full write access) in v1.3.0. Both had survived in five documentation
    files and the in-app wiki, recommending the exact things the code was
    changed to prevent.
    """
    root = Path(__file__).resolve().parent.parent
    offenders = []
    for path in list(root.glob("*.md")) + list(root.glob("*.py")):
        if path.name.startswith("test_") or path.name == "CHANGELOG.md":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for bad in ("-t YOUR_TOKEN", "-t TOKEN", "admin:org_hook"):
            if bad == "admin:org_hook" and "requires `admin:org_hook`" in text:
                continue  # SECURITY_AUDIT.md explains this scope is NOT needed
            if bad in text:
                offenders.append(f"{path.name}: {bad!r}")
    assert offenders == [], offenders


def test_no_phantom_third_party_integrations_in_docs():
    """
    VirusTotal/AbuseIPDB belong to a different project. config.py reads no
    such environment variable; documenting them as optional features was
    describing a tool this project is not.
    """
    root = Path(__file__).resolve().parent.parent
    offenders = []
    for path in list(root.glob("*.md")):
        if path.name == "CHANGELOG.md":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for bad in ("VirusTotal", "AbuseIPDB", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"):
            if bad in text and "does not have" not in text and "belong to a different project" not in text:
                offenders.append(f"{path.name}: {bad!r}")
    assert offenders == [], offenders


def test_no_stale_dependency_versions_in_docs():
    """SECURITY_AUDIT.md and TOOL_SUMMARY.md quoted PyGithub 1.59/2.1.1,
    Flask 2.3.0/3.0.0, requests 2.31.0, and a python-dotenv dependency that
    was never in requirements.txt. Both drift and phantom-dependency classes
    of the same underlying failure: a hand-copied version list in prose.
    """
    requirements = (Path(__file__).resolve().parent.parent / "requirements.txt").read_text()
    root = Path(__file__).resolve().parent.parent
    offenders = []
    for path in list(root.glob("*.md")):
        if path.name == "CHANGELOG.md":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for bad in ("PyGithub==1.59", "PyGithub 1.59", "PyGithub 2.1.1",
                    "Flask 2.3.0", "Flask 3.0.0", "requests 2.31.0",
                    "python-dotenv"):
            if bad in text:
                offenders.append(f"{path.name}: {bad!r}")
    assert offenders == [], offenders
    assert "python-dotenv" not in requirements


def test_no_fabricated_certification_in_docs():
    """
    An earlier SECURITY_AUDIT.md self-certified 'APPROVED FOR PUBLIC RELEASE'
    with a fictional 'Security Review Team' and audit date. A document
    describing its own code is not a third-party certification and must not
    read as one.
    """
    text = (Path(__file__).resolve().parent.parent / "SECURITY_AUDIT.md").read_text()
    for bad in ("APPROVED FOR PUBLIC RELEASE", "Security Review Team",
                "MAXIMUM", "Certification"):
        assert bad not in text, bad


def test_privacy_doc_does_not_claim_no_usernames_are_stored():
    """The access inventory (v1.9.0+) stores GitHub usernames by design."""
    text = (Path(__file__).resolve().parent.parent / "PRIVACY.md").read_text()
    assert "usernames" in text.lower() or "access inventory" in text.lower()


def test_web_footer_shows_the_current_version_string():
    import app as app_module
    from version import version_string

    client = app_module.create_app().test_client()
    body = client.get("/").get_data(as_text=True)
    assert version_string() in body


# -- repository scope: API robustness (found via end-to-end testing) --------

def test_api_splits_comma_separated_repos_string():
    """
    Regression: a raw comma-separated string sent directly to the API (the
    same format the CLI's --repos flag accepts) was wrapped whole into a
    single-element list instead of split, silently scoping the audit to zero
    repositories. The browser's client-side JS split first and masked this,
    but the API contract itself must not depend on that.
    """
    import sys, time
    from unittest.mock import patch
    import app as app_module

    class FakeOrgWithRepos(FakeOrg):
        def __init__(self, repos):
            super().__init__()
            self._repos = repos

        def get_repos(self):
            return self._repos

    repos = [
        FakeRepo(name="keep-me", branch=FakeBranch(protected=True)),
        FakeRepo(name="exclude-me", branch=FakeBranch(protected=True)),
    ]

    def fake_resolve_target(self, selection):
        return FakeOrgWithRepos(repos)

    with patch("github_auditor.GitHubAuditor._resolve_target", fake_resolve_target), \
         patch("github_auditor.Github", lambda token, retry=None: None):
        client = app_module.create_app().test_client()
        resp = client.post('/api/start-audit', json={
            "token": "fake", "org": "acme", "repos": "keep-me, typo-repo ",
            "account_type": "organization", "standard": "all",
        })
        session_id = resp.get_json()["session_id"]
        status = {}
        for _ in range(40):
            status = client.get(f'/api/audit-status/{session_id}').get_json()
            if status.get("status") in ("completed", "error"):
                break
            time.sleep(0.02)

    assert status["status"] == "completed"
    results = status["results"]
    assert list(results["checks"]["repositories"].keys()) == ["keep-me"]
    assert results["repository_scope"] == ["keep-me", "typo-repo"]
    assert "typo-repo" in results["scope_warning"]


def test_api_normalises_a_list_payload_with_whitespace_and_empties():
    """The browser's JS payload must be held to the same standard as a raw string."""
    import time
    from unittest.mock import patch
    import app as app_module

    class FakeOrgWithRepos(FakeOrg):
        def __init__(self, repos):
            super().__init__()
            self._repos = repos

        def get_repos(self):
            return self._repos

    repos = [FakeRepo(name="keep-me", branch=FakeBranch(protected=True))]

    def fake_resolve_target(self, selection):
        return FakeOrgWithRepos(repos)

    with patch("github_auditor.GitHubAuditor._resolve_target", fake_resolve_target), \
         patch("github_auditor.Github", lambda token, retry=None: None):
        client = app_module.create_app().test_client()
        resp = client.post('/api/start-audit', json={
            "token": "fake", "org": "acme", "repos": [" keep-me ", "", "  "],
            "account_type": "organization", "standard": "all",
        })
        session_id = resp.get_json()["session_id"]
        status = {}
        for _ in range(40):
            status = client.get(f'/api/audit-status/{session_id}').get_json()
            if status.get("status") in ("completed", "error"):
                break
            time.sleep(0.02)

    assert status["status"] == "completed"
    assert status["results"]["repository_scope"] == ["keep-me"]


def test_empty_repos_field_audits_the_full_account():
    """An empty 'repos' input must mean full scope, not zero repositories."""
    import time
    from unittest.mock import patch
    import app as app_module

    class FakeOrgWithRepos(FakeOrg):
        def __init__(self, repos):
            super().__init__()
            self._repos = repos

        def get_repos(self):
            return self._repos

    repos = [FakeRepo(name="a", branch=FakeBranch(protected=True)),
             FakeRepo(name="b", branch=FakeBranch(protected=True))]

    def fake_resolve_target(self, selection):
        return FakeOrgWithRepos(repos)

    with patch("github_auditor.GitHubAuditor._resolve_target", fake_resolve_target), \
         patch("github_auditor.Github", lambda token, retry=None: None):
        client = app_module.create_app().test_client()
        resp = client.post('/api/start-audit', json={
            "token": "fake", "org": "acme", "repos": "",
            "account_type": "organization", "standard": "all",
        })
        session_id = resp.get_json()["session_id"]
        status = {}
        for _ in range(40):
            status = client.get(f'/api/audit-status/{session_id}').get_json()
            if status.get("status") in ("completed", "error"):
                break
            time.sleep(0.02)

    assert status["status"] == "completed"
    assert sorted(status["results"]["checks"]["repositories"].keys()) == ["a", "b"]
    assert status["results"]["repository_scope"] is None


# -- "find repositories, then pick" flow -------------------------------------

def test_list_repositories_returns_metadata_for_the_picker():
    from unittest.mock import patch
    import app as app_module

    class FakeOrgWithRepos(FakeOrg):
        def __init__(self, repos):
            super().__init__()
            self._repos = repos

        def get_repos(self):
            return self._repos

    repos = [
        FakeRepo(name="zeta", private=False),
        FakeRepo(name="alpha", private=True, archived=True),
    ]

    with patch("app.resolve_github_target",
               lambda gh, name, sel: (FakeOrgWithRepos(repos), None)), \
         patch("app.Github", lambda token, retry=None: None):
        client = app_module.create_app().test_client()
        resp = client.post('/api/list-repositories', json={
            "token": "fake", "org": "acme", "account_type": "organization",
        })

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["count"] == 2
    # sorted case-insensitively, not in API order
    assert [r["name"] for r in body["repositories"]] == ["alpha", "zeta"]
    alpha = body["repositories"][0]
    assert alpha["private"] is True
    assert alpha["archived"] is True
    assert body["truncated"] is False


def test_list_repositories_requires_token_and_org():
    import app as app_module

    client = app_module.create_app().test_client()
    resp = client.post('/api/list-repositories', json={"token": "", "org": "acme"})
    assert resp.status_code == 400
    resp2 = client.post('/api/list-repositories', json={"token": "x", "org": ""})
    assert resp2.status_code == 400


def test_list_repositories_surfaces_target_mismatch_warning():
    """Selecting 'user' for a name that is actually an organization warns."""
    from unittest.mock import patch
    import app as app_module

    class FakeOrgWithRepos(FakeOrg):
        def get_repos(self):
            return []

    with patch("app.resolve_github_target",
               lambda gh, name, sel: (FakeOrgWithRepos(), f"'{name}' is an organization...")), \
         patch("app.Github", lambda token, retry=None: None):
        client = app_module.create_app().test_client()
        resp = client.post('/api/list-repositories', json={
            "token": "fake", "org": "acme", "account_type": "user",
        })

    assert resp.status_code == 200
    assert "organization" in resp.get_json()["warning"]


def test_list_repositories_never_leaks_the_token_on_error():
    """The generic-exception path must not include exception text verbatim."""
    from unittest.mock import patch
    import app as app_module

    def boom(gh, name, sel):
        raise RuntimeError(f"connection failed with token {('x' * 40)}")

    with patch("app.resolve_github_target", boom), \
         patch("app.Github", lambda token, retry=None: None):
        client = app_module.create_app().test_client()
        resp = client.post('/api/list-repositories', json={
            "token": "supersecrettoken1234567890", "org": "acme",
        })

    assert resp.status_code == 500
    assert "supersecrettoken1234567890" not in resp.get_data(as_text=True)
    assert "x" * 40 not in resp.get_data(as_text=True)


def test_find_then_select_then_audit_end_to_end():
    """
    The full flow this feature exists for: list repositories, select a
    subset (simulating what the picker's checkboxes send), then start the
    audit scoped to exactly that subset.
    """
    import time
    from unittest.mock import patch
    import app as app_module

    class FakeOrgWithRepos(FakeOrg):
        def __init__(self, repos):
            super().__init__()
            self._repos = repos

        def get_repos(self):
            return self._repos

    repos = [
        FakeRepo(name="api", branch=FakeBranch(protected=True)),
        FakeRepo(name="web", branch=FakeBranch(protected=True)),
        FakeRepo(name="infra", branch=FakeBranch(protected=True)),
    ]
    org_double = FakeOrgWithRepos(repos)

    with patch("app.resolve_github_target", lambda gh, name, sel: (org_double, None)), \
         patch("app.Github", lambda token, retry=None: None):
        client = app_module.create_app().test_client()

        # Step 1: find repositories
        listing = client.post('/api/list-repositories', json={
            "token": "fake", "org": "acme", "account_type": "organization",
        }).get_json()
        found_names = sorted(r["name"] for r in listing["repositories"])
        assert found_names == ["api", "infra", "web"]

    # Step 2: the picker's checkboxes select a subset ("api" and "infra")
    selected = ["api", "infra"]

    # Step 3: start the audit scoped to that subset
    with patch("github_auditor.GitHubAuditor._resolve_target",
               lambda self, sel: org_double), \
         patch("github_auditor.Github", lambda token, retry=None: None):
        resp = client.post('/api/start-audit', json={
            "token": "fake", "org": "acme", "repos": selected,
            "account_type": "organization", "standard": "all",
        })
        session_id = resp.get_json()["session_id"]
        status = {}
        for _ in range(40):
            status = client.get(f'/api/audit-status/{session_id}').get_json()
            if status.get("status") in ("completed", "error"):
                break
            time.sleep(0.02)

    assert status["status"] == "completed"
    audited = sorted(status["results"]["checks"]["repositories"].keys())
    assert audited == ["api", "infra"]
    assert "web" not in status["results"]["checks"]["repositories"]


def test_readme_json_example_keys_match_real_output():
    """
    README's example previously invented 'checks': [...] as a list and a
    'compliance_mapping' block that does not exist in the real output. The
    top-level keys quoted in the example must be keys audit_organization()
    actually writes.
    """
    import inspect
    from github_auditor import GitHubAuditor

    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text()
    source = inspect.getsource(GitHubAuditor.audit_organization)
    for key in ("organization", "account_type", "timestamp",
                "repository_scope", "checks", "summary"):
        assert f'"{key}"' in source, f"audit_organization no longer writes {key!r}"
        assert f'"{key}"' in readme, f"README example is missing {key!r}"
    assert '"compliance_mapping"' not in readme
    assert '"checks": [' not in readme


def test_api_endpoints_doc_lists_the_repository_picker_route():
    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text()
    assert "/api/list-repositories" in readme


# -- repository name on compliance mapping / gap findings --------------------

def sample_multi_repo_results():
    """
    Two repositories where the same check disagrees: passes in one, fails in
    the other. The pre-fix _collect_checks would have shown only one of these
    two facts, arbitrarily.
    """
    org = FakeOrg(owners=["anton"])
    checker = SecurityChecker(org)
    good_repo = FakeRepo(name="good-repo", files={"SECURITY.md": "policy"})
    bad_repo = FakeRepo(name="bad-repo", files={})
    results = {
        "organization": "acme", "account_type": "Organization",
        "target_warning": None, "timestamp": "2026-08-11T00:00:00",
        "checks": {
            "organization": checker.check_organization_settings(),
            "repositories": {
                "good-repo": checker.check_repository(good_repo),
                "bad-repo": checker.check_repository(bad_repo),
            },
        },
    }
    results["summary"] = GitHubAuditor._calculate_summary(
        GitHubAuditor.__new__(GitHubAuditor), results["checks"]
    )
    return results


def test_compliance_mapping_table_shows_repository_per_row():
    from report_generator import ReportGenerator

    gen = ReportGenerator(Cfg())
    html = gen._render_compliance_details_by_check(sample_multi_repo_results())
    assert "Repository" in html
    assert "good-repo" in html
    assert "bad-repo" in html


def test_compliance_mapping_shows_both_outcomes_for_a_disagreeing_check():
    """
    SECURITY.md File passes in good-repo and fails in bad-repo. Both facts
    must appear as separate rows - not one collapsed, arbitrarily-chosen
    answer for both repositories.
    """
    from report_generator import ReportGenerator

    gen = ReportGenerator(Cfg())
    rows = gen._collect_check_rows(sample_multi_repo_results())
    security_md_rows = {
        (repo, r["status"]) for name, repo, r in rows if name == "SECURITY.md File"
    }
    assert ("good-repo", "pass") in security_md_rows
    assert ("bad-repo", "fail") in security_md_rows


def test_gap_table_shows_repository_per_row_and_does_not_undercount():
    from compliance_mapping import COMPLIANCE_MAPPING
    from report_generator import ReportGenerator

    gen = ReportGenerator(Cfg())
    results = sample_multi_repo_results()
    html = gen._render_compliance_gaps(results)
    assert "bad-repo" in html

    rows = gen._collect_check_rows(results)
    # good-repo passed SECURITY.md File specifically - that pair must not be
    # one of the failing rows, even though good-repo fails other checks.
    security_md_failures = {
        repo for name, repo, r in rows
        if name == "SECURITY.md File" and r["status"] == "fail"
    }
    assert "good-repo" not in security_md_failures
    assert "bad-repo" in security_md_failures

    total_failures = sum(1 for n, _, r in rows if r["status"] == "fail" and n in COMPLIANCE_MAPPING)
    assert f"{total_failures} finding(s)" in html


def test_organization_level_rows_are_labelled_organization_not_a_repo_name():
    from report_generator import ReportGenerator

    gen = ReportGenerator(Cfg())
    rows = gen._collect_check_rows(sample_multi_repo_results())
    org_rows = [r for n, r, _ in rows if n == "Organization Owner Count"]
    assert org_rows == ["Organization"]


def test_collect_check_rows_produces_one_row_per_repo_not_collapsed():
    """
    Direct regression test for the defect: previously one dict entry per
    check name meant N repositories running the same check produced 1 row,
    not N.
    """
    from report_generator import ReportGenerator

    gen = ReportGenerator(Cfg())
    rows = gen._collect_check_rows(sample_multi_repo_results())
    repo_activity_repos = {repo for n, repo, _ in rows if n == "Repository Activity"}
    assert repo_activity_repos == {"good-repo", "bad-repo"}


def test_sample_outputs_in_docs_use_the_current_version():
    """
    Sample console/report output quoted in README, QUICKSTART and
    SECURITY_AUDIT.md previously drifted to v1.11.0 while version.py had
    already moved past it. These are illustrative, not generated, so nothing
    updates them automatically - this guard is the only thing that will.

    Only patterns that claim to BE the current tool version are checked -
    "GitHub Security Auditor v1.x" (a version banner) and "Reflects: v1.x" (a
    document's stated baseline). A historical "feature X shipped in v1.9.0"
    reference is not a stale version claim and must not be flagged.
    """
    import re as _re
    from version import __version__

    root = Path(__file__).resolve().parent.parent
    offenders = []
    for name in ("README.md", "QUICKSTART.md", "SECURITY_AUDIT.md"):
        text = (root / name).read_text(encoding="utf-8", errors="replace")
        for match in _re.finditer(
            r"(?:GitHub Security Auditor v|Reflects\*\*: v)(\d+\.\d+\.\d+)", text
        ):
            if match.group(1) != __version__:
                offenders.append(f"{name}: v{match.group(1)} (current: v{__version__})")
    assert offenders == [], offenders


# -- severity-weighted scoring ------------------------------------------------

def test_every_mapped_check_has_a_severity():
    """A check with no severity silently defaults to medium - verify none do."""
    from compliance_mapping import COMPLIANCE_MAPPING, SEVERITY

    missing = sorted(set(COMPLIANCE_MAPPING) - set(SEVERITY))
    assert missing == [], f"checks without an assigned severity: {missing}"
    extra = sorted(set(SEVERITY) - set(COMPLIANCE_MAPPING))
    assert extra == [], f"severities for checks that do not exist: {extra}"


def test_severity_weight_is_monotonic():
    from compliance_mapping import SEVERITY_WEIGHT

    assert SEVERITY_WEIGHT["critical"] > SEVERITY_WEIGHT["high"] > \
           SEVERITY_WEIGHT["medium"] > SEVERITY_WEIGHT["low"]


def _summary_for_single_failure(check_name):
    """Build a minimal realistic bucket (with `details`) failing one check."""
    return GitHubAuditor._calculate_summary(
        GitHubAuditor.__new__(GitHubAuditor),
        {"organization": {
            "passed": 0, "failed": 1, "unknown": 0, "not_applicable": 0,
            "details": {check_name: {"status": FAIL, "message": "x"}},
        }},
    )


def test_a_critical_failure_weighs_more_than_a_low_one():
    """
    The whole point of this feature: one critical failure among otherwise
    passing checks must drag the weighted score down more than one low
    failure among the same checks.
    """
    def score_with_one_failure(failing_check, other_checks):
        details = {failing_check: {"status": FAIL, "message": "x"}}
        details.update({c: {"status": PASS, "message": "ok"} for c in other_checks})
        summary = GitHubAuditor._calculate_summary(
            GitHubAuditor.__new__(GitHubAuditor),
            {"organization": {
                "passed": len(other_checks), "failed": 1,
                "unknown": 0, "not_applicable": 0, "details": details,
            }},
        )
        return summary["weighted_score"], summary["compliance_score"]

    passing = ["Repository Activity", "CODEOWNERS File", "SECURITY.md File"]
    critical_weighted, critical_flat = score_with_one_failure("2FA Enforcement", passing)
    low_weighted, low_flat = score_with_one_failure(".gitignore Configuration", passing)

    # The flat score is identical either way - one failure out of four checks.
    assert critical_flat == low_flat
    # The weighted score is not: a critical failure costs far more.
    assert critical_weighted < low_weighted


def test_severity_breakdown_counts_failures_by_level():
    summary = GitHubAuditor._calculate_summary(
        GitHubAuditor.__new__(GitHubAuditor),
        {"organization": {
            "passed": 0, "failed": 2, "unknown": 0, "not_applicable": 0,
            "details": {
                "2FA Enforcement": {"status": FAIL, "message": "x"},       # critical
                ".gitignore Configuration": {"status": FAIL, "message": "x"},  # low
            },
        }},
    )
    assert summary["severity_breakdown"] == {
        "critical": 1, "high": 0, "medium": 0, "low": 1
    }


def test_risk_level_is_driven_by_the_weighted_score():
    """
    A single critical failure among many passing low-severity checks should
    push risk classification, not be diluted into an equally-weighted average
    that reads as low risk.
    """
    details = {"2FA Enforcement": {"status": FAIL, "message": "x"}}
    details.update({
        name: {"status": PASS, "message": "ok"}
        for name in ["Repository Activity", "CODEOWNERS File", "SECURITY.md File",
                     ".gitignore Configuration", "Repository Visibility",
                     "Build Provenance Attestation"]
    })
    summary = GitHubAuditor._calculate_summary(
        GitHubAuditor.__new__(GitHubAuditor),
        {"organization": {
            "passed": 6, "failed": 1, "unknown": 0, "not_applicable": 0,
            "details": details,
        }},
    )
    # 6/7 flat would read as ~86% (MEDIUM); weighted, one critical failure
    # among mostly low/medium checks should read materially worse.
    assert summary["compliance_score"] > summary["weighted_score"]
    assert summary["risk_level"] in ("HIGH RISK", "CRITICAL RISK")


def test_weighted_score_falls_back_to_flat_score_without_detail_data():
    """
    A bucket with aggregate counts but no `details` mapping (never produced
    by _record(), but a defensive guard against stale or partial data) must
    not silently report weighted_score=0 / CRITICAL RISK.
    """
    summary = GitHubAuditor._calculate_summary(
        GitHubAuditor.__new__(GitHubAuditor),
        {"organization": {"passed": 9, "failed": 1, "unknown": 0, "not_applicable": 0}},
    )
    assert summary["weighted_score"] == summary["compliance_score"] == 90.0
    assert summary["risk_level"] == "LOW RISK"


def test_scoped_standard_summary_is_also_severity_weighted():
    """scope_results_to_standard() recomputes its own summary independently
    of _calculate_summary and must apply the same weighting, not a flat one."""
    from compliance_mapping import resolve_standard, scope_results_to_standard

    results = {"checks": {"organization": {"details": {
        "2FA Enforcement": {"status": "fail", "message": "x"},
        "Repository Activity": {"status": "pass", "message": "ok"},
    }}, "repositories": {}}}
    scoped = scope_results_to_standard(results, resolve_standard("soc2"))
    assert scoped["summary"]["severity_breakdown"]["critical"] == 1
    assert scoped["summary"]["weighted_score"] < scoped["summary"]["compliance_score"]


# -- severity surfaced in the report -----------------------------------------

def test_report_shows_weighted_score_and_severity_breakdown():
    from report_generator import ReportGenerator

    gen = ReportGenerator(Cfg())
    html = gen.generate_html_report(sample_multi_repo_results())
    assert "Weighted Compliance Score" in html
    assert "Unweighted" in html


def test_no_unrendered_placeholders_after_severity_changes():
    """The exact class of bug found in v1.10.1 (a template call printed
    literally because it landed in a plain string, not an f-string)."""
    import re as _re
    from report_generator import ReportGenerator

    for standard in ["soc2", "nist", "iso27001", "cis", "all"]:
        html = ReportGenerator(Cfg(), standard=standard).generate_html_report(
            sample_multi_repo_results()
        )
        leftovers = _re.findall(r"\{self\.\w+[^}]*\}|\{[a-z_]+\}", html)
        assert leftovers == [], f"{standard}: {sorted(set(leftovers))}"


def test_mapping_and_gap_tables_show_a_severity_badge():
    from report_generator import ReportGenerator

    gen = ReportGenerator(Cfg())
    results = sample_multi_repo_results()
    mapping_html = gen._render_compliance_details_by_check(results)
    gap_html = gen._render_compliance_gaps(results)
    assert ">Severity<" in mapping_html
    assert ">Severity<" in gap_html
    assert "critical" in mapping_html  # 2FA Enforcement or similar appears


def test_risk_badge_colour_matches_risk_label():
    """
    _get_risk_css_class previously took a raw score and re-derived thresholds
    independently of risk_level's own thresholds - two copies that could
    disagree. It must now be driven by risk_level directly.
    """
    from report_generator import ReportGenerator

    gen = ReportGenerator(Cfg())
    assert gen._get_risk_css_class("LOW RISK") == "low"
    assert gen._get_risk_css_class("MEDIUM RISK") == "medium"
    assert gen._get_risk_css_class("HIGH RISK") == "high"
    assert gen._get_risk_css_class("CRITICAL RISK") == "critical"


# -- rate-limit backoff visibility --------------------------------------------

def test_retry_policy_is_shared_not_duplicated():
    """Both call sites construct Github() with the same named policy object,
    not two independent GithubRetry() instances that could drift apart."""
    import app as app_module
    import github_auditor

    assert app_module.GITHUB_RETRY_POLICY is github_auditor.GITHUB_RETRY_POLICY


def test_rate_limit_logging_is_configured_and_idempotent():
    """configure_rate_limit_logging() must not install duplicate handlers
    when called repeatedly (both create_app() and GitHubAuditor.__init__()
    call it)."""
    import logging
    from github_auditor import configure_rate_limit_logging, _RATE_LIMIT_LOGGER_NAME

    logger = logging.getLogger(_RATE_LIMIT_LOGGER_NAME)
    logger.handlers.clear()

    configure_rate_limit_logging()
    configure_rate_limit_logging()
    configure_rate_limit_logging()

    stream_handlers = [h for h in logger.handlers if isinstance(h, logging.StreamHandler)]
    assert len(stream_handlers) == 1
    assert logger.level == logging.INFO


def test_github_constructed_with_explicit_retry_policy():
    """
    Regression: relying on Github()'s own default retry object means a future
    PyGithub upgrade could silently change retry behaviour with no signal in
    this codebase. The policy must be passed explicitly.
    """
    import inspect
    import github_auditor

    source = inspect.getsource(github_auditor.GitHubAuditor.__init__)
    assert "retry=GITHUB_RETRY_POLICY" in source


# -- API call deduplication ---------------------------------------------------

def test_repo_actions_permissions_is_fetched_once_not_four_times():
    """
    Four repository-level checks each read /actions/permissions
    independently: Repository Actions Policy, Action SHA Pinning Policy, and
    Fork Pull Request Workflows (twice, via the private/public branches).
    Before caching, a full check_repository() pass made four identical
    requests to the same URL for one repository.
    """
    checker = SecurityChecker(org=None)
    repo = FakeRepo(name="dedup-test", branch=FakeBranch(protected=True), actions={
        "permissions": {
            "enabled": True, "allowed_actions": "selected",
            "sha_pinning_required": True, "fork_pr_workflows_policy": False,
        },
    })

    checker.check_repository(repo)

    permission_calls = [c for c in repo._requester.calls if c.endswith("/actions/permissions")]
    assert len(permission_calls) == 1, (
        f"expected 1 call to /actions/permissions, got {len(permission_calls)}: "
        f"{permission_calls}"
    )


def test_org_workflow_permissions_is_fetched_once_not_twice():
    """
    Actions Default Token Permissions and Actions Pull Request Approval both
    read /actions/permissions/workflow independently at the organization
    level.
    """
    org = FakeOrg(actions={
        "permissions": {"allowed_actions": "selected"},
        "workflow": {"default_workflow_permissions": "read",
                     "can_approve_pull_request_reviews": False},
    })
    checker = SecurityChecker(org)

    checker.check_organization_settings()

    workflow_calls = [c for c in org._requester.calls if c.endswith("/actions/permissions/workflow")]
    assert len(workflow_calls) == 1, (
        f"expected 1 call to /actions/permissions/workflow, got {len(workflow_calls)}: "
        f"{workflow_calls}"
    )


def test_cache_does_not_mix_up_two_different_repositories():
    """
    The cache is keyed by URL, which is unique per repository in real usage.
    Two different repositories with different settings must not leak into
    each other's results.
    """
    checker = SecurityChecker(org=None)
    permissive = FakeRepo(name="repo-a", actions={
        "permissions": {"enabled": True, "allowed_actions": "all"}
    })
    restricted = FakeRepo(name="repo-b", actions={
        "permissions": {"enabled": True, "allowed_actions": "selected"}
    })

    result_a = checker._check_repo_actions_policy(permissive)
    result_b = checker._check_repo_actions_policy(restricted)

    assert result_a["status"] == FAIL   # allowed_actions: all
    assert result_b["status"] == PASS   # allowed_actions: selected


def test_cache_is_fresh_per_security_checker_instance():
    """The cache must not leak across separate audits (separate instances)."""
    repo = FakeRepo(name="app", actions={
        "permissions": {"enabled": True, "allowed_actions": "all"}
    })
    first = SecurityChecker(org=None)._check_repo_actions_policy(repo)
    assert first["status"] == FAIL

    # A fresh checker (a new audit run) must make its own request, not reuse
    # a previous instance's cache - there is no cache to reuse since _api_cache
    # is a fresh dict per instance.
    second_checker = SecurityChecker(org=None)
    assert second_checker._api_cache == {}


# -- history module: compact records and diffing -----------------------------

def test_summarize_repository_computes_weighted_score_and_statuses():
    from history import summarize_repository

    checker = SecurityChecker(FakeOrg())
    repo_checks = checker.check_repository(hardened_repo())
    summary = summarize_repository(repo_checks)

    assert summary["passed"] == repo_checks["passed"]
    assert summary["failed"] == repo_checks["failed"]
    assert "Branch Protection Rules" in summary["statuses"]
    assert summary["statuses"]["Branch Protection Rules"] == "pass"
    assert 0 <= summary["weighted_score"] <= 100


def test_build_history_entry_excludes_messages_and_usernames():
    """
    History is for tracking trends across many runs; every field added here
    is multiplied by every run ever stored. Full messages, guidance text, and
    the access inventory (usernames) must not be included.
    """
    from history import build_history_entry

    results = sample_multi_repo_results()
    entry = build_history_entry(results)

    assert "org" in entry and "summary" in entry and "repositories" in entry
    dumped = json.dumps(entry)
    # A distinctive phrase from a real check message must not appear -
    # confirms full text was not carried into the compact record.
    assert "Add patterns such as .env" not in dumped
    assert "access_inventory" not in dumped


def test_find_previous_run_matches_by_org_case_insensitively():
    from history import find_previous_run

    history = {
        "old": {"org": "Acme", "timestamp": "2026-01-01T00:00:00", "repositories": {}},
        "newer": {"org": "acme", "timestamp": "2026-02-01T00:00:00", "repositories": {}},
        "other-org": {"org": "other", "timestamp": "2026-03-01T00:00:00", "repositories": {}},
    }
    found = find_previous_run(history, "ACME", "Organization")
    assert found["session_id"] == "newer"


def test_find_previous_run_skips_legacy_entries_without_repositories():
    """Entries written before this module existed have no 'repositories' key
    and cannot be diffed against - they must be skipped, not crash the lookup."""
    from history import find_previous_run

    history = {
        "legacy": {"org": "acme", "timestamp": "2026-01-01T00:00:00", "score": 70.0},
    }
    assert find_previous_run(history, "acme", "Organization") is None


def test_find_previous_run_returns_none_when_no_match():
    from history import find_previous_run

    assert find_previous_run({}, "acme", "Organization") is None
    assert find_previous_run(
        {"x": {"org": "other", "timestamp": "t", "repositories": {}}},
        "acme", "Organization",
    ) is None


def test_diff_repository_statuses_classifies_transitions():
    from history import diff_repository_statuses

    previous = {"A": "pass", "B": "fail", "C": "pass", "D": "unknown"}
    current = {"A": "fail", "B": "pass", "C": "pass", "D": "not_applicable"}

    diff = diff_repository_statuses(previous, current)
    assert diff["newly_failing"] == ["A"]
    assert diff["newly_passing"] == ["B"]
    assert any("D" in c for c in diff["coverage_changed"])


def test_diff_runs_identifies_new_and_removed_repositories():
    from history import diff_runs

    previous = {"repositories": {"old-repo": {"weighted_score": 50, "statuses": {}}}}
    current = {"repositories": {"new-repo": {"weighted_score": 80, "statuses": {}}}}

    diff = diff_runs(previous, current)
    assert diff["new_repositories"] == ["new-repo"]
    assert diff["removed_repositories"] == ["old-repo"]
    assert diff["repository_diffs"] == {}


def test_diff_runs_full_scenario_matches_the_original_defect_report():
    """
    A repository that fixed one check and regressed on none must show a
    positive score delta and exactly one newly-passing entry, with no
    unrelated repository affected.
    """
    from history import summarize_repository, diff_runs

    checker = SecurityChecker(FakeOrg())
    before = FakeRepo(name="api", files={})
    after = FakeRepo(name="api", files={"SECURITY.md": "x"})

    previous = {"repositories": {"api": summarize_repository(checker.check_repository(before))}}
    current = {"repositories": {"api": summarize_repository(checker.check_repository(after))}}

    diff = diff_runs(previous, current)
    api_diff = diff["repository_diffs"]["api"]
    assert "SECURITY.md File" in api_diff["newly_passing"]
    assert api_diff["newly_failing"] == []
    assert api_diff["score_delta"] > 0


# -- history surfaced in the web app and report -------------------------------

def test_history_route_groups_runs_by_organization():
    import app as app_module

    client = app_module.create_app().test_client()
    app_module.audit_history.clear()
    app_module.audit_history.update({
        "s1": {"org": "acme", "timestamp": "2026-01-01T00:00:00",
               "summary": {"weighted_score": 60.0, "risk_level": "HIGH RISK"},
               "repositories": {"api": {}}},
        "s2": {"org": "acme", "timestamp": "2026-02-01T00:00:00",
               "summary": {"weighted_score": 80.0, "risk_level": "MEDIUM RISK"},
               "repositories": {"api": {}}},
        "s3": {"org": "other", "timestamp": "2026-01-15T00:00:00",
               "summary": {"weighted_score": 40.0, "risk_level": "CRITICAL RISK"},
               "repositories": {}},
    })
    html = client.get('/history').get_data(as_text=True)
    assert html.count(">acme<") >= 1
    assert html.count(">other<") >= 1
    # newest-first within a group: 80.0 (2026-02-01) must appear before 60.0
    assert html.index("80.0%") < html.index("60.0%")


def test_history_route_trend_arrow_is_real_markup_not_escaped():
    """Regression: Jinja autoescape turned the trend arrow's <span> into
    literal '&lt;span&gt;' text until marked with the |safe filter."""
    import app as app_module

    client = app_module.create_app().test_client()
    app_module.audit_history.clear()
    app_module.audit_history.update({
        "s1": {"org": "acme", "timestamp": "2026-01-01T00:00:00",
               "summary": {"weighted_score": 60.0, "risk_level": "HIGH RISK"},
               "repositories": {}},
        "s2": {"org": "acme", "timestamp": "2026-02-01T00:00:00",
               "summary": {"weighted_score": 80.0, "risk_level": "MEDIUM RISK"},
               "repositories": {}},
    })
    html = client.get('/history').get_data(as_text=True)
    assert '<span style="color: #3fb950;">' in html
    assert "&lt;span" not in html


def test_history_route_handles_legacy_entries_without_summary():
    """Old-format entries (org/timestamp/score only) must render without
    crashing the page, using the numeric fallback documented in risk_css."""
    import app as app_module

    client = app_module.create_app().test_client()
    app_module.audit_history.clear()
    app_module.audit_history["legacy"] = {
        "org": "acme", "timestamp": "2026-01-01T00:00:00", "score": 95.0
    }
    resp = client.get('/history')
    assert resp.status_code == 200
    assert "acme" in resp.get_data(as_text=True)


def test_report_renders_comparison_section_when_present():
    from report_generator import ReportGenerator

    results = sample_multi_repo_results()
    results["comparison"] = {
        "previous_session_id": "prev", "previous_timestamp": "2026-08-01T00:00:00",
        "weighted_score_delta": 12.5, "new_repositories": [], "removed_repositories": [],
        "repository_diffs": {
            "bad-repo": {"newly_failing": [], "newly_passing": ["SECURITY.md File"],
                        "coverage_changed": [], "score_delta": 5.0},
        },
        "unchanged_repository_count": 0,
    }
    html = ReportGenerator(Cfg()).generate_html_report(results)
    assert "Changes since the previous audit" in html
    assert "Newly passing" in html
    assert "+12.5 pts" in html


def test_report_omits_comparison_section_on_first_audit():
    from report_generator import ReportGenerator

    html = ReportGenerator(Cfg()).generate_html_report(sample_multi_repo_results())
    assert "Changes since the previous audit" not in html


# -- token visibility gap detection -------------------------------------------

def test_visibility_gap_is_detected_when_token_sees_fewer_repos():
    """
    A fine-grained token scoped to a subset of an organization's repositories
    enumerates that subset with no error - the gap is only detectable by
    comparing against the account's own reported total.
    """
    auditor = GitHubAuditor.__new__(GitHubAuditor)
    org = FakeOrg()
    org.public_repos = 30
    org.total_private_repos = 10
    auditor.org = org

    visible_repos = [object()] * 3  # token can only see 3 of 40
    result = auditor._check_repo_visibility(visible_repos)

    assert result["confidence"] == "gap"
    assert result["visible_count"] == 3
    assert result["expected_total"] == 40
    assert result["gap"] == 37


def test_visibility_confirmed_when_counts_match():
    auditor = GitHubAuditor.__new__(GitHubAuditor)
    org = FakeOrg()
    org.public_repos = 2
    org.total_private_repos = 0
    auditor.org = org

    result = auditor._check_repo_visibility([object(), object()])
    assert result["confidence"] == "confirmed"
    assert result["gap"] == 0


def test_visibility_unconfirmed_when_totals_not_exposed_by_the_api():
    """
    A plain org member's token, or a personal account viewed by someone other
    than its owner, may not have public_repos/total_private_repos populated
    by the API at all. This must report 'unconfirmed', never a false 'gap'
    or a false 'confirmed'.
    """
    class RestrictedOrg(FakeOrg):
        @property
        def public_repos(self):
            raise Exception("field not present")

        @property
        def total_private_repos(self):
            raise Exception("field not present")

    auditor = GitHubAuditor.__new__(GitHubAuditor)
    auditor.org = RestrictedOrg()

    result = auditor._check_repo_visibility([object()] * 5)
    assert result["confidence"] == "unconfirmed"
    assert result["expected_total"] is None
    assert result["visible_count"] == 5


def test_visibility_gap_never_reported_as_negative():
    """If the token somehow sees MORE than the reported total (a race between
    the count and the listing, or a stale cached total), the gap must not go
    negative and read as a phantom shortfall."""
    auditor = GitHubAuditor.__new__(GitHubAuditor)
    org = FakeOrg()
    org.public_repos = 1
    org.total_private_repos = 0
    auditor.org = org

    result = auditor._check_repo_visibility([object(), object()])
    assert result["confidence"] == "confirmed"
    assert result["gap"] == 0


# -- scope banner reflects visibility -----------------------------------------

def test_scope_banner_states_gap_prominently():
    from report_generator import ReportGenerator

    results = sample_multi_repo_results()
    results["repository_visibility"] = {
        "confidence": "gap", "visible_count": 3, "expected_total": 40, "gap": 37,
    }
    html = ReportGenerator(Cfg())._render_scope_banner(results)
    assert "Partial coverage" in html
    assert "3 of 40" in html
    assert "Grant the token access" in html


def test_scope_banner_does_not_claim_full_account_when_unconfirmed():
    from report_generator import ReportGenerator

    results = sample_multi_repo_results()
    results["repository_visibility"] = {
        "confidence": "unconfirmed", "visible_count": 5,
        "expected_total": None, "gap": None,
    }
    html = ReportGenerator(Cfg())._render_scope_banner(results)
    assert "Full account" not in html
    assert "cannot be confirmed" in html


def test_scope_banner_confirms_full_account_only_when_counts_match():
    from report_generator import ReportGenerator

    results = sample_multi_repo_results()
    results["repository_visibility"] = {
        "confidence": "confirmed", "visible_count": 2, "expected_total": 2, "gap": 0,
    }
    html = ReportGenerator(Cfg())._render_scope_banner(results)
    assert "Full account: all repositories were audited (token visibility confirmed)" in html


def test_scope_banner_handles_missing_visibility_field_gracefully():
    """Older results (pre-upgrade, or a test fixture) with no
    repository_visibility key at all must not crash the banner."""
    from report_generator import ReportGenerator

    results = sample_multi_repo_results()
    results.pop("repository_visibility", None)
    html = ReportGenerator(Cfg())._render_scope_banner(results)
    assert "Full account" in html


# -- not_applicable reason categories -----------------------------------------

def test_free_plan_private_repo_gives_plan_restricted_reason():
    """
    When protection is not_enforceable (the plan blocks it outright), every
    dependent check must carry the plan_restricted reason, not a generic or
    prerequisite-failed one - the plan is the actual, single root cause here.
    """
    org = FakeOrg()
    repo = FakeRepo(private=True, branch=FakeBranch(protected=False))
    checker = SecurityChecker(org, plan_name="free")
    details = checker.check_repository(repo)["details"]

    assert details["Branch Protection Rules"]["reason_category"] == "plan_restricted"
    for name in DEPENDENT_CHECKS:
        assert details[name]["reason_category"] == "plan_restricted", name


def test_unconfigured_protection_on_paid_plan_gives_prerequisite_failed():
    """
    A paid-plan repository that simply never had branch protection turned on
    is not a plan limitation - the dependent checks must say
    'prerequisite_failed', not 'plan_restricted', so nobody escalates a
    configuration gap to a billing decision it isn't.
    """
    org = FakeOrg()
    repo = FakeRepo(private=False, branch=FakeBranch(protected=False))
    checker = SecurityChecker(org, plan_name="team")
    details = checker.check_repository(repo)["details"]

    assert details["Branch Protection Rules"]["status"] == "fail"
    for name in DEPENDENT_CHECKS:
        assert details[name]["reason_category"] == "prerequisite_failed", name


def test_no_workflows_gives_structural_reason():
    repo = FakeRepo()  # no workflows configured
    details = SecurityChecker(org=None).check_repository(repo)["details"]
    for name in ["Action Version Pinning", "Workflow Permissions Declared",
                 "Untrusted Workflow Triggers", "Self-Hosted Runner Exposure",
                 "Build Provenance Attestation"]:
        assert details[name]["reason_category"] == "structural", name


def test_personal_account_org_checks_give_structural_reason():
    result = SecurityChecker(FakePersonalAccount()).check_organization_settings()
    for name, detail in result["details"].items():
        assert detail["reason_category"] == "structural", name


def test_pass_and_fail_results_carry_no_reason_category_confusion():
    """pass/fail/unknown results should not accidentally carry a leftover
    reason_category key from a previous not_applicable() call pattern."""
    good = SecurityChecker(FakeOrg()).check_organization_settings()["details"]
    for name, detail in good.items():
        if detail["status"] in ("pass", "fail", "unknown"):
            assert "reason_category" not in detail, name


# -- plan-restricted findings surfaced in the report --------------------------

def test_report_shows_plan_restricted_section_when_present():
    from report_generator import ReportGenerator

    org = FakeOrg()
    repo = FakeRepo(name="private-free", private=True, branch=FakeBranch(protected=False))
    checker = SecurityChecker(org, plan_name="free")
    results = {
        "organization": "acme", "account_type": "Organization",
        "target_warning": None, "timestamp": "2026-08-13T00:00:00",
        "repository_visibility": None,
        "checks": {"organization": checker.check_organization_settings(),
                   "repositories": {"private-free": checker.check_repository(repo)}},
    }
    results["summary"] = GitHubAuditor._calculate_summary(
        GitHubAuditor.__new__(GitHubAuditor), results["checks"]
    )
    html = ReportGenerator(Cfg()).generate_html_report(results)
    assert "blocked by the current GitHub plan" in html
    assert "private-free" in html
    assert "10 control(s) blocked" in html


def test_report_omits_plan_restricted_section_when_none_exist():
    from report_generator import ReportGenerator

    html = ReportGenerator(Cfg()).generate_html_report(sample_multi_repo_results())
    assert "blocked by the current GitHub plan" not in html


# -- pass_rate_of_total_scope: the conservative third metric -----------------

def test_pass_rate_of_total_scope_is_the_conservative_denominator():
    summary = GitHubAuditor._calculate_summary(
        GitHubAuditor.__new__(GitHubAuditor),
        {"organization": {"passed": 11, "failed": 8, "unknown": 6, "not_applicable": 15,
                          "details": {
                              **{f"p{i}": {"status": PASS, "message": "ok"} for i in range(11)},
                              **{f"f{i}": {"status": FAIL, "message": "x"} for i in range(8)},
                          }}},
    )
    # 11 passed out of 40 total (11+8+6+15) = 27.5%, distinct from
    # compliance_score (11 of 19 evaluated = 57.9%)
    assert summary["pass_rate_of_total_scope"] == 27.5
    assert summary["compliance_score"] > summary["pass_rate_of_total_scope"]


def test_pass_rate_of_total_scope_equals_compliance_score_at_full_coverage():
    """When every check was evaluated, the conservative and flat figures
    must be identical - there is nothing left to be conservative about."""
    summary = GitHubAuditor._calculate_summary(
        GitHubAuditor.__new__(GitHubAuditor),
        {"organization": {"passed": 8, "failed": 2, "unknown": 0, "not_applicable": 0,
                          "details": {
                              **{f"p{i}": {"status": PASS, "message": "ok"} for i in range(8)},
                              **{f"f{i}": {"status": FAIL, "message": "x"} for i in range(2)},
                          }}},
    )
    assert summary["pass_rate_of_total_scope"] == summary["compliance_score"] == 80.0


def test_scoped_standard_summary_also_carries_pass_rate_of_total_scope():
    from compliance_mapping import resolve_standard, scope_results_to_standard

    results = {"checks": {"organization": {"details": {
        "2FA Enforcement": {"status": "pass", "message": "ok"},
        "SSO Configuration": {"status": "unknown", "message": "x"},
    }}, "repositories": {}}}
    scoped = scope_results_to_standard(results, resolve_standard("soc2"))
    assert "pass_rate_of_total_scope" in scoped["summary"]
    assert scoped["summary"]["pass_rate_of_total_scope"] == 50.0


def test_report_header_warns_when_coverage_is_low():
    from report_generator import ReportGenerator

    results = sample_multi_repo_results()
    assert results["summary"]["low_coverage"]  # sanity: this fixture IS low coverage
    html = ReportGenerator(Cfg()).generate_html_report(results)
    assert "confirmed passing" in html
    assert "most controls could not be evaluated" in html


def test_report_header_omits_low_coverage_warning_at_full_coverage():
    from report_generator import ReportGenerator

    org = FakeOrg()
    repo = FakeRepo(name="app", branch=FakeBranch(protected=True))
    checker = SecurityChecker(org)
    results = {
        "organization": "acme", "account_type": "Organization",
        "target_warning": None, "timestamp": "2026-08-13T00:00:00",
        "repository_visibility": None,
        "checks": {"organization": checker.check_organization_settings(),
                   "repositories": {"app": checker.check_repository(repo)}},
    }
    results["summary"] = GitHubAuditor._calculate_summary(
        GitHubAuditor.__new__(GitHubAuditor), results["checks"]
    )
    html = ReportGenerator(Cfg()).generate_html_report(results)
    if not results["summary"]["low_coverage"]:
        assert "most controls could not be evaluated" not in html


# -- owner category and severity-sorted gap table -----------------------------

def test_every_mapped_check_has_an_owner_category():
    from compliance_mapping import COMPLIANCE_MAPPING, OWNER_CATEGORY

    missing = sorted(set(COMPLIANCE_MAPPING) - set(OWNER_CATEGORY))
    assert missing == [], f"checks without an owner category: {missing}"
    extra = sorted(set(OWNER_CATEGORY) - set(COMPLIANCE_MAPPING))
    assert extra == [], f"owner categories for checks that do not exist: {extra}"
    assert set(OWNER_CATEGORY.values()) == {
        "Organization owner", "Repository admin", "Engineering team"
    }


def test_org_only_checks_are_organization_owner_category():
    from compliance_mapping import owner_category_for

    for name in ["2FA Enforcement", "SSO Configuration", "Organization Owner Count",
                 "Actions Allowed Actions Policy"]:
        assert owner_category_for(name) == "Organization owner"


def test_documentation_checks_are_engineering_team_category():
    from compliance_mapping import owner_category_for

    for name in ["SECURITY.md File", "CODEOWNERS File", ".gitignore Configuration",
                 "Action Version Pinning"]:
        assert owner_category_for(name) == "Engineering team"


def test_gap_table_sorts_critical_findings_first():
    from compliance_mapping import severity_for, COMPLIANCE_MAPPING
    from report_generator import ReportGenerator

    gen = ReportGenerator(Cfg())
    html = gen._render_compliance_gaps(sample_multi_repo_results())
    rows = html.split('<tr style="border-bottom')[1:]

    seen_severities = []
    for row in rows:
        for name in COMPLIANCE_MAPPING:
            if f">{name}<" in row:
                seen_severities.append(severity_for(name))
                break

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ranks = [order[s] for s in seen_severities]
    assert ranks == sorted(ranks), f"gap table not sorted by severity: {seen_severities}"


def test_gap_table_shows_owner_column():
    from report_generator import ReportGenerator

    gen = ReportGenerator(Cfg())
    html = gen._render_compliance_gaps(sample_multi_repo_results())
    assert ">Owner<" in html
    assert "Engineering team" in html or "Repository admin" in html or "Organization owner" in html


def test_gap_table_owner_matches_the_check_that_failed():
    """The Owner column value on each row must correspond to that row's own
    check, not a stray value copied from elsewhere in the table."""
    from compliance_mapping import owner_category_for
    from report_generator import ReportGenerator

    org = FakeOrg(two_factor=False)  # 2FA Enforcement fails -> Organization owner
    checker = SecurityChecker(org)
    results = {
        "organization": "acme", "account_type": "Organization",
        "target_warning": None, "timestamp": "2026-08-13T00:00:00",
        "repository_visibility": None,
        "checks": {"organization": checker.check_organization_settings(), "repositories": {}},
    }
    results["summary"] = GitHubAuditor._calculate_summary(
        GitHubAuditor.__new__(GitHubAuditor), results["checks"]
    )
    html = ReportGenerator(Cfg())._render_compliance_gaps(results)
    row = [r for r in html.split('<tr style="border-bottom')[1:]
           if "2FA Enforcement" in r][0]
    assert owner_category_for("2FA Enforcement") in row


def test_failed_checks_summary_sorts_by_severity_within_each_repository():
    """Repository grouping (this table's distinct purpose) must be preserved,
    with severity ordering applied only within each repository's own block."""
    from compliance_mapping import severity_for, COMPLIANCE_MAPPING
    from report_generator import ReportGenerator

    org = FakeOrg()
    checker = SecurityChecker(org)
    repo_a = FakeRepo(name="a", branch=FakeBranch(protected=False))
    repo_b = FakeRepo(name="b", branch=FakeBranch(protected=False))
    repos = {"a": checker.check_repository(repo_a), "b": checker.check_repository(repo_b)}

    html = ReportGenerator(Cfg())._render_failed_checks_summary(repos)
    rows = html.split('<tr style="border-bottom')[1:]

    seen = []
    for row in rows:
        repo = "a" if 'color: var(--primary);">\n                    a\n' in row else "b"
        for name in COMPLIANCE_MAPPING:
            if f">{name}<" in row:
                seen.append((repo, severity_for(name)))
                break

    # repo "a" rows must all precede repo "b" rows
    repo_order = [r for r, _ in seen]
    a_indices = [i for i, r in enumerate(repo_order) if r == "a"]
    b_indices = [i for i, r in enumerate(repo_order) if r == "b"]
    assert not a_indices or not b_indices or max(a_indices) < min(b_indices)

    # within each repo, severity is non-decreasing
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for repo in ("a", "b"):
        ranks = [order[s] for r, s in seen if r == repo]
        assert ranks == sorted(ranks), f"repo {repo} not severity-sorted: {ranks}"


def test_failed_checks_summary_shows_owner_column():
    from report_generator import ReportGenerator

    org = FakeOrg()
    checker = SecurityChecker(org)
    repo = FakeRepo(name="app", branch=FakeBranch(protected=False))
    html = ReportGenerator(Cfg())._render_failed_checks_summary(
        {"app": checker.check_repository(repo)}
    )
    assert ">Owner<" in html
