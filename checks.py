"""
GitHub Security Checks

40 checks (9 organization-level, 31 repository-level) executed against the
real GitHub REST API via PyGithub, plus an unscored access inventory.

The exact count is derived from the check engine and the compliance mapping,
never restated here as a fixed number - see
`compliance_mapping.checks_for_standard(None)` and
`tests/test_check_count_claims_match_the_code`, which fails if any file
(including this one) states a count the engine does not match.

Every check returns a four-state result:

    {"status": "pass" | "fail" | "unknown" | "not_applicable",
     "passed": bool, "message": str}

"unknown" means the check could not be evaluated (missing permission, plan
restriction, unrecognised API field). "not_applicable" means the control does
not apply here (wrong account type, plan restriction, or a prerequisite
control already failed). Both are EXCLUDED from the compliance score - a
missing permission and a control that cannot exist for this account are
neither of them a security finding.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from github.GithubException import GithubException

PASS = "pass"
FAIL = "fail"
UNKNOWN = "unknown"
NOT_APPLICABLE = "not_applicable"

#: Statuses excluded from the compliance score.
UNSCORED = (UNKNOWN, NOT_APPLICABLE)


def _result(status: str, message: str) -> Dict[str, Any]:
    """Build a check result. `passed` is kept for backwards compatibility."""
    return {"status": status, "passed": status == PASS, "message": message}


def ok(message: str) -> Dict[str, Any]:
    return _result(PASS, message)


def fail(message: str) -> Dict[str, Any]:
    return _result(FAIL, message)


def unknown(message: str) -> Dict[str, Any]:
    return _result(UNKNOWN, message)


#: Categories a NOT_APPLICABLE result can carry, distinguishing *why* a
#: control does not apply - which determines who can act on it and how:
#:
#:   structural         - genuinely never applies here (no workflows to pin,
#:                         an organization-only setting on a personal account,
#:                         no rulesets defined). Nothing to do, ever.
#:   plan_restricted     - blocked by the current GitHub plan (branch
#:                         protection unenforceable on a private repo under
#:                         Free). Fixable by a plan/billing decision.
#:   prerequisite_failed - contingent on a sibling control that already
#:                         failed and reported the finding (nine checks depend
#:                         on Branch Protection Rules; repeating the same
#:                         finding nine times would let one setting dominate
#:                         the score). Look at the named prerequisite instead.
REASON_STRUCTURAL = "structural"
REASON_PLAN_RESTRICTED = "plan_restricted"
REASON_PREREQUISITE_FAILED = "prerequisite_failed"


def not_applicable(message: str, reason_category: str = REASON_STRUCTURAL) -> Dict[str, Any]:
    """
    The control cannot apply here. Excluded from the score so that one root
    cause produces one finding instead of ten.

    `reason_category` distinguishes structural (never applies), plan-caused
    (fixable by upgrading), and prerequisite-contingent (the finding lives on
    a sibling check) - see the REASON_* constants above. Reports downstream
    use this to route a plan-caused finding to whoever makes billing
    decisions rather than burying it among controls that will never apply
    under any plan.
    """
    result = _result(NOT_APPLICABLE, message)
    result["reason_category"] = reason_category
    return result


def _from_exception(exc: Exception, what: str) -> Dict[str, Any]:
    """Translate an API exception into an honest result state."""
    status = getattr(exc, "status", None)
    if status == 403:
        return unknown(f"{what}: token lacks the required permission (403)")
    if status == 404:
        return unknown(f"{what}: not available for this account or plan (404)")
    if status == 401:
        return unknown(f"{what}: token is invalid or expired (401)")
    if isinstance(exc, GithubException):
        return unknown(f"{what}: GitHub API error {status}")
    return unknown(f"{what}: {type(exc).__name__}")


class ProtectionFacts:
    """
    Normalised view of default-branch protection, merged from classic branch
    protection and repository rulesets. `None` means "not determined", which is
    deliberately distinct from `False` ("determined to be off").
    """

    def __init__(self):
        self.state = UNKNOWN
        self.source = None
        self.reason = None
        self.review_count = None
        self.dismiss_stale = False
        self.code_owner_review = False
        self.status_contexts = []
        self.enforce_admins = None
        self.linear_history = False
        self.block_force_push = None
        self.block_deletion = None
        self.signatures_classic = None
        self.signatures_ruleset = None
        self.last_push_approval = False
        self.org_enforced = False
        self.plan_caveat = False
        self.unrecognised_rules = set()

    # -- classic branch protection ---------------------------------------

    def apply_classic(self, protection) -> None:
        reviews = getattr(protection, "required_pull_request_reviews", None)
        if reviews is not None:
            self.review_count = getattr(reviews, "required_approving_review_count", 0) or 0
            self.dismiss_stale |= bool(getattr(reviews, "dismiss_stale_reviews", False))
            self.code_owner_review |= bool(getattr(reviews, "require_code_owner_reviews", False))

        status_checks = getattr(protection, "required_status_checks", None)
        if status_checks is not None:
            self.status_contexts += list(getattr(status_checks, "contexts", []) or [])

        self.enforce_admins = bool(getattr(protection, "enforce_admins", False))
        self.linear_history |= bool(getattr(protection, "required_linear_history", False))

        raw = getattr(protection, "raw_data", None)
        if isinstance(raw, dict):
            force = raw.get("allow_force_pushes", {})
            deletions = raw.get("allow_deletions", {})
            if isinstance(force, dict) and "enabled" in force:
                self.block_force_push = not force["enabled"]
            if isinstance(deletions, dict) and "enabled" in deletions:
                self.block_deletion = not deletions["enabled"]

    # -- rulesets ---------------------------------------------------------

    #: Rule types that actually govern a branch. The /rules/branches/{b}
    #: endpoint also returns organization-level repository rules
    #: (repository_visibility, repository_name, repository_create, ...) which
    #: say nothing about branch protection. Observed live on
    #: hashicorp/terraform. Counting those as protection would mark a branch
    #: "protected" and then fail every dependent control.
    REPOSITORY_RULE_TYPES = frozenset({
        "repository_visibility", "repository_name", "repository_create",
        "repository_delete", "repository_transfer", "file_path_restriction",
        "max_file_size", "file_extension_restriction",
    })

    BRANCH_RULE_TYPES = frozenset({
        "creation", "update", "deletion", "non_fast_forward",
        "pull_request", "required_status_checks", "required_signatures",
        "required_linear_history", "required_deployments", "merge_queue",
        "workflows", "code_scanning", "copilot_code_review",
        "commit_message_pattern", "commit_author_email_pattern",
        "committer_email_pattern", "branch_name_pattern",
    })

    def apply_rules(self, rules) -> bool:
        """
        Merge active ruleset rules. Presence of a rule means the behaviour is
        enforced: a "deletion" rule blocks deletion, "non_fast_forward" blocks
        force pushes.

        Field names verified against live responses from rust-lang/rust,
        github/docs, microsoft/vscode, actions/checkout and vercel/next.js.
        """
        if not rules:
            return False

        seen = False
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            rtype = rule.get("type")
            if rtype in self.REPOSITORY_RULE_TYPES:
                continue  # repository- or org-scoped rule, not branch protection
            if rtype not in self.BRANCH_RULE_TYPES:
                # GitHub ships new rule types continuously (code quality and code
                # coverage rules appeared in the UI after this list was written).
                # Record rather than ignore, so an unfamiliar ruleset is reported
                # as unknown instead of as an unprotected branch.
                self.unrecognised_rules.add(rtype)
                continue
            params = rule.get("parameters") or {}
            seen = True

            if rule.get("ruleset_source_type") == "Organization":
                self.org_enforced = True

            if rtype == "pull_request":
                count = params.get("required_approving_review_count", 0) or 0
                self.review_count = max(self.review_count or 0, count)
                self.dismiss_stale |= bool(params.get("dismiss_stale_reviews_on_push"))
                self.code_owner_review |= bool(params.get("require_code_owner_review"))
                self.last_push_approval |= bool(params.get("require_last_push_approval"))
            elif rtype == "required_status_checks":
                self.status_contexts += [
                    c.get("context")
                    for c in params.get("required_status_checks", []) or []
                    if isinstance(c, dict)
                ]
            elif rtype == "required_linear_history":
                self.linear_history = True
            elif rtype == "required_signatures":
                self.signatures_ruleset = True
            elif rtype == "non_fast_forward":
                self.block_force_push = True
            elif rtype == "deletion":
                self.block_deletion = True

        if seen:
            # A rule absent from an active ruleset is off, not unknown.
            if self.block_force_push is None:
                self.block_force_push = False
            if self.block_deletion is None:
                self.block_deletion = False
        return seen

    def required_signatures(self):
        if self.signatures_ruleset:
            return True
        return self.signatures_classic


class SecurityChecker:
    """GitHub security checks implementation."""

    STALE_AFTER_DAYS = 365

    def __init__(self, org, verbose: bool = False, plan_name: Optional[str] = None,
                 account_type: Optional[str] = None):
        self.org = org
        self.verbose = verbose
        #: "Organization" or "User". Organization-scoped controls do not exist
        #: on a personal account, which is different from being unreadable.
        self.account_type = account_type or self._detect_account_type()
        self._access = None
        #: Cache for _api_get(), keyed by exact URL. Scoped to this
        #: instance's lifetime, i.e. one audit run - see _api_get's docstring.
        self._api_cache = {}
        # Classic branch protection and rulesets are not configurable on private
        # repositories under GitHub Free. Reporting them as failures would blame
        # the user for something the account cannot enable.
        self.plan_name = plan_name if plan_name is not None else self._detect_plan()

    def _detect_account_type(self) -> str:
        """
        Distinguish an organization from a personal account.

        PyGithub returns Organization or NamedUser/AuthenticatedUser. The
        organization-only attributes are the reliable discriminator, because
        the `type` field is not always populated on a lazily loaded object.
        """
        explicit = getattr(self.org, "type", None)
        if explicit in ("Organization", "User"):
            return explicit
        try:
            # Present as a property on Organization, absent on NamedUser.
            # Checked on the instance so that a lazily loaded object still
            # answers correctly.
            if hasattr(self.org, "default_repository_permission"):
                return "Organization"
        except Exception:
            pass
        return "User"

    @property
    def is_organization(self) -> bool:
        return self.account_type == "Organization"

    def _org_only(self, control: str) -> Optional[Dict[str, Any]]:
        """
        Short-circuit for controls that exist only on organizations.

        Returning `unknown` here would be wrong twice over: it implies the
        setting exists and that the token merely cannot read it, sending the
        reader to look for a page that a personal account does not have.
        """
        if self.is_organization:
            return None
        return not_applicable(
            f"{control} is an organization setting. This account is a personal "
            "account, which has no membership policy to configure"
        )

    def _detect_plan(self) -> Optional[str]:
        try:
            plan = getattr(self.org, "plan", None)
            return getattr(plan, "name", None)
        except Exception:
            return None

    def _enforcement(self, repo) -> str:
        """
        Whether branch protection is actually enforced for this repository.

        GitHub lets a ruleset be created on a private repository under a free
        plan and then does not enforce it, showing only a banner. Confirmed on
        both account types:

          personal account: "Your rulesets won't be enforced on this private
            repository until you move to GitHub Team organization account."
          free organization: "Your rulesets won't be enforced on this private
            repository until you upgrade this organization account to GitHub
            Team."

        That produces a state the API cannot be trusted on: rules exist, the
        branch is not protected. Reporting a pass there would be worse than any
        false failure, so it is treated as its own finding.

        The banner names rulesets specifically in both confirmed cases, and
        nothing else. It says nothing about classic branch protection, and the
        same banner appears on Settings > Actions > Policies, which is also
        ruleset-backed. This return value gates ruleset-derived facts only;
        classic branch protection, when present, is trusted regardless of it -
        see the caller in `_get_protection`.

        Returns "enforced", "not_enforced" or "unknown".
        """
        if not getattr(repo, "private", False):
            return "enforced"
        if self.plan_name == "free":
            return "not_enforced"
        if not self.is_organization:
            # The banner names a GitHub Team *organization* as the requirement,
            # so a paid personal plan is not established to lift the restriction.
            return "unknown"
        if self.plan_name is None:
            return "unknown"
        return "enforced"

    # ------------------------------------------------------------------
    # Result accumulation
    # ------------------------------------------------------------------

    @staticmethod
    def _new_bucket() -> Dict[str, Any]:
        return {
            "total": 0, "passed": 0, "failed": 0,
            "unknown": 0, "not_applicable": 0, "details": {},
        }

    @staticmethod
    def _record(bucket: Dict[str, Any], name: str, result: Dict[str, Any]) -> None:
        bucket["total"] += 1
        status = result["status"]
        if status == PASS:
            bucket["passed"] += 1
        elif status == FAIL:
            bucket["failed"] += 1
        elif status == NOT_APPLICABLE:
            bucket["not_applicable"] += 1
        else:
            bucket["unknown"] += 1
        bucket["details"][name] = result

    # ------------------------------------------------------------------
    # Organization-level checks (9)
    # ------------------------------------------------------------------

    @property
    def access(self):
        """Lazily built so that importing checks.py stays cycle-free."""
        if self._access is None:
            from access_review import AccessReview
            self._access = AccessReview(self.org, self.is_organization)
        return self._access

    def check_organization_settings(self) -> Dict[str, Any]:
        checks = self._new_bucket()
        self._record(checks, "2FA Enforcement", self._check_2fa_enforcement())
        self._record(checks, "SSO Configuration", self._check_sso_configuration())
        self._record(
            checks,
            "Default Repository Permission",
            self._check_default_repository_permission(),
        )
        self._record(
            checks,
            "Member Repository Creation",
            self._check_member_repository_creation(),
        )
        self._record(checks, "Audit Logging", self._check_audit_logs())
        self._record(checks, "Actions Allowed Actions Policy", self._check_actions_allowed())
        self._record(checks, "Actions Default Token Permissions",
                     self._check_org_workflow_permissions())
        self._record(checks, "Actions Pull Request Approval",
                     self._check_org_workflow_pr_approval())
        self._record(checks, "Organization Owner Count",
                     self.access.check_owner_count())
        return checks

    def _check_2fa_enforcement(self) -> Dict[str, Any]:
        guard = self._org_only("2FA enforcement for members")
        if guard:
            return guard
        try:
            enforced = getattr(self.org, "two_factor_requirement_enabled", None)
        except Exception as exc:
            return _from_exception(exc, "2FA enforcement")

        if enforced is None:
            return unknown(
                "2FA status is only visible to organization owners"
            )
        if enforced:
            return ok(
                "Organization policy requires 2FA for membership. This is the "
                "control that blocks a non-compliant account from being added; "
                "GitHub's own account-level requirement is a staged rollout with "
                "per-account deadlines and does not cover organization membership"
            )
        return fail(
                "Organization does not require 2FA for membership. GitHub's own "
                "account-level requirement is a staged rollout with per-account "
                "deadlines, so it does not guarantee every current or future member "
                "is covered — enable at org/settings/security"
            )

    def _check_sso_configuration(self) -> Dict[str, Any]:
        """SAML status is not exposed by the REST API; report honestly."""
        guard = self._org_only("SAML SSO")
        if guard:
            return guard
        try:
            plan = getattr(self.org, "plan", None)
            plan_name = plan.name if plan is not None and hasattr(plan, "name") else None
        except Exception:
            plan_name = None

        if plan_name == "free":
            return unknown(
                "SAML SSO requires GitHub Enterprise; this organization is on the free plan"
            )
        return unknown(
            "SAML SSO status is not exposed by the REST API — verify manually "
            "at org/settings/security"
        )

    def _check_default_repository_permission(self) -> Dict[str, Any]:
        """Least privilege: base permission granted to every member."""
        guard = self._org_only("Default repository permission")
        if guard:
            return guard
        try:
            permission = getattr(self.org, "default_repository_permission", None)
        except Exception as exc:
            return _from_exception(exc, "Default repository permission")

        if permission is None:
            return unknown(
                "Default repository permission is only visible to organization owners"
            )
        if permission in ("none", "read"):
            return ok(f"Default member permission is '{permission}' (least privilege)")
        return fail(
            f"Default member permission is '{permission}' — every member can "
            f"{'push to' if permission == 'write' else 'administer'} every repository"
        )

    def _check_member_repository_creation(self) -> Dict[str, Any]:
        guard = self._org_only("Member repository creation")
        if guard:
            return guard
        try:
            can_create = getattr(self.org, "members_can_create_repositories", None)
        except Exception as exc:
            return _from_exception(exc, "Member repository creation")

        if can_create is None:
            return unknown(
                "Repository creation policy is only visible to organization owners"
            )
        if can_create:
            return fail(
                "Any member can create repositories — restrict to owners to keep "
                "new repositories inside the audited perimeter"
            )
        return ok("Repository creation is restricted to organization owners")

    def _check_audit_logs(self) -> Dict[str, Any]:
        """Audit log API is Enterprise Cloud only and absent from PyGithub 2.5.0."""
        guard = self._org_only("Audit logging")
        if guard:
            return guard
        getter = getattr(self.org, "get_audit_logs", None)
        if getter is None:
            return unknown(
                "Audit log API requires GitHub Enterprise Cloud and is not exposed "
                "by the installed PyGithub version"
            )
        try:
            entries = getter()
            first = next(iter(entries), None)
        except Exception as exc:
            return _from_exception(exc, "Audit logging")

        if first is None:
            return fail("Audit log is reachable but contains no entries")
        return ok("Audit log is accessible and recording events")

    # ------------------------------------------------------------------
    # Repository-level checks (31)
    # ------------------------------------------------------------------

    def check_repository(self, repo) -> Dict[str, Any]:
        checks = self._new_bucket()

        facts = self._get_protection(repo)

        self._record(checks, "Repository Visibility", self._check_visibility(repo))
        self._record(
            checks, "Branch Protection Rules", self._check_branch_protection(facts, repo)
        )
        self._record(checks, "Pull Request Reviews", self._check_pr_reviews(facts))
        self._record(
            checks, "Status Checks Before Merge", self._check_status_checks(facts)
        )
        self._record(checks, "Commit Signing", self._check_commit_signing(facts))
        self._record(
            checks, "Dismiss Stale PR Reviews", self._check_dismiss_stale(facts)
        )
        self._record(
            checks, "Code Owner Reviews", self._check_code_owner_reviews(facts)
        )
        self._record(
            checks, "Admin Bypass Prevention", self._check_admin_enforcement(facts)
        )
        self._record(
            checks, "Linear History Required", self._check_linear_history(facts)
        )
        self._record(
            checks, "Force Push Protection", self._check_force_push(facts)
        )
        self._record(
            checks, "Branch Deletion Protection", self._check_deletion(facts)
        )
        self._record(checks, "Secrets Scanning", self._check_secrets_scanning(repo))
        self._record(checks, "Push Protection", self._check_push_protection(repo))
        self._record(checks, "Dependency Scanning", self._check_dependency_scanning(repo))
        self._record(checks, "SECURITY.md File", self._check_security_md(repo))
        self._record(checks, "CODEOWNERS File", self._check_codeowners_file(repo))
        self._record(checks, ".gitignore Configuration", self._check_gitignore(repo))
        self._record(checks, "Repository Activity", self._check_activity(repo))

        workflows = self._load_workflows(repo)
        self._record(checks, "Workflow Token Permissions",
                     self._check_repo_workflow_permissions(repo))
        self._record(checks, "Action Version Pinning", self._check_action_pinning(workflows))
        self._record(checks, "Workflow Permissions Declared",
                     self._check_workflow_permissions_declared(workflows))
        self._record(checks, "Untrusted Workflow Triggers",
                     self._check_untrusted_triggers(workflows))
        self._record(checks, "Self-Hosted Runner Exposure",
                     self._check_self_hosted_runners(repo, workflows))
        self._record(checks, "Build Provenance Attestation",
                     self._check_build_provenance(workflows))
        self._record(checks, "Repository Actions Policy",
                     self._check_repo_actions_policy(repo))
        self._record(checks, "Action SHA Pinning Policy",
                     self._check_sha_pinning_policy(repo))
        self._record(checks, "Fork Pull Request Workflows",
                     self._check_fork_pr_workflows(repo))
        self._record(checks, "Ruleset Enforcement Status",
                     self._check_ruleset_enforcement(repo))

        # Access review. The inventory is descriptive and unscored; the three
        # findings drawn from it are scored like any other check.
        inventory = self.access.repository_inventory(repo)
        checks["access_inventory"] = inventory
        self._record(checks, "Direct Collaborator Grants",
                     self.access.check_direct_grants(inventory))
        self._record(checks, "Outside Collaborator Access",
                     self.access.check_outside_collaborators(repo, inventory))
        self._record(checks, "Repository Admin Concentration",
                     self.access.check_admin_concentration(inventory))

        return checks

    # -- branch protection ------------------------------------------------

    def _get_protection(self, repo) -> "ProtectionFacts":
        """
        Resolve the effective protection of the default branch, once per repo.

        GitHub exposes two independent mechanisms. Classic branch protection
        lives at /branches/{b}/protection; rulesets live at
        /rules/branches/{b} and return 404 on the classic endpoint. A repo
        governed entirely by a ruleset used to read as "unprotected" here.
        Both sources are read and merged.
        """
        facts = ProtectionFacts()
        enforcement = self._enforcement(repo)

        try:
            branch = repo.get_branch(repo.default_branch)
        except Exception as exc:
            facts.state = UNKNOWN
            facts.reason = _from_exception(exc, "Branch protection")["message"]
            return facts

        classic_ok = False
        if getattr(branch, "protected", False):
            try:
                facts.apply_classic(branch.get_protection())
                classic_ok = True
            except Exception:
                pass  # ruleset-only repositories 404 here

        ruleset_ok = facts.apply_rules(self._fetch_rules(repo))

        if enforcement == "not_enforced":
            # The non-enforcement banner observed live, on both a personal
            # account and a free organization, names rulesets specifically:
            # "Your rulesets won't be enforced on this private repository...".
            # It says nothing about classic branch protection. Suppressing
            # classic protection under the same restriction has no evidence
            # behind it and would hide a genuinely enforced setting. Only the
            # ruleset-derived facts are affected; classic protection, if
            # present, is trusted on its own.
            if classic_ok:
                facts.state, facts.source = "protected", "classic branch protection"
            elif ruleset_ok:
                facts.state = "configured_not_enforced"
            else:
                facts.state = "not_enforceable"
            if facts.state == "protected":
                try:
                    facts.signatures_classic = branch.get_required_signatures()
                except Exception:
                    facts.signatures_classic = None
            return facts

        if enforcement == "unknown" and (classic_ok or ruleset_ok):
            facts.plan_caveat = True

        if classic_ok and ruleset_ok:
            facts.state, facts.source = "protected", "classic + ruleset"
        elif classic_ok:
            facts.state, facts.source = "protected", "classic branch protection"
        elif ruleset_ok:
            facts.state, facts.source = "protected", "repository ruleset"
        elif getattr(branch, "protected", False):
            facts.state = UNKNOWN
            facts.reason = "branch reports as protected but no rule detail is readable"
        elif facts.unrecognised_rules:
            facts.state = UNKNOWN
            facts.reason = (
                "branch is covered by rule types this version does not understand "
                f"({', '.join(sorted(facts.unrecognised_rules))})"
            )
        else:
            facts.state = "unprotected"

        try:
            facts.signatures_classic = branch.get_required_signatures()
        except Exception:
            facts.signatures_classic = None

        return facts

    @staticmethod
    def _fetch_rules(repo):
        """GET /repos/{owner}/{repo}/rules/branches/{branch} - active rulesets."""
        try:
            requester = repo._requester
            _, data = requester.requestJsonAndCheck(
                "GET", f"{repo.url}/rules/branches/{repo.default_branch}"
            )
            return data if isinstance(data, list) else None
        except Exception:
            return None

    def _dependent(self, facts, what: str):
        """
        Shared short-circuit for controls that require branch protection.

        When protection is absent this returns NOT_APPLICABLE rather than a
        failure: the missing protection is already reported once by
        "Branch Protection Rules", and repeating it nine more times would let a
        single setting dominate the score.
        """
        if facts.state == "not_enforceable":
            return not_applicable(
                f"{what}: not enforceable on a private repository under this plan",
                reason_category=REASON_PLAN_RESTRICTED,
            )
        if facts.state in ("unprotected", "configured_not_enforced"):
            return not_applicable(
                f"{what}: requires branch protection - see 'Branch Protection Rules'",
                reason_category=REASON_PREREQUISITE_FAILED,
            )
        if facts.state == UNKNOWN:
            return unknown(facts.reason or f"{what}: branch protection is not readable")
        return None

    def _check_branch_protection(self, facts, repo) -> Dict[str, Any]:
        if facts.state == "protected":
            detail = facts.source
            if facts.org_enforced:
                detail += ", enforced by an organization-level ruleset"
            message = f"Default branch '{repo.default_branch}' is protected ({detail})"
            if facts.plan_caveat:
                message += (
                    " - plan could not be determined; confirm enforcement, as private "
                    "repositories require a GitHub Team organization"
                )
            return ok(message)
        if facts.state == "unprotected":
            return fail(
                f"Default branch '{repo.default_branch}' has no branch protection "
                "or ruleset - every dependent control below is unenforceable"
            )
        if facts.state == "configured_not_enforced":
            return fail(
                "Branch protection is CONFIGURED BUT NOT ENFORCED. GitHub does not "
                "apply rulesets to a private repository on this plan, so the "
                "settings shown in the UI have no effect. Upgrade the account to "
                "GitHub Team, make the repository public, or stop relying on "
                "these rules"
            )
        if facts.state == "not_enforceable":
            return not_applicable(
                "Branch protection is not enforced on private repositories under "
                "this plan - a ruleset could be created but would not apply. "
                "Upgrade to GitHub Team or make the repository public to bring "
                "these controls into scope",
                reason_category=REASON_PLAN_RESTRICTED,
            )
        return unknown(facts.reason or "Branch protection is not readable with this token")

    def _check_pr_reviews(self, facts, _unused=None) -> Dict[str, Any]:
        guard = self._dependent(facts, "Pull request reviews")
        if guard:
            return guard
        count = facts.review_count
        if count is None or count < 1:
            return fail("Pull request reviews are not required before merge")
        return ok(f"Pull request reviews required ({count} approval(s))")

    def _check_status_checks(self, facts, _unused=None) -> Dict[str, Any]:
        guard = self._dependent(facts, "Status checks")
        if guard:
            return guard
        if not facts.status_contexts:
            return fail("No status checks are required before merge")
        return ok(f"{len(facts.status_contexts)} status check(s) required before merge")

    def _check_dismiss_stale(self, facts, _unused=None) -> Dict[str, Any]:
        guard = self._dependent(facts, "Stale review dismissal")
        if guard:
            return guard
        if facts.review_count is None:
            return fail("Pull request reviews are not configured")
        if facts.dismiss_stale:
            return ok("Stale approvals are dismissed when new commits are pushed")
        return fail("Stale approvals survive new commits")

    def _check_code_owner_reviews(self, facts, _unused=None) -> Dict[str, Any]:
        guard = self._dependent(facts, "Code owner reviews")
        if guard:
            return guard
        if facts.review_count is None:
            return fail("Pull request reviews are not configured")
        if facts.code_owner_review:
            return ok("Review from a designated code owner is required")
        return fail("Code owner review is not required")

    def _check_admin_enforcement(self, facts, _unused=None) -> Dict[str, Any]:
        guard = self._dependent(facts, "Admin bypass prevention")
        if guard:
            return guard
        if facts.enforce_admins is None:
            return unknown(
                "Bypass actors are configured per ruleset and are not readable here"
            )
        if facts.enforce_admins:
            return ok("Administrators are bound by branch protection rules")
        return fail("Administrators can bypass branch protection")

    def _check_linear_history(self, facts, _unused=None) -> Dict[str, Any]:
        guard = self._dependent(facts, "Linear history")
        if guard:
            return guard
        if facts.linear_history:
            return ok("Linear history is required (no merge commits)")
        return fail("Linear history is not required")

    def _check_force_push(self, facts, _unused=None) -> Dict[str, Any]:
        guard = self._dependent(facts, "Force push protection")
        if guard:
            return guard
        if facts.block_force_push is None:
            return unknown("Force push setting is not present in the API response")
        if facts.block_force_push:
            return ok("Force pushes are blocked on the default branch")
        return fail("Force pushes are allowed on the default branch")

    def _check_deletion(self, facts, _unused=None) -> Dict[str, Any]:
        guard = self._dependent(facts, "Branch deletion protection")
        if guard:
            return guard
        if facts.block_deletion is None:
            return unknown("Branch deletion setting is not present in the API response")
        if facts.block_deletion:
            return ok("The default branch cannot be deleted")
        return fail("The default branch can be deleted")

    def _check_commit_signing(self, facts, _unused=None) -> Dict[str, Any]:
        guard = self._dependent(facts, "Commit signing")
        if guard:
            return guard
        required = facts.required_signatures()
        if required is None:
            return unknown("Signed-commit requirement is not readable with this token")
        if required:
            return ok("Signed commits are required on the default branch")
        return fail("Signed commits are not required")

    # ------------------------------------------------------------------
    # GitHub Actions (supply chain)
    # ------------------------------------------------------------------
    #
    # Every large-scale GitHub compromise since 2024 has come through the
    # Actions supply chain rather than through branch settings: a popular
    # third-party action is backdoored, and every workflow that referenced it
    # by a mutable tag executes the new code with whatever token permissions
    # the workflow was granted. The controls below target that path.

    #: A pinned reference is a full 40-character commit SHA. Tags and branches
    #: are mutable and can be repointed by whoever controls the action repo.
    _SHA_RE = re.compile(r"^[0-9a-f]{40}$")
    _USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*[\'\"]?([^\'\"\s#]+)", re.MULTILINE)
    _TOP_LEVEL_PERMISSIONS_RE = re.compile(r"^permissions:", re.MULTILINE)
    _SELF_HOSTED_RE = re.compile(r"runs-on:.*self-hosted", re.IGNORECASE)
    _RISKY_TRIGGER_RE = re.compile(r"^\s*(pull_request_target|workflow_run)\s*:", re.MULTILINE)
    _PR_REF_CHECKOUT_RE = re.compile(
        r"ref:\s*\$\{\{\s*github\.event\.(pull_request\.head\.sha|"
        r"pull_request\.head\.ref|workflow_run\.head_sha)", re.IGNORECASE
    )
    _ATTESTATION_RE = re.compile(
        r"attest-build-provenance|attest-sbom|sigstore/|cosign", re.IGNORECASE
    )
    _PUBLISH_RE = re.compile(
        r"^\s*release\s*:|npm publish|docker/build-push-action|"
        r"pypa/gh-action-pypi-publish|gh release create", re.MULTILINE | re.IGNORECASE
    )
    #: Namespaces maintained by GitHub itself. Still worth pinning, but a
    #: materially different risk profile from an arbitrary third-party action.
    _FIRST_PARTY = ("actions/", "github/", "advanced-security/")

    def _api_get(self, obj, path: str, label: str = "Setting"):
        """
        GET an arbitrary API path using an object's requester, cached for the
        lifetime of this SecurityChecker instance.

        Several checks read the same settings endpoint independently - four
        repository-level checks all read `/actions/permissions` for that
        repository, and two organization-level checks both read
        `/actions/permissions/workflow`. The setting cannot change mid-audit,
        so repeating the request wastes an API call (and rate-limit budget)
        for data already in hand. Cached by the exact URL, which already
        includes the repository or organization identifier, so a hit here
        can never mix up results between two different repositories.
        """
        cache_key = path
        if cache_key in self._api_cache:
            return self._api_cache[cache_key]
        try:
            requester = obj._requester
        except AttributeError:
            result = None, "no requester available"
            self._api_cache[cache_key] = result
            return result
        try:
            _, data = requester.requestJsonAndCheck("GET", path)
            result = data, None
        except Exception as exc:
            result = None, _from_exception(exc, label)["message"]
        self._api_cache[cache_key] = result
        return result

    def _load_workflows(self, repo):
        """
        Return {path: text} for .github/workflows/*.yml.

        Parsed with regular expressions rather than a YAML loader on purpose:
        workflow files routinely contain templating that breaks strict parsers,
        and a YAML 1.1 loader silently turns the `on:` key into the boolean
        True, which is a well-known source of wrong answers in this exact task.
        """
        try:
            entries = repo.get_contents(".github/workflows")
        except Exception:
            return {}
        if not isinstance(entries, list):
            entries = [entries]

        workflows = {}
        for entry in entries:
            name = getattr(entry, "path", "") or ""
            if not name.endswith((".yml", ".yaml")):
                continue
            try:
                workflows[name] = entry.decoded_content.decode("utf-8", errors="replace")
            except Exception:
                continue
        return workflows

    # -- organization level -------------------------------------------------

    def _check_actions_allowed(self) -> Dict[str, Any]:
        guard = self._org_only("Organization Actions policy")
        if guard:
            return guard
        data, err = self._api_get(self.org, f"{self.org.url}/actions/permissions", "Actions policy")
        if data is None:
            return unknown(err or "Actions policy is not readable (organization owner required)")
        allowed = data.get("allowed_actions")
        if allowed is None:
            return unknown("Actions policy did not include an allowed_actions value")
        if allowed == "all":
            return fail(
                "Any action from the Marketplace can run — a single backdoored "
                "third-party action reaches every repository. Restrict to "
                "'selected' or 'local_only'"
            )
        if allowed == "local_only":
            return ok("Only actions from within this organization may run")
        return ok("Allowed actions are restricted to a reviewed list")

    def _check_org_workflow_permissions(self) -> Dict[str, Any]:
        guard = self._org_only("Organization workflow permissions")
        if guard:
            return guard
        data, err = self._api_get(self.org, f"{self.org.url}/actions/permissions/workflow", "Workflow permissions")
        if data is None:
            return unknown(err or "Workflow permissions are not readable (owner required)")
        default = data.get("default_workflow_permissions")
        if default is None:
            return unknown("Workflow permission default was not returned")
        if default == "read":
            return ok("GITHUB_TOKEN defaults to read-only across the organization")
        return fail(
            "GITHUB_TOKEN defaults to write across the organization — a compromised "
            "action inherits push access to the repository"
        )

    def _check_org_workflow_pr_approval(self) -> Dict[str, Any]:
        guard = self._org_only("Organization workflow approval policy")
        if guard:
            return guard
        data, err = self._api_get(self.org, f"{self.org.url}/actions/permissions/workflow", "Workflow permissions")
        if data is None:
            return unknown(err or "Workflow permissions are not readable (owner required)")
        can_approve = data.get("can_approve_pull_request_reviews")
        if can_approve is None:
            return unknown("Pull request approval setting was not returned")
        if can_approve:
            return fail(
                "Workflows may approve pull requests — this defeats required "
                "reviews, because a workflow can supply its own approval"
            )
        return ok("Workflows cannot approve pull requests")

    # -- repository level ---------------------------------------------------

    #: The Actions permissions payload gained settings after this engine was
    #: written (native SHA pinning, fork pull request workflows). The exact JSON
    #: key names are not confirmed, so candidates are probed and a missing key
    #: is reported as unknown rather than guessed into a pass or a failure.
    _SHA_PINNING_KEYS = (
        "sha_pinning_required", "require_sha_pinning",
        "actions_sha_pinning_required", "require_actions_pinned_to_sha",
    )
    _FORK_WORKFLOW_KEYS = (
        "fork_pr_workflows_policy", "run_workflows_from_fork_pull_requests",
        "fork_pull_request_workflows", "allow_fork_pr_workflows",
    )

    @staticmethod
    def _probe(payload, candidates):
        """Return (found, value) for the first candidate key present."""
        if not isinstance(payload, dict):
            return False, None
        for key in candidates:
            if key in payload:
                return True, payload[key]
        return False, None

    def _actions_permissions(self, repo):
        return self._api_get(repo, f"{repo.url}/actions/permissions", "Actions policy")

    def _check_repo_actions_policy(self, repo) -> Dict[str, Any]:
        """
        Repository-level allowed-actions policy.

        Personal accounts have no organization settings at all, so without this
        check a personal account received no Actions policy coverage whatsoever.
        """
        data, err = self._actions_permissions(repo)
        if data is None:
            return unknown(err or "Actions policy is not readable (admin access required)")
        if data.get("enabled") is False:
            return ok("GitHub Actions is disabled for this repository")
        allowed = data.get("allowed_actions")
        if allowed is None:
            return unknown("Actions policy did not include an allowed_actions value")
        if allowed == "all":
            return fail(
                "Any action from the Marketplace may run in this repository. "
                "Restrict to 'selected' or to actions owned by this account"
            )
        if allowed == "local_only":
            return ok("Only actions owned by this account may run")
        return ok("Allowed actions are restricted to a reviewed list")

    def _check_sha_pinning_policy(self, repo) -> Dict[str, Any]:
        """
        GitHub's native "Require actions to be pinned to a full-length commit
        SHA" setting. This is a preventive control: it blocks an unpinned
        reference from running at all, where scanning workflow files can only
        report one after it is already committed.
        """
        data, err = self._actions_permissions(repo)
        if data is None:
            return unknown(err or "Actions policy is not readable (admin access required)")
        found, value = self._probe(data, self._SHA_PINNING_KEYS)
        if not found:
            return unknown(
                "SHA pinning policy was not present in the API response — verify "
                "manually under Settings > Actions > General"
            )
        if value:
            return ok("Actions are required to be pinned to a full-length commit SHA")
        return fail(
            "Actions are not required to be pinned to a commit SHA. Enabling this "
            "enforces pinning at the platform level instead of relying on review"
        )

    _FORK_APPROVAL_KEYS = (
        "approval_policy", "fork_pr_contributor_approval",
        "fork_pull_request_approval_policy",
    )

    def _check_fork_pr_workflows(self, repo) -> Dict[str, Any]:
        """
        Fork pull request workflow policy.

        The control differs by visibility. A private repository chooses whether
        fork pull request workflows run at all; a public repository chooses
        which contributors need approval first. Treating public repositories as
        not applicable skipped the more consequential of the two.
        """
        if not getattr(repo, "private", False):
            return self._check_fork_pr_approval(repo)
        data, err = self._actions_permissions(repo)
        if data is None:
            return unknown(err or "Actions policy is not readable (admin access required)")
        found, value = self._probe(data, self._FORK_WORKFLOW_KEYS)
        if not found:
            return unknown(
                "Fork pull request workflow policy was not present in the API "
                "response — verify manually under Settings > Actions > General"
            )
        if value in (False, "disabled", "none"):
            return ok("Workflows do not run from fork pull requests")
        return fail(
            "Workflows run from fork pull requests — maintainers of a fork gain "
            "a token with read access to this private repository"
        )

    def _check_fork_pr_approval(self, repo) -> Dict[str, Any]:
        """Approval required before a fork pull request runs workflows."""
        data, err = self._actions_permissions(repo)
        if data is None:
            return unknown(err or "Actions policy is not readable (admin access required)")
        found, value = self._probe(data, self._FORK_APPROVAL_KEYS)
        if not found:
            return unknown(
                "Fork pull request approval policy was not present in the API "
                "response — verify manually under Settings > Actions > General"
            )
        policy = str(value).lower()
        if "all" in policy or "external" in policy:
            return ok("All external contributors require approval to run workflows")
        if "first_time" in policy or "first-time" in policy:
            if "new" in policy:
                return fail(
                    "Only contributors new to GitHub require approval. An account "
                    "with any prior GitHub history runs workflows on this public "
                    "repository unreviewed"
                )
            return ok("First-time contributors require approval to run workflows")
        return fail(
            f"Fork pull request workflows run without approval (policy: {policy})"
        )



    def _check_repo_workflow_permissions(self, repo) -> Dict[str, Any]:
        data, err = self._api_get(repo, f"{repo.url}/actions/permissions/workflow", "Workflow permissions")
        if data is None:
            return unknown(err or "Workflow permissions are not readable (admin required)")
        default = data.get("default_workflow_permissions")
        if default is None:
            return unknown("Workflow permission default was not returned")
        if default == "read":
            return ok("GITHUB_TOKEN defaults to read-only for this repository")
        return fail("GITHUB_TOKEN defaults to write — grant scopes per workflow instead")

    def _check_action_pinning(self, workflows) -> Dict[str, Any]:
        if not workflows:
            return not_applicable("Repository has no GitHub Actions workflows")

        unpinned_third_party, unpinned_first_party = set(), set()
        for text in workflows.values():
            for ref in self._USES_RE.findall(text):
                if ref.startswith("./") or ref.startswith("docker://"):
                    continue  # local action or image, no mutable tag to abuse
                _, _, version = ref.partition("@")
                if self._SHA_RE.match(version or ""):
                    continue
                if ref.startswith(self._FIRST_PARTY):
                    unpinned_first_party.add(ref)
                else:
                    unpinned_third_party.add(ref)

        if unpinned_third_party:
            sample = ", ".join(sorted(unpinned_third_party)[:3])
            return fail(
                f"{len(unpinned_third_party)} third-party action(s) referenced by a "
                f"mutable tag ({sample}). Pin to a full commit SHA — this is the exact "
                "path used in the tj-actions/changed-files compromise. See also "
                "'Action SHA Pinning Policy', which enforces this at the platform level"
            )
        if unpinned_first_party:
            return ok(
                f"All third-party actions are pinned to a commit SHA "
                f"({len(unpinned_first_party)} GitHub-owned action(s) still use tags)"
            )
        return ok("All external actions are pinned to a commit SHA")

    def _check_workflow_permissions_declared(self, workflows) -> Dict[str, Any]:
        if not workflows:
            return not_applicable("Repository has no GitHub Actions workflows")
        missing = [
            path for path, text in workflows.items()
            if not self._TOP_LEVEL_PERMISSIONS_RE.search(text)
        ]
        if missing:
            return fail(
                f"{len(missing)} workflow(s) declare no top-level 'permissions:' block "
                f"({', '.join(sorted(missing)[:3])}) — they inherit the repository "
                "default instead of stating least privilege explicitly"
            )
        return ok("Every workflow declares an explicit permissions block")

    def _check_untrusted_triggers(self, workflows) -> Dict[str, Any]:
        if not workflows:
            return not_applicable("Repository has no GitHub Actions workflows")
        dangerous = [
            path for path, text in workflows.items()
            if self._RISKY_TRIGGER_RE.search(text) and self._PR_REF_CHECKOUT_RE.search(text)
        ]
        if dangerous:
            return fail(
                f"{len(dangerous)} workflow(s) check out untrusted pull request code "
                f"under a privileged trigger ({', '.join(sorted(dangerous)[:3])}) — "
                "pull_request_target runs with repository secrets in scope"
            )
        risky_trigger_only = [
            path for path, text in workflows.items()
            if self._RISKY_TRIGGER_RE.search(text)
        ]
        if risky_trigger_only:
            return ok(
                f"{len(risky_trigger_only)} workflow(s) use a privileged trigger but do "
                "not check out pull request code"
            )
        return ok("No workflow uses a privileged trigger on untrusted input")

    def _check_self_hosted_runners(self, repo, workflows) -> Dict[str, Any]:
        if not workflows:
            return not_applicable("Repository has no GitHub Actions workflows")
        using = [p for p, t in workflows.items() if self._SELF_HOSTED_RE.search(t)]
        if not using:
            return ok("No workflow targets a self-hosted runner")
        if getattr(repo, "private", False):
            return ok(
                f"{len(using)} workflow(s) use self-hosted runners on a private "
                "repository (ensure runners are ephemeral)"
            )
        return fail(
            f"{len(using)} workflow(s) run on self-hosted runners in a PUBLIC "
            "repository — a fork pull request can execute arbitrary code on your "
            "infrastructure. Use ephemeral runners or GitHub-hosted runners"
        )

    def _check_build_provenance(self, workflows) -> Dict[str, Any]:
        if not workflows:
            return not_applicable("Repository has no GitHub Actions workflows")
        publishes = [p for p, t in workflows.items() if self._PUBLISH_RE.search(t)]
        if not publishes:
            return not_applicable("Repository does not publish releases or packages")
        attested = [p for p in publishes if self._ATTESTATION_RE.search(workflows[p])]
        if attested:
            return ok(f"{len(attested)} publishing workflow(s) generate build provenance")
        return fail(
            f"{len(publishes)} publishing workflow(s) emit no build provenance — "
            "consumers cannot verify the artifact came from this repository "
            "(actions/attest-build-provenance)"
        )

    #: Ruleset targets known not to govern branches. Excluded explicitly
    #: (a denylist) rather than requiring "target == branch" (an allowlist), so
    #: a ruleset with a missing or unrecognised target value stays in scope
    #: instead of being silently dropped from the finding.
    _NON_BRANCH_RULESET_TARGETS = frozenset({"tag", "push"})

    def _check_ruleset_enforcement(self, repo) -> Dict[str, Any]:
        """
        Rulesets whose enforcement status is not active.

        The new-ruleset form defaults Enforcement status to "Disabled". A
        ruleset saved without changing it appears in the Rulesets list, looks
        configured, and enforces nothing. This is the same false-confidence
        failure as an unenforced plan, reached by a different route.

        Only branch-scoped rulesets are evaluated. `/rulesets` lists every
        ruleset in the repository regardless of target, and a disabled *tag*
        or *push* ruleset says nothing about branch protection - counting it
        here would fail this check while "Branch Protection Rules" correctly
        passes from an unrelated, active branch ruleset, with no way for the
        reader to tell the two findings are about different things.
        """
        data, err = self._api_get(repo, f"{repo.url}/rulesets", "Rulesets")
        if data is None:
            return unknown(err or "Rulesets are not readable (admin access required)")
        if not isinstance(data, list):
            return unknown("Unexpected ruleset listing format")

        candidates = [
            r for r in data
            if isinstance(r, dict)
            and r.get("target") not in self._NON_BRANCH_RULESET_TARGETS
        ]
        if not candidates:
            return not_applicable("No branch rulesets are defined for this repository")

        inactive = []
        evaluating = []
        for ruleset in candidates:
            status = (ruleset.get("enforcement") or "").lower()
            name = ruleset.get("name") or f"id {ruleset.get('id')}"
            if status == "disabled":
                inactive.append(name)
            elif status == "evaluate":
                evaluating.append(name)

        if inactive:
            return fail(
                f"{len(inactive)} ruleset(s) exist with enforcement DISABLED "
                f"({', '.join(inactive[:3])}). They appear configured in the UI and "
                "enforce nothing - the new-ruleset form defaults to Disabled"
            )
        if evaluating:
            return fail(
                f"{len(evaluating)} ruleset(s) are in evaluate mode "
                f"({', '.join(evaluating[:3])}) - violations are reported but not blocked"
            )
        return ok(f"All {len(candidates)} ruleset(s) are actively enforced")

    # -- security features ------------------------------------------------

    @staticmethod
    def _security_and_analysis(repo) -> Optional[Dict[str, Any]]:
        try:
            raw = repo.raw_data
        except Exception:
            return None
        if not isinstance(raw, dict):
            return None
        block = raw.get("security_and_analysis")
        return block if isinstance(block, dict) else None

    def _feature_status(self, repo, key: str, label: str) -> Dict[str, Any]:
        block = self._security_and_analysis(repo)
        if block is None:
            return unknown(
                f"{label} status requires admin access to the repository"
            )
        feature = block.get(key)
        if not isinstance(feature, dict) or "status" not in feature:
            if getattr(repo, "private", False):
                return unknown(
                    f"{label} is not available for this repository "
                    "(on private repositories this requires GitHub Secret Protection)"
                )
            return unknown(f"{label} status was not returned by the API")
        if feature["status"] == "enabled":
            return ok(f"{label} is enabled")
        return fail(f"{label} is disabled — enable in repository settings")

    def _check_secrets_scanning(self, repo) -> Dict[str, Any]:
        return self._feature_status(repo, "secret_scanning", "Secret scanning")

    def _check_push_protection(self, repo) -> Dict[str, Any]:
        return self._feature_status(
            repo, "secret_scanning_push_protection", "Secret scanning push protection"
        )

    def _check_dependency_scanning(self, repo) -> Dict[str, Any]:
        try:
            enabled = repo.get_vulnerability_alert()
        except Exception as exc:
            return _from_exception(exc, "Dependency scanning")
        if enabled:
            return ok("Dependabot vulnerability alerts are enabled")
        return fail("Dependabot vulnerability alerts are disabled")

    # -- repository content -----------------------------------------------

    def _get_first_existing(self, repo, paths):
        for path in paths:
            try:
                return repo.get_contents(path), path
            except GithubException as exc:
                if getattr(exc, "status", None) in (403, 401):
                    raise
                continue
            except Exception:
                continue
        return None, None

    def _check_security_md(self, repo) -> Dict[str, Any]:
        try:
            found, path = self._get_first_existing(
                repo, ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"]
            )
        except Exception as exc:
            return _from_exception(exc, "SECURITY.md")
        if found is not None:
            return ok(f"SECURITY.md is present at {path}")
        return fail("SECURITY.md is missing — no documented vulnerability reporting path")

    def _check_codeowners_file(self, repo) -> Dict[str, Any]:
        try:
            found, path = self._get_first_existing(
                repo, ["CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"]
            )
        except Exception as exc:
            return _from_exception(exc, "CODEOWNERS")
        if found is not None:
            return ok(f"CODEOWNERS is configured at {path}")
        return fail("CODEOWNERS is missing — reviews are not routed to owners")

    SECRET_PATTERNS = (
        ".env", ".pem", ".key", "credentials", "password",
        "token", "secret", "private_key", "id_rsa", ".p12", ".pfx",
    )

    def _check_gitignore(self, repo) -> Dict[str, Any]:
        try:
            gitignore, _ = self._get_first_existing(repo, [".gitignore"])
        except Exception as exc:
            return _from_exception(exc, ".gitignore")
        if gitignore is None:
            return fail(".gitignore is missing")
        try:
            content = gitignore.decoded_content.decode("utf-8", errors="replace").lower()
        except Exception as exc:
            return _from_exception(exc, ".gitignore")

        matched = [p for p in self.SECRET_PATTERNS if p in content]
        if matched:
            return ok(f".gitignore excludes secret patterns ({', '.join(matched[:4])})")
        return fail(".gitignore exists but excludes no common secret patterns")

    # -- hygiene -----------------------------------------------------------

    def _check_visibility(self, repo) -> Dict[str, Any]:
        sensitive = ("credential", "secret", "private", "internal", "infra", "deploy")
        name = (getattr(repo, "name", "") or "").lower()
        is_private = bool(getattr(repo, "private", False))

        if is_private:
            return ok("Repository is private")
        flagged = [p for p in sensitive if p in name]
        if flagged:
            return fail(
                f"Repository is public but its name suggests sensitive content "
                f"({', '.join(flagged)})"
            )
        return ok("Repository is public (intentional public visibility assumed)")

    def _check_activity(self, repo) -> Dict[str, Any]:
        if getattr(repo, "archived", False):
            return ok("Repository is archived (read-only, intentionally retired)")

        pushed_at = getattr(repo, "pushed_at", None)
        if pushed_at is None:
            return unknown("Last push timestamp is not available")

        if pushed_at.tzinfo is None:
            pushed_at = pushed_at.replace(tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - pushed_at

        if age > timedelta(days=self.STALE_AFTER_DAYS):
            return fail(
                f"No push in {age.days} days — archive it or resume maintenance "
                "(unmaintained code keeps its access grants)"
            )
        return ok(f"Actively maintained (last push {age.days} days ago)")
