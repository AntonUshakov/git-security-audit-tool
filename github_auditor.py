#!/usr/bin/env python3
"""
GitHub Security Auditor
Comprehensive security audit tool for GitHub organizations
"""

import argparse
import json
import sys
from version import __version__, version_string
from datetime import datetime, timezone
from pathlib import Path

import logging

from github import Github, GithubRetry
from github.GithubException import GithubException

from checks import SecurityChecker
from config import Config
from report_generator import ReportGenerator

# PyGithub retries 403 responses that indicate a rate limit, backing off
# until the primary limit's reset time or a fixed wait for the secondary
# (abuse-detection) limit - this is already correct behaviour built into the
# library, not something this project should reimplement. Constructed
# explicitly (rather than relying on Github()'s own default retry object) so
# the policy is visible here and a future PyGithub upgrade changing that
# default cannot silently change audit behaviour.
GITHUB_RETRY_POLICY = GithubRetry(total=8, secondary_rate_wait=60)

#: PyGithub logs each retry/backoff decision under this logger name at INFO,
#: but nothing in this project configures logging, so those messages are
#: silently dropped by Python's default (no handler, WARNING level). A
#: multi-minute pause waiting for a rate-limit reset then looks identical to
#: a hang. `configure_rate_limit_logging()` attaches a console handler so the
#: wait is explained.
_RATE_LIMIT_LOGGER_NAME = "github.GithubRetry"


def configure_rate_limit_logging() -> None:
    """Make PyGithub's own rate-limit backoff messages visible on stderr.

    Idempotent - safe to call from both the CLI entry point and the web
    app's startup without installing duplicate handlers.
    """
    logger = logging.getLogger(_RATE_LIMIT_LOGGER_NAME)
    if any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
        return
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[RATE LIMIT] %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def resolve_github_target(gh, name: str, selection: str):
    """
    Resolve an audit target (organization or personal account) by name.

    Shared between `GitHubAuditor` and the repository-listing endpoint in
    `app.py`, so "is this an organization or a personal account" is answered
    identically everywhere rather than by two copies that could drift apart.

    Returns (target, warning_or_None). The warning is set when a personal
    account selection actually resolves to an organization - organization-
    level checks silently do not exist for that account type, so the
    mismatch is surfaced rather than absorbed.
    """
    if selection == "organization":
        try:
            return gh.get_organization(name), None
        except GithubException as exc:
            if getattr(exc, "status", None) == 404:
                raise GithubException(
                    404,
                    {"message": f"No organization named '{name}'. If this is a "
                                "personal account, select 'Personal account' "
                                "instead."},
                    None,
                )
            raise

    if selection == "user":
        target = gh.get_user(name)
        warning = None
        if getattr(target, "type", None) == "Organization":
            warning = (
                f"'{name}' is an organization, but the audit was started as a "
                "personal account. Eight organization-level checks will be "
                "skipped. Re-run with the organization option for full coverage."
            )
        return target, warning

    # auto
    try:
        return gh.get_organization(name), None
    except GithubException:
        return gh.get_user(name), None


class GitHubAuditor:
    """Main auditor class"""

    def __init__(self, config: Config):
        self.config = config
        self.target_warning = None
        configure_rate_limit_logging()
        try:
            self.gh = Github(config.github_token, retry=GITHUB_RETRY_POLICY)
            self.org = self._resolve_target(getattr(config, "account_type", "auto"))
        except GithubException as e:
            print(f"[FAILED] GitHub API Error: {e.data.get('message', str(e))}")
            sys.exit(1)

    def _resolve_target(self, selection: str):
        """
        Resolve the audit target according to the caller's selection, printing
        progress and recording a warning on `self` for the CLI/web reporting
        paths. See `resolve_github_target` for the shared resolution logic.
        """
        if selection == "auto":
            print("[INFO] Detecting account type...")

        target, warning = resolve_github_target(self.gh, self.config.org_name, selection)
        if warning:
            self.target_warning = warning
            print(f"[WARN] {warning}")
        return target

    def _check_repo_visibility(self, all_repos: list) -> dict:
        """
        Compare what this token could enumerate against the account's own
        reported repository count, so the report can distinguish "we audited
        everything that exists" from "we audited everything this token can
        see" - which are not the same claim. A fine-grained token scoped to
        3 of 40 repositories still successfully enumerates those 3 with no
        error, and a report saying "Full account audited" in that case is
        confidently wrong in exactly the way this project has repeatedly
        found and fixed elsewhere (personal-account/org mismatch, unenforced
        rulesets read as protected).

        `public_repos` / `total_private_repos` are themselves permission-
        gated: GitHub only returns them when the requester has visibility
        into the account's own repository counts, which is not guaranteed
        even for an organization the token is a plain member of. When
        unavailable, this reports "unconfirmed" rather than guessing either
        way.
        """
        visible_count = len(all_repos)
        try:
            public = self.org.public_repos
            private = self.org.total_private_repos
        except Exception:
            public = private = None

        if public is None or private is None:
            return {
                "confidence": "unconfirmed",
                "visible_count": visible_count,
                "expected_total": None,
                "gap": None,
            }

        expected_total = public + private
        gap = expected_total - visible_count
        if gap > 0:
            print(f"[WARN] Token visibility gap: this token can see {visible_count} "
                  f"of {expected_total} repositories in this account. The audit "
                  "covers only what was visible - see repository_visibility in "
                  "the results.")
            return {
                "confidence": "gap",
                "visible_count": visible_count,
                "expected_total": expected_total,
                "gap": gap,
            }

        return {
            "confidence": "confirmed",
            "visible_count": visible_count,
            "expected_total": expected_total,
            "gap": 0,
        }

    def audit_organization(self, verbose=False, repo_names=None) -> dict:
        """
        Run the audit.

        `repo_names`, when given, restricts the repository-level checks to
        that list. Organization-level checks always run against the whole
        account, since they are not a property of any single repository.
        Unmatched names are reported rather than silently dropped -- a typo
        should not read as "zero findings".
        """
        self.scope_warning = None
        print(f"{version_string()}")
        print(f"\n[START] Starting GitHub security audit for: "
              f"{getattr(self.org, 'name', None) or getattr(self.org, 'login', self.config.org_name)}")
        print(f"[TIME] Timestamp (UTC): {datetime.now(timezone.utc).isoformat()}")
        print("-" * 70)

        checker = SecurityChecker(self.org, verbose=verbose)
        account_type = checker.account_type
        if account_type == "User":
            print("[INFO] Personal account: 8 organization-level checks do not "
                  "apply. See APPLICABILITY.md.")
        org_label = getattr(self.org, "name", None) or getattr(
            self.org, "login", None
        ) or self.config.org_name
        
        # Run all checks
        audit_results = {
            "organization": org_label,
            "tool_version": __version__,
            "account_type": account_type,
            "target_warning": self.target_warning,
            "scope_warning": self.scope_warning,
            "repository_scope": sorted(repo_names) if repo_names else None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "checks": {}
        }

        # Organization-level checks
        print("\n[INFO] Running organization-level checks...")
        org_checks = checker.check_organization_settings()
        audit_results["checks"]["organization"] = org_checks
        self._print_results("Organization Settings", org_checks)

        # Repository-level checks
        all_repos = list(self.org.get_repos())
        audit_results["repository_visibility"] = self._check_repo_visibility(all_repos)

        if repo_names:
            wanted = set(repo_names)
            by_name = {r.name: r for r in all_repos}
            repos = [by_name[n] for n in repo_names if n in by_name]
            missing = sorted(wanted - set(by_name))
            if missing:
                self.scope_warning = (
                    f"{len(missing)} requested repository name(s) were not found "
                    f"and were skipped: {', '.join(missing)}"
                )
                print(f"[WARN] {self.scope_warning}")
            print(f"\n[SCANNING] Scanning {len(repos)} of {len(all_repos)} "
                  "repositories (scope restricted)...")
        else:
            repos = all_repos
            print("\n[SCANNING] Scanning repositories...")
        print(f"   Found {len(repos)} repositories")
        
        repo_results = {}
        for idx, repo in enumerate(repos, 1):
            print(f"   [{idx}/{len(repos)}] Checking {repo.name}...", end=" ")
            repo_checks = checker.check_repository(repo)
            repo_results[repo.name] = repo_checks
            status = "[PASSED]" if repo_checks["passed"] else "[WARNING]"
            print(f"{status} ({repo_checks['passed']}/{repo_checks['total']})")
        
        audit_results["checks"]["repositories"] = repo_results

        # scope_warning is only known once repository names have been resolved
        # against the account's actual repositories, which happens after
        # audit_results was first assembled.
        audit_results["scope_warning"] = self.scope_warning

        # Calculate summary
        audit_results["summary"] = self._calculate_summary(audit_results["checks"])
        
        return audit_results

    def _calculate_summary(self, checks: dict) -> dict:
        """
        Calculate overall audit summary.

        Checks that could not be evaluated ("unknown") or do not apply
        ("not_applicable") are excluded from the score entirely. A permission
        the token does not hold, or a control that cannot exist for this
        account or plan, is not a security finding.

        Two scores are computed:

        - `compliance_score`: passed / evaluated, every check weighted equally.
          Kept for continuity with earlier reports and for a simple "percent of
          checks passing" reading.
        - `weighted_score`: the same ratio, but each check contributes
          proportional to its severity (see compliance_mapping.SEVERITY_WEIGHT).
          A single critical failure - 2FA off, no branch protection, secret
          scanning disabled - now visibly moves the number, rather than being
          one vote among forty equally-weighted checks. `risk_level` is derived
          from this score, not the flat one, because a report that classifies
          "CODEOWNERS is missing" and "2FA is off" as contributing equally to
          risk is not telling the reader what actually matters.
        """
        from compliance_mapping import severity_for, SEVERITY_WEIGHT

        passed = failed = unknown = not_applicable = 0
        weighted_passed = weighted_evaluated = 0
        severity_failures = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        def accumulate(bucket: dict) -> None:
            nonlocal passed, failed, unknown, not_applicable
            nonlocal weighted_passed, weighted_evaluated
            passed += bucket.get("passed", 0)
            failed += bucket.get("failed", 0)
            unknown += bucket.get("unknown", 0)
            not_applicable += bucket.get("not_applicable", 0)

            for check_name, result in bucket.get("details", {}).items():
                status = result.get(
                    "status", "pass" if result.get("passed") else "fail"
                )
                if status not in ("pass", "fail"):
                    continue
                weight = SEVERITY_WEIGHT[severity_for(check_name)]
                weighted_evaluated += weight
                if status == "pass":
                    weighted_passed += weight
                else:
                    severity_failures[severity_for(check_name)] += 1

        for check_type, check_data in checks.items():
            if check_type == "organization":
                accumulate(check_data)
            elif check_type == "repositories":
                for repo_checks in check_data.values():
                    accumulate(repo_checks)

        evaluated = passed + failed
        total = evaluated + unknown + not_applicable
        score = round((passed / evaluated * 100), 2) if evaluated > 0 else 0.0
        weighted_score = (
            round((weighted_passed / weighted_evaluated * 100), 2)
            if weighted_evaluated > 0 else score
        )
        coverage = round((evaluated / total * 100), 2) if total > 0 else 0.0
        # The conservative denominator: what fraction of the FULL control set
        # (not just what could be evaluated) is confirmed passing. A flat
        # "compliance_score" of 58% reads as a near-passing grade; if only a
        # quarter of the checks could actually be evaluated, the honest
        # statement is closer to "27% of controls are confirmed passing" -
        # this field makes that statement directly available rather than
        # requiring the reader to multiply compliance_score by coverage.
        pass_rate_of_total = round((passed / total * 100), 2) if total > 0 else 0.0

        return {
            "total_checks": evaluated + unknown + not_applicable,
            "evaluated_checks": evaluated,
            "passed_checks": passed,
            "failed_checks": failed,
            "unknown_checks": unknown,
            "not_applicable_checks": not_applicable,
            "compliance_score": score,
            "weighted_score": weighted_score,
            "pass_rate_of_total_scope": pass_rate_of_total,
            "severity_breakdown": severity_failures,
            "coverage_percent": coverage,
            # A score derived from a minority of the checks is a weaker claim
            # than the same number derived from all of them. Say so in the data
            # rather than leaving the reader to divide.
            "low_coverage": coverage < 60.0,
            "risk_level": self._get_risk_level(weighted_score) if evaluated else "UNSCORED",
        }

    @staticmethod
    def _get_risk_level(score: float) -> str:
        """Determine risk level from compliance score"""
        if score >= 90:
            return "LOW RISK"
        elif score >= 70:
            return "MEDIUM RISK"
        elif score >= 50:
            return "HIGH RISK"
        else:
            return "CRITICAL RISK"

    @staticmethod
    def _print_results(title: str, results: dict) -> None:
        """Print check results in readable format"""
        passed = results.get("passed", 0)
        total = results.get("total", 0)
        status = "[PASSED]" if passed == total else "[WARNING]"
        
        print(f"\n{status} {title}: {passed}/{total}")
        
        for check_name, check_result in results.get("details", {}).items():
            status = check_result.get("status", "pass" if check_result.get("passed") else "fail")
            icon = {"pass": "[OK]", "fail": "[FAIL]"}.get(status, "[SKIP]")
            print(f"   {icon} {check_name}")
            if check_result.get("message"):
                print(f"      └─ {check_result['message']}")

    def generate_report(self, audit_results: dict, output_format: str = "html") -> str:
        """Generate audit report"""
        generator = ReportGenerator(self.config)
        
        if output_format == "json":
            return generator.generate_json_report(audit_results)
        elif output_format == "html":
            return generator.generate_html_report(audit_results)
        else:
            raise ValueError(f"Unknown output format: {output_format}")

    def save_results(self, audit_results: dict, output_dir: str = ".") -> None:
        """Save audit results to files"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # UTC so two auditors in different timezones agree on session ordering,
        # and so a filename never implies a local time it did not use.
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        
        # Save JSON
        json_file = output_path / f"github_audit_{timestamp}.json"
        with open(json_file, "w") as f:
            json.dump(audit_results, f, indent=2)
        print(f"\n📄 JSON Report: {json_file}")
        
        # Save HTML
        html_content = self.generate_report(audit_results, "html")
        html_file = output_path / f"github_audit_{timestamp}.html"
        with open(html_file, "w") as f:
            f.write(html_content)
        print(f"[SAVED] HTML Report: {html_file}")
        
        return str(html_file)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description=f"{version_string()} - Comprehensive security audit tool"
    )
    parser.add_argument(
        "--version", action="version", version=version_string()
    )
    parser.add_argument(
        "--repos",
        default=None,
        help="Comma-separated repository names to audit, instead of every "
             "repository in the account (e.g. --repos api,web,infra)"
    )
    parser.add_argument(
        "--standard",
        default="all",
        help="Produce a report for one framework only: soc2, nist, iso27001, cis, or all"
    )
    parser.add_argument(
        "--account-type",
        choices=("auto", "organization", "user"),
        default="auto",
        help="What is being audited. Eight checks exist only on organizations."
    )
    parser.add_argument(
        "--token-stdin",
        action="store_true",
        help="Read the GitHub token from stdin instead of the GITHUB_TOKEN env var"
    )
    parser.add_argument(
        "-o", "--org",
        required=True,
        help="GitHub organization name to audit"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["html", "json", "both"],
        default="html",
        help="Output format (default: html)"
    )
    parser.add_argument(
        "-d", "--output-dir",
        default=".",
        help="Output directory for reports (default: current directory)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--web",
        action="store_true",
        help="Start web dashboard instead of CLI"
    )

    args = parser.parse_args()

    # If web mode, import and run Flask app
    if args.web:
        from app import create_app
        app = create_app(args.org)
        print(f"[START] Starting web dashboard on http://localhost:5000")
        print(f"[CONFIG] Organization: {args.org}")
        app.run(host='127.0.0.1', port=5000, debug=False)
        return

    # CLI mode
    token = None
    if args.token_stdin:
        token = sys.stdin.readline().strip()
    config = Config(github_token=token, org_name=args.org,
                    account_type=args.account_type)
    auditor = GitHubAuditor(config)
    
    try:
        repo_names = (
            [r.strip() for r in args.repos.split(",") if r.strip()]
            if args.repos else None
        )
        results = auditor.audit_organization(verbose=args.verbose, repo_names=repo_names)
        
        print("\n" + "=" * 70)
        print("AUDIT SUMMARY")
        print("=" * 70)
        summary = results["summary"]
        print(f"Compliance Score: {summary['compliance_score']}%")
        print(f"Risk Level: {summary['risk_level']}")
        print(f"Passed: {summary['passed_checks']}/{summary['evaluated_checks']} evaluated")
        print(f"Not evaluated: {summary['unknown_checks']} unknown, "
              f"{summary['not_applicable_checks']} not applicable")
        print(f"Coverage: {summary['coverage_percent']}% of checks were scored")
        if summary["low_coverage"]:
            print("  NOTE: fewer than 60% of checks could be scored. The score "
                  "describes a minority of the control set.")
        print("=" * 70)
        
        auditor.save_results(results, args.output_dir)
        
    except KeyboardInterrupt:
        print("\n[INTERRUPT] Audit interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Audit failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
