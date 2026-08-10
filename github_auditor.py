#!/usr/bin/env python3
"""
GitHub Security Auditor
Comprehensive security audit tool for GitHub organizations
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from github import Github
from github.GithubException import GithubException

from checks import SecurityChecker
from config import Config
from report_generator import ReportGenerator


class GitHubAuditor:
    """Main auditor class"""

    def __init__(self, config: Config):
        self.config = config
        self.target_warning = None
        try:
            self.gh = Github(config.github_token)
            self.org = self._resolve_target(getattr(config, "account_type", "auto"))
        except GithubException as e:
            print(f"[FAILED] GitHub API Error: {e.data.get('message', str(e))}")
            sys.exit(1)

    def _resolve_target(self, selection: str):
        """
        Resolve the audit target according to the caller's selection.

        The selection matters beyond lookup: eight checks exist only on
        organizations. Auditing an organization as a personal account silently
        drops them, so a mismatch is surfaced rather than absorbed.
        """
        name = self.config.org_name

        if selection == "organization":
            try:
                return self.gh.get_organization(name)
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
            target = self.gh.get_user(name)
            if getattr(target, "type", None) == "Organization":
                self.target_warning = (
                    f"'{name}' is an organization, but the audit was started as a "
                    "personal account. Eight organization-level checks will be "
                    "skipped. Re-run with the organization option for full coverage."
                )
                print(f"[WARN] {self.target_warning}")
            return target

        # auto
        try:
            return self.gh.get_organization(name)
        except GithubException:
            print("[INFO] No organization by that name, trying personal account...")
            return self.gh.get_user(name)

    def audit_organization(self, verbose=False) -> dict:
        """Run full organization audit"""
        print(f"\n[START] Starting GitHub security audit for: "
              f"{getattr(self.org, 'name', None) or getattr(self.org, 'login', self.config.org_name)}")
        print(f"[TIME] Timestamp: {datetime.now().isoformat()}")
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
            "account_type": account_type,
            "target_warning": self.target_warning,
            "timestamp": datetime.now().isoformat(),
            "checks": {}
        }

        # Organization-level checks
        print("\n[INFO] Running organization-level checks...")
        org_checks = checker.check_organization_settings()
        audit_results["checks"]["organization"] = org_checks
        self._print_results("Organization Settings", org_checks)

        # Repository-level checks
        print("\n[SCANNING] Scanning repositories...")
        repos = list(self.org.get_repos())
        print(f"   Found {len(repos)} repositories")
        
        repo_results = {}
        for idx, repo in enumerate(repos, 1):
            print(f"   [{idx}/{len(repos)}] Checking {repo.name}...", end=" ")
            repo_checks = checker.check_repository(repo)
            repo_results[repo.name] = repo_checks
            status = "[PASSED]" if repo_checks["passed"] else "[WARNING]"
            print(f"{status} ({repo_checks['passed']}/{repo_checks['total']})")
        
        audit_results["checks"]["repositories"] = repo_results

        # Calculate summary
        audit_results["summary"] = self._calculate_summary(audit_results["checks"])
        
        return audit_results

    def _calculate_summary(self, checks: dict) -> dict:
        """
        Calculate overall audit summary.

        Checks that could not be evaluated ("unknown") are excluded from the
        score entirely. A permission the token does not hold is not a security
        finding, and counting it as one makes the score unreadable.
        """
        passed = failed = unknown = not_applicable = 0

        def accumulate(bucket: dict) -> None:
            nonlocal passed, failed, unknown, not_applicable
            passed += bucket.get("passed", 0)
            failed += bucket.get("failed", 0)
            unknown += bucket.get("unknown", 0)
            not_applicable += bucket.get("not_applicable", 0)

        for check_type, check_data in checks.items():
            if check_type == "organization":
                accumulate(check_data)
            elif check_type == "repositories":
                for repo_checks in check_data.values():
                    accumulate(repo_checks)

        evaluated = passed + failed
        total = evaluated + unknown + not_applicable
        score = round((passed / evaluated * 100), 2) if evaluated > 0 else 0.0
        coverage = round((evaluated / total * 100), 2) if total > 0 else 0.0

        return {
            "total_checks": evaluated + unknown + not_applicable,
            "evaluated_checks": evaluated,
            "passed_checks": passed,
            "failed_checks": failed,
            "unknown_checks": unknown,
            "not_applicable_checks": not_applicable,
            "compliance_score": score,
            "coverage_percent": coverage,
            # A score derived from a minority of the checks is a weaker claim
            # than the same number derived from all of them. Say so in the data
            # rather than leaving the reader to divide.
            "low_coverage": coverage < 60.0,
            "risk_level": self._get_risk_level(score) if evaluated else "UNSCORED",
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
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
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
        description="GitHub Security Auditor - Comprehensive security audit tool"
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
        results = auditor.audit_organization(verbose=args.verbose)
        
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
