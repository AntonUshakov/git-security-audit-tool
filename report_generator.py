"""
Report Generator
Generates HTML and JSON reports from audit results
"""

import json
from html import escape as _esc
from typing import Dict, Any
from datetime import datetime
from compliance_mapping import (
    STANDARDS,
    guidance_for,
    resolve_standard,
    controls_for_check,
    scope_results_to_standard,
    calculate_compliance_scores,
    get_compliance_gaps,
    get_risk_level_for_standard,
    COMPLIANCE_MAPPING
)


class ReportGenerator:
    """Generate audit reports in various formats"""

    def __init__(self, config, standard=None):
        """
        `standard` selects a single framework. When set, the report contains
        that framework and no other: a SOC 2 report that also scores NIST is
        not a SOC 2 report, and an auditor reading it has to work out which
        number applies to them.
        """
        self.config = config
        self.standard = resolve_standard(standard) if isinstance(standard, str) else standard


    #: Framework descriptions, rendered only for the standard in scope.
    _FRAMEWORK_DESCRIPTIONS = {'soc2': ('SOC 2 Trust Services Criteria', 'Service Organization Control Framework addressing the Trust Services Categories (Security, Availability, Processing Integrity, Confidentiality, Privacy)'), 'nist': ('NIST SP 800-53 Rev. 5', 'US federal cybersecurity control catalogue, with families covering access control, authentication, audit, change management and integrity'), 'iso27001': ('ISO/IEC 27001:2022', 'International information security management system. The 2022 revision organises Annex A into 93 controls across clauses 5 to 8'), 'cis_csc': ('CIS Controls v8.1', 'Prioritised, actionable safeguards derived from observed attack patterns')}

    def _frameworks_in_scope(self):
        if self.standard:
            key = self.standard["key"]
            return [(key, *self._FRAMEWORK_DESCRIPTIONS[key])]
        return [(k, *v) for k, v in self._FRAMEWORK_DESCRIPTIONS.items()]

    def _framework_line(self) -> str:
        if self.standard:
            return f"Assessed against {_esc(self.standard['reference'])}"
        names = ", ".join(n for _, n, _ in self._frameworks_in_scope())
        return f"Mapped to {_esc(names)}"

    def _mapping_lead_in(self) -> str:
        if self.standard:
            return (f"Each security check mapped to {_esc(self.standard['name'])} "
                    f"{_esc(self.standard['control_label'].lower())}s:")
        return ("Each security check mapped to requirements from SOC 2, NIST, "
                "ISO/IEC 27001 and CIS Controls:")

    def _framework_list_items(self) -> str:
        return "".join(
            f"<li><strong>{_esc(name)}</strong> &mdash; {_esc(desc)}</li>"
            for _, name, desc in self._frameworks_in_scope()
        )

    def _framework_blocks(self) -> str:
        return "".join(
            f'<div style="margin-bottom: 12px;"><strong>{_esc(name)}</strong> &mdash; {_esc(desc)}</div>'
            for _, name, desc in self._frameworks_in_scope()
        )

    def _total_controls(self) -> int:
        """Count from the mapping, never a literal in prose."""
        from compliance_mapping import checks_for_standard
        return len(checks_for_standard(self.standard))

    def _shows(self, field: str) -> bool:
        """True when a framework belongs in this report."""
        return self.standard is None or self.standard["key"] == field

    @property
    def standard_name(self) -> str:
        return self.standard["name"] if self.standard else "All standards"

    def generate_json_report(self, audit_results: Dict[str, Any]) -> str:
        """Generate JSON report, scoped to the selected standard if any."""
        return json.dumps(self._scoped(audit_results), indent=2)

    def _scoped(self, audit_results: Dict[str, Any]) -> Dict[str, Any]:
        return scope_results_to_standard(audit_results, self.standard)

    def generate_html_report(self, audit_results: Dict[str, Any]) -> str:
        audit_results = self._scoped(audit_results)
        """Generate comprehensive HTML report"""
        summary = audit_results["summary"]
        timestamp = audit_results["timestamp"]
        org_name = audit_results["organization"]

        # Determine color based on score
        score = summary["compliance_score"]
        if score >= 90:
            score_color = "#10b981"  # green
            score_class = "score-excellent"
        elif score >= 70:
            score_color = "#f59e0b"  # amber
            score_class = "score-good"
        elif score >= 50:
            score_color = "#ef9546"  # orange
            score_class = "score-warning"
        else:
            score_color = "#ef4444"  # red
            score_class = "score-critical"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitHub Security Audit Report - {_esc(str(org_name))}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        :root {{
            --primary: #1f2937;
            --secondary: #374151;
            --accent: #0f766e;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --light: #f9fafb;
            --border: #e5e7eb;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: var(--primary);
            background: linear-gradient(135deg, var(--primary) 0%, #111827 100%);
            min-height: 100vh;
            padding: 20px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }}

        .header {{
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            color: white;
            padding: 40px 30px;
            border-bottom: 4px solid var(--accent);
        }}

        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}

        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}

        .meta {{
            font-size: 0.9em;
            margin-top: 15px;
            opacity: 0.8;
            border-top: 1px solid rgba(255, 255, 255, 0.2);
            padding-top: 15px;
        }}

        .content {{
            padding: 40px 30px;
        }}

        .score-card {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-bottom: 40px;
        }}

        .score-box {{
            background: white;
            border: 2px solid var(--border);
            border-radius: 12px;
            padding: 30px;
            text-align: center;
        }}

        .score-circle {{
            width: 150px;
            height: 150px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            font-size: 3em;
            font-weight: 700;
            color: white;
        }}

        .score-excellent {{
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        }}

        .score-good {{
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
        }}

        .score-warning {{
            background: linear-gradient(135deg, #ef9546 0%, #f97316 100%);
        }}

        .score-critical {{
            background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
        }}

        .score-label {{
            font-size: 1.3em;
            font-weight: 600;
            margin-bottom: 5px;
            color: var(--primary);
        }}

        .score-value {{
            font-size: 0.95em;
            color: var(--secondary);
        }}

        .findings {{
            margin-top: 40px;
        }}

        .findings h2 {{
            font-size: 1.8em;
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 3px solid var(--accent);
            color: var(--primary);
        }}

        .org-section {{
            margin-bottom: 40px;
        }}

        .section-title {{
            font-size: 1.4em;
            font-weight: 600;
            color: var(--primary);
            margin-bottom: 20px;
            padding: 15px;
            background: var(--light);
            border-left: 4px solid var(--accent);
            border-radius: 4px;
        }}

        .check-item {{
            display: flex;
            gap: 15px;
            padding: 15px;
            margin-bottom: 12px;
            border-left: 4px solid var(--border);
            border-radius: 6px;
            background: white;
            transition: all 0.3s ease;
        }}

        .check-item:hover {{
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            border-left-color: var(--accent);
        }}

        .check-item.passed {{
            border-left-color: var(--success);
            background: rgba(16, 185, 129, 0.05);
        }}

        .check-item.failed {{
            border-left-color: var(--danger);
            background: rgba(239, 68, 68, 0.05);
        }}

        .check-icon {{
            flex-shrink: 0;
            font-size: 1.5em;
            width: 30px;
            text-align: center;
        }}

        .check-content {{
            flex: 1;
        }}

        .check-name {{
            font-weight: 600;
            color: var(--primary);
            margin-bottom: 5px;
        }}

        .check-message {{
            font-size: 0.95em;
            color: var(--secondary);
        }}

        .repo-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}

        .repo-card {{
            background: white;
            border: 2px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            transition: all 0.3s ease;
        }}

        .repo-card:hover {{
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1);
            border-color: var(--accent);
        }}

        .repo-name {{
            font-size: 1.2em;
            font-weight: 600;
            color: var(--primary);
            margin-bottom: 10px;
        }}

        .repo-stats {{
            display: flex;
            gap: 15px;
            margin-bottom: 15px;
            font-size: 0.95em;
        }}

        .repo-stat {{
            flex: 1;
        }}

        .repo-stat-value {{
            font-size: 1.4em;
            font-weight: 700;
            color: var(--accent);
        }}

        .repo-stat-label {{
            color: var(--secondary);
            font-size: 0.85em;
        }}

        .progress-bar {{
            width: 100%;
            height: 6px;
            background: var(--border);
            border-radius: 3px;
            overflow: hidden;
        }}

        .progress-fill {{
            height: 100%;
            border-radius: 3px;
            background: linear-gradient(90deg, var(--accent) 0%, #14b8a6 100%);
            transition: width 0.3s ease;
        }}

        .footer {{
            background: var(--light);
            padding: 20px 30px;
            border-top: 1px solid var(--border);
            text-align: center;
            color: var(--secondary);
            font-size: 0.9em;
        }}

        .summary-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .stat-card {{
            background: linear-gradient(135deg, var(--light) 0%, white 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }}

        .stat-number {{
            font-size: 2.2em;
            font-weight: 700;
            color: var(--accent);
            margin-bottom: 5px;
        }}

        .stat-label {{
            color: var(--secondary);
            font-size: 0.95em;
        }}

        @media (max-width: 768px) {{
            .score-card {{
                grid-template-columns: 1fr;
            }}

            .header h1 {{
                font-size: 1.8em;
            }}

            .repo-grid {{
                grid-template-columns: 1fr;
            }}

            .content {{
                padding: 20px 15px;
            }}
        }}

        .risk-badge {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.95em;
        }}

        .risk-low {{
            background: rgba(16, 185, 129, 0.1);
            color: #059669;
        }}

        .risk-medium {{
            background: rgba(245, 158, 11, 0.1);
            color: #b45309;
        }}

        .risk-high {{
            background: rgba(239, 149, 70, 0.1);
            color: #d97706;
        }}

        .risk-critical {{
            background: rgba(239, 68, 68, 0.1);
            color: #dc2626;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 GitHub Security Audit Report</h1>
            <p>Organization: <strong>{_esc(str(org_name))}</strong></p>
            <div class="meta">
                Generated: {datetime.fromisoformat(timestamp).strftime('%Y-%m-%d %H:%M:%S %Z')}
            </div>
        </div>

        <div class="content">
            <!-- Score Card -->
            <div class="score-card">
                <div class="score-box">
                    <div class="score-circle {score_class}">
                        {score:.0f}%
                    </div>
                    <div class="score-label">Compliance Score</div>
                    <div class="score-value">Based on security best practices</div>
                </div>

                <div class="score-box">
                    <div style="margin-bottom: 20px;">
                        <div class="risk-badge risk-{self._get_risk_css_class(score)}">
                            {summary['risk_level']}
                        </div>
                    </div>
                    <div class="score-label">Risk Assessment</div>
                    <div class="score-value">
                        <div style="margin-top: 20px; text-align: left;">
                            <div>✓ Passed: <strong style="color: var(--success);">{summary['passed_checks']}</strong></div>
                            <div>✗ Failed: <strong style="color: var(--danger);">{summary['failed_checks']}</strong></div>
                            <div>→ Total: <strong style="color: var(--accent);">{summary['total_checks']}</strong></div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Summary Stats -->
            <div class="summary-stats">
                <div class="stat-card">
                    <div class="stat-number">{summary['passed_checks']}</div>
                    <div class="stat-label">Checks Passed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{summary['failed_checks']}</div>
                    <div class="stat-label">Checks Failed</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(audit_results['checks'].get('repositories', {}))}</div>
                    <div class="stat-label">Repositories Audited</div>
                </div>
            </div>

            <!-- Introduction & Framework Overview -->
            {self._render_introduction()}

            <!-- Organization Findings -->
            <div class="findings">
                <h2>Organization-Level Findings</h2>
                
                <div class="org-section">
                    <div class="section-title">Security Settings</div>
                    {self._render_checks(audit_results['checks'].get('organization', {}))}
                </div>
            </div>

            <!-- Repository Findings -->
            <div class="findings">
                <h2>Repository-Level Findings</h2>
                
                <div class="section-title">Detailed Repository Audit Results</div>
                {self._render_access_inventory(audit_results['checks'].get('repositories', {}))}
                {self._render_repo_details(audit_results['checks'].get('repositories', {}))}
                
                <div style="margin-top: 40px;">
                    <div class="section-title">Failed Checks Summary</div>
                    {self._render_failed_checks_summary(audit_results['checks'].get('repositories', {}))}
                </div>
            </div>

            <!-- Compliance by Standards -->
            <div class="findings" style="margin-top: 50px;">
                <h2>Compliance by International Standards</h2>
                <p style="color: var(--secondary); margin-bottom: 20px;">
                    Your GitHub security posture mapped against industry-leading compliance frameworks:
                </p>
                {self._render_compliance_by_standard(audit_results)}
            </div>

            <!-- Compliance Details by Check -->
            <div class="findings" style="margin-top: 50px;">
                <h2>Security Checks & Compliance Mapping</h2>
                <p style="color: var(--secondary); margin-bottom: 20px;">
                    {self._mapping_lead_in()}
                </p>
                {self._render_compliance_details_by_check(audit_results)}
            </div>

            <!-- Compliance Gaps -->
            <div class="findings" style="margin-top: 50px;">
                <h2>Compliance Gaps Analysis</h2>
                <p style="color: var(--secondary); margin-bottom: 20px;">
                    Specific controls that are not yet met for each compliance standard:
                </p>
                {self._render_compliance_gaps(audit_results)}
            </div>

            <!-- Methodology -->
            <div class="findings" style="margin-top: 50px;">
                <h2>How Compliance Score is Calculated</h2>
                <div class="org-section">
                    <div style="background: var(--light); padding: 20px; border-radius: 8px;">
                        <p><strong>Formula:</strong> Compliance Score = (Passed Checks / Total Checks) × 100%</p>
                        <p style="margin-top: 15px;"><strong>Your Results:</strong></p>
                        <ul style="margin-left: 20px; margin-top: 10px;">
                            <li>✅ <strong>Passed Checks:</strong> {summary['passed_checks']}</li>
                            <li>❌ <strong>Failed Checks:</strong> {summary['failed_checks']}</li>
                            <li>→ <strong>Total Checks:</strong> {summary['total_checks']}</li>
                            <li>📊 <strong>Calculation:</strong> {summary['passed_checks']} / {summary['total_checks']} × 100 = <strong>{summary['compliance_score']:.1f}%</strong></li>
                        </ul>
                        <div style="margin-top: 20px; padding: 15px; background: white; border-radius: 6px;">
                            <p><strong>About the Audit:</strong></p>
                            <p style="margin-top: 10px; color: var(--secondary); font-size: 0.95em;">
                                This audit implements 40 security controls that have been specifically selected to address requirements from major international compliance frameworks. 
                                These controls are not arbitrary best practices but rather represent specific requirements from recognized security standards.
                            </p>
                            <p style="margin-top: 10px; color: var(--secondary); font-size: 0.95em;">
                                {self._mapping_lead_in()}
                            </p>
                            <ul style="margin-left: 20px; margin-top: 10px; color: var(--secondary); font-size: 0.95em;">
                                {self._framework_list_items()}
                            </ul>
                            <p style="margin-top: 10px; color: var(--secondary); font-size: 0.95em;">
                                The scoring methodology is straightforward: each control is evaluated as passed or failed based on configuration verification. 
                                Overall compliance score represents the percentage of controls that meet the requirements of each standard.
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Detailed Recommendations -->
            <div class="findings" style="margin-top: 50px;">
                <h2>Recommendations & Action Items</h2>
                {self._render_recommendations(score)}
            </div>
        </div>

        <div class="footer">
            <p>GitHub Security Audit Report | Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p style="margin-top: 10px; font-size: 0.85em;">{self._framework_line()}</p>
        </div>
    </div>
</body>
</html>
"""
        return html

    def _render_checks(self, checks: Dict[str, Any]) -> str:
        """Render check items HTML"""
        html = ""
        for check_name, check_result in checks.get("details", {}).items():
            message = check_result.get("message", "")
            status = check_result.get(
                "status", "pass" if check_result.get("passed") else "fail"
            )
            status_class, status_text, status_color = {
                "pass": ("passed", "PASSED", "#10b981"),
                "fail": ("failed", "FAILED", "#ef4444"),
                "unknown": ("unknown", "NOT CHECKED", "#94a3b8"),
                "not_applicable": ("na", "N/A", "#94a3b8"),
            }.get(status, ("failed", "FAILED", "#ef4444"))
            
            html += f"""
            <div class="check-item {status_class}" style="margin-bottom: 15px; padding: 12px; background: white; border-left: 4px solid {status_color}; border-radius: 4px;">
                <div style="display: flex; gap: 12px; margin-bottom: 6px;">
                    <div style="font-weight: 600; color: {status_color}; min-width: 65px; font-family: monospace;">[{status_text}]</div>
                    <div style="font-weight: 600; color: var(--primary);">{_esc(str(check_name))}</div>
                </div>
                <div style="margin-left: 77px; padding-left: 0;">
                    <div style="font-size: 0.9em; color: var(--secondary); line-height: 1.5;">{_esc(str(message))}</div>
                </div>
            </div>
            """
        return html

    def _render_repo_cards(self, repos: Dict[str, Any]) -> str:
        """Render repository cards"""
        html = ""
        for repo_name, repo_checks in repos.items():
            passed = repo_checks.get("passed", 0)
            evaluated = passed + repo_checks.get("failed", 0)
            total = evaluated if evaluated else repo_checks.get("total", 1)
            percentage = int((passed / evaluated * 100)) if evaluated > 0 else 0
            
            html += f"""
            <div class="repo-card">
                <div class="repo-name">{_esc(str(repo_name))}</div>
                <div class="repo-stats">
                    <div class="repo-stat">
                        <div class="repo-stat-value">{passed}/{total}</div>
                        <div class="repo-stat-label">Checks Passed</div>
                    </div>
                    <div class="repo-stat">
                        <div class="repo-stat-value">{percentage}%</div>
                        <div class="repo-stat-label">Compliance</div>
                    </div>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {percentage}%"></div>
                </div>
            </div>
            """
        return html

    def _render_introduction(self) -> str:
        """Audit scope, written for the standard actually in scope."""
        if self.standard:
            scope_line = (
                f"This audit assesses {self._total_controls()} security controls "
                f"against {_esc(self.standard['reference'])}. Each control is "
                f"mapped to the {_esc(self.standard['control_label'].lower())}s it "
                "provides evidence for."
            )
            rationale_title = "Why these controls"
            rationale = (
                f"Every control in this report maps to at least one "
                f"{_esc(self.standard['control_label'].lower())} in "
                f"{_esc(self.standard['name'])}. Controls that provide no evidence "
                "for this framework are not shown, and do not affect the score."
            )
        else:
            scope_line = (
                f"This audit assesses {self._total_controls()} security controls "
                "against four compliance frameworks. Each control was chosen "
                "because it maps to a specific requirement, rather than to a "
                "general notion of best practice."
            )
            rationale_title = "Why these controls"
            rationale = (
                "These controls sit at the intersection of the four frameworks "
                "below. A control that maps to no framework requirement is not "
                "included, and one that maps to several is reported once."
            )

        return f"""
        <div class="findings" style="margin-top: 50px; background: #f8fafc; padding: 20px; border-radius: 8px; border-left: 4px solid #0f766e;">
            <h2 style="margin-top: 0; color: #0f766e;">Audit Scope &amp; Compliance Framework</h2>

            <p style="color: var(--secondary); line-height: 1.6; margin-bottom: 15px;">
                {scope_line}
            </p>

            {self._framework_blocks()}

            <p style="font-weight: 600; color: var(--primary); margin: 18px 0 10px;">{rationale_title}</p>
            <p style="color: var(--secondary); line-height: 1.6;">
                {rationale}
            </p>

            <p style="color: var(--secondary); line-height: 1.6; margin-top: 15px; font-size: 0.9em;">
                A mapping is an aid to evidence gathering, not a certification. A
                passing control is one input to a requirement; it does not by itself
                satisfy that requirement for an auditor.
            </p>
        </div>
        """

    def _render_compliance_by_standard(self, audit_results: Dict[str, Any]) -> str:
        """Render compliance scores by international standards"""
        compliance_scores = calculate_compliance_scores(audit_results)
        
        html = '''
        <table style="width: 100%; border-collapse: collapse; margin-top: 20px;">
            <thead>
                <tr style="background: var(--light); border-bottom: 2px solid var(--border);">
                    <th style="padding: 15px; text-align: left; font-weight: 600;">Compliance Standard</th>
                    <th style="padding: 15px; text-align: center; font-weight: 600;">Controls Covered</th>
                    <th style="padding: 15px; text-align: center; font-weight: 600;">Compliance Score</th>
                    <th style="padding: 15px; text-align: center; font-weight: 600;">Risk Assessment</th>
                    <th style="padding: 15px; text-align: center; font-weight: 600;">Progress</th>
                </tr>
            </thead>
            <tbody>
        '''
        
        if self.standard:
            standards = [(self.standard["key"], self.standard["name"])]
        else:
            standards = [
                ("soc2", "SOC 2 Trust Services Criteria"),
                ("nist", "NIST SP 800-53 Rev. 5"),
                ("iso27001", "ISO/IEC 27001:2022"),
                ("cis_csc", "CIS Controls v8.1")
            ]
        
        for key, label in standards:
            data = compliance_scores.get(key, {})
            score = data.get("percentage", 0)
            passed = data.get("passed", 0)
            total = data.get("total", 1)
            controls = data.get("controls_covered", 0)
            risk_label, risk_color = get_risk_level_for_standard(score)
            
            # Remove emoji from risk label
            risk_label_clean = risk_label.replace("CRITICAL", "CRITICAL").replace("HIGH", "HIGH").replace("MEDIUM", "MEDIUM").replace("LOW", "LOW")
            
            html += f'''
            <tr style="border-bottom: 1px solid var(--border);">
                <td style="padding: 15px; font-weight: 600;">{label}</td>
                <td style="padding: 15px; text-align: center;">{controls}</td>
                <td style="padding: 15px; text-align: center;">
                    <strong style="color: {risk_color}; font-size: 1.1em;">{score:.1f}%</strong>
                </td>
                <td style="padding: 15px; text-align: center; color: {risk_color}; font-weight: 600;">
                    {risk_label_clean}
                </td>
                <td style="padding: 15px; text-align: center;">
                    <div style="background: var(--border); height: 8px; border-radius: 4px; overflow: hidden; width: 100%;">
                        <div style="background: linear-gradient(90deg, #0f766e 0%, #14b8a6 100%); height: 100%; width: {score}%;"></div>
                    </div>
                    <div style="font-size: 0.8em; color: var(--secondary); margin-top: 4px;">{passed}/{total}</div>
                </td>
            </tr>
            '''
        
        html += '</tbody></table>'
        return html

    def _render_compliance_gaps(self, audit_results: Dict[str, Any]) -> str:
        """
        Failing controls only, as a work list.

        Each row carries the requirement it fails to evidence, what was actually
        observed, and the remediation. Nothing here is a summary: every line is
        a task.
        """
        all_checks = self._collect_checks(audit_results)
        fields = self._framework_fields()

        gaps = []
        for check_name in sorted(all_checks):
            if check_name not in COMPLIANCE_MAPPING:
                continue
            result = all_checks[check_name]
            status = result.get("status", "pass" if result.get("passed") else "fail")
            if status == "fail":
                gaps.append((check_name, result))

        scope = self.standard["name"] if self.standard else "the mapped frameworks"

        if not gaps:
            return f"""
            <div class="org-section">
                <div style="padding: 18px; background: rgba(16, 185, 129, 0.06); border-left: 4px solid var(--success); border-radius: 4px;">
                    <div style="font-weight: 600; color: var(--success);">No failing controls</div>
                    <div style="font-size: 0.9em; color: var(--secondary); margin-top: 8px;">
                        Every control evaluated against {_esc(scope)} passed. Controls
                        reported as Not Checked or N/A are excluded from this list and
                        from the score &mdash; review the applicability notes before
                        treating this as full coverage.
                    </div>
                </div>
            </div>"""

        header = "".join(
            f'<th style="padding: 12px; text-align: left; font-weight: 600;">{_esc(label)}</th>'
            for _, label, _ in fields
        )
        rows = ""
        for check_name, result in gaps:
            guidance = guidance_for(check_name)
            requirement_cells = "".join(
                f'<td style="padding: 12px; vertical-align: top; font-size: 0.85em;">'
                f'{self._requirement_cell(check_name, field)}</td>'
                for field, _, _ in fields
            )
            rows += f"""
            <tr style="border-bottom: 1px solid var(--border);">
                <td style="padding: 12px; vertical-align: top;">
                    <strong style="color: var(--danger);">{_esc(str(check_name))}</strong>
                    <div style="color: var(--secondary); font-size: 0.85em; margin-top: 4px;">
                        {_esc(str(guidance.get("verifies", "")))}
                    </div>
                </td>
                {requirement_cells}
                <td style="padding: 12px; vertical-align: top; font-size: 0.85em;">
                    {_esc(str(result.get("message", "")))}
                </td>
                <td style="padding: 12px; vertical-align: top; font-size: 0.85em; color: var(--secondary);">
                    {_esc(str(guidance.get("remediation", "")))}
                </td>
            </tr>"""

        return f"""
        <div class="org-section">
            <p style="color: var(--secondary); margin-bottom: 14px;">
                {len(gaps)} control(s) fail against {_esc(scope)}. Controls reported as
                Not Checked or N/A are not listed here and do not affect the score.
            </p>
            <table style="width: 100%; border-collapse: collapse; font-size: 0.9em;">
                <thead>
                    <tr style="background: var(--light); border-bottom: 2px solid var(--border);">
                        <th style="padding: 12px; text-align: left; font-weight: 600;">Failing control</th>
                        {header}
                        <th style="padding: 12px; text-align: left; font-weight: 600;">Observed</th>
                        <th style="padding: 12px; text-align: left; font-weight: 600;">Recommendation</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>"""

    def _requirement_cell(self, check_name: str, field: str) -> str:
        """The control identifiers and titles a check maps to, for one framework."""
        mapping = COMPLIANCE_MAPPING.get(check_name, {}).get(field, {})
        if not mapping:
            return "&mdash;"
        if "control" in mapping:
            pairs = [(mapping["control"], mapping.get("title", ""))]
        else:
            controls = mapping.get("controls", [])
            titles = mapping.get("titles", [])
            pairs = [
                (control, titles[i] if i < len(titles) else "")
                for i, control in enumerate(controls)
            ]
        return "<br>".join(
            f'<strong>{_esc(str(control))}</strong>'
            + (f'<br><span style="color: var(--secondary);">{_esc(str(title))}</span>'
               if title and title != control else "")
            for control, title in pairs
        )

    def _collect_checks(self, audit_results: Dict[str, Any]) -> Dict[str, Any]:
        """All distinct checks across the organization and every repository."""
        checks = audit_results.get("checks", {})
        collected: Dict[str, Any] = {}
        for name, result in checks.get("organization", {}).get("details", {}).items():
            collected[name] = result
        for repo_checks in checks.get("repositories", {}).values():
            for name, result in repo_checks.get("details", {}).items():
                existing = collected.get(name)
                # Prefer a scored result over an unscored one when the same
                # check ran against several repositories.
                if existing is None or existing.get("status") in ("unknown", "not_applicable"):
                    collected[name] = result
        return collected

    _STATUS_STYLE = {
        "pass": ("PASSED", "var(--success)"),
        "fail": ("FAILED", "var(--danger)"),
        "unknown": ("NOT CHECKED", "#94a3b8"),
        "not_applicable": ("N/A", "#94a3b8"),
    }

    def _framework_fields(self):
        if self.standard:
            return [(self.standard["key"], self.standard["name"],
                     self.standard["control_label"])]
        return [
            ("soc2", "SOC 2", "Criterion"),
            ("nist", "NIST SP 800-53", "Control"),
            ("iso27001", "ISO/IEC 27001:2022", "Annex A control"),
            ("cis_csc", "CIS Controls v8.1", "Safeguard"),
        ]

    def _render_compliance_details_by_check(self, audit_results: Dict[str, Any]) -> str:
        """
        Every control as a row: what it verifies, the requirement it evidences,
        the result, and what to do about it.

        A list of check names with a tick tells a reader nothing they can act
        on. The requirement and the remediation belong on the same line as the
        finding, because that is the unit of work.
        """
        all_checks = self._collect_checks(audit_results)
        fields = self._framework_fields()

        header = "".join(
            f'<th style="padding: 12px; text-align: left; font-weight: 600;">{_esc(label)}</th>'
            for _, label, _ in fields
        )
        rows = ""

        for check_name in sorted(all_checks):
            if check_name not in COMPLIANCE_MAPPING:
                continue
            result = all_checks[check_name]
            status = result.get(
                "status", "pass" if result.get("passed") else "fail"
            )
            status_text, status_color = self._STATUS_STYLE.get(
                status, ("FAILED", "var(--danger)")
            )
            guidance = guidance_for(check_name)
            requirement_cells = "".join(
                f'<td style="padding: 12px; vertical-align: top; font-size: 0.85em;">'
                f'{self._requirement_cell(check_name, field)}</td>'
                for field, _, _ in fields
            )

            rows += f"""
            <tr style="border-bottom: 1px solid var(--border);">
                <td style="padding: 12px; vertical-align: top;">
                    <strong style="color: var(--primary);">{_esc(str(check_name))}</strong>
                    <div style="color: var(--secondary); font-size: 0.85em; margin-top: 4px;">
                        {_esc(str(guidance.get("verifies", "")))}
                    </div>
                </td>
                {requirement_cells}
                <td style="padding: 12px; vertical-align: top; white-space: nowrap;">
                    <strong style="color: {status_color}; font-family: monospace;">{status_text}</strong>
                </td>
                <td style="padding: 12px; vertical-align: top; font-size: 0.85em; color: var(--secondary);">
                    {_esc(str(guidance.get("remediation", "")))}
                </td>
            </tr>"""

        return f"""
        <div class="org-section">
            <table style="width: 100%; border-collapse: collapse; font-size: 0.9em;">
                <thead>
                    <tr style="background: var(--light); border-bottom: 2px solid var(--border);">
                        <th style="padding: 12px; text-align: left; font-weight: 600;">Security control</th>
                        {header}
                        <th style="padding: 12px; text-align: left; font-weight: 600;">Result</th>
                        <th style="padding: 12px; text-align: left; font-weight: 600;">Recommendation</th>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>"""

    def _render_access_inventory(self, repos: Dict[str, Any]) -> str:
        """
        Who holds what, per repository.

        This section is deliberately unscored. A score tells an auditor a
        conclusion; a roster lets them sample it and reach their own. It is the
        artefact an access review is actually performed against.
        """
        ELEVATED = ("push", "maintain", "admin")
        rows = ""
        any_data = False

        for repo_name, repo_checks in repos.items():
            inventory = repo_checks.get("access_inventory")
            if not inventory:
                continue
            any_data = True

            if not inventory.get("readable"):
                rows += f"""
                <tr>
                    <td style="padding: 10px; font-weight: 600;">{_esc(str(repo_name))}</td>
                    <td colspan="9" style="padding: 10px; color: var(--secondary); font-style: italic;">
                        Not readable: {_esc(str(inventory.get("error") or "unknown reason"))}
                    </td>
                </tr>"""
                continue

            principals = inventory.get("principals", [])
            if not principals:
                rows += f"""
                <tr>
                    <td style="padding: 10px; font-weight: 600;">{_esc(str(repo_name))}</td>
                    <td colspan="9" style="padding: 10px; color: var(--secondary);">
                        No collaborators beyond the owner
                    </td>
                </tr>"""
                continue

            for index, principal in enumerate(principals):
                elevated = principal.get("permission") in ELEVATED
                external = principal.get("affiliation") == "outside collaborator"
                direct = principal.get("affiliation") == "direct"

                flags = []
                if external and elevated:
                    flags.append("external party with write access")
                elif external:
                    flags.append("external party")
                if direct and elevated:
                    flags.append("direct grant, not visible in any team roster")
                if principal.get("permission") == "admin":
                    flags.append("can disable protection and delete the repository")

                caps = principal.get("capabilities") or {}
                colour = "#ef4444" if (elevated and (external or direct)) else (
                    "#f59e0b" if elevated else "var(--secondary)")

                rows += f"""
                <tr style="border-top: 1px solid #e5e7eb;">
                    <td style="padding: 8px 10px; font-weight: 600; color: var(--primary);">
                        {_esc(str(repo_name)) if index == 0 else ""}
                    </td>
                    <td style="padding: 8px 10px;">{_esc(str(principal.get("name", "")))}</td>
                    <td style="padding: 8px 10px; color: var(--secondary);">{_esc(str(principal.get("kind", "")))}</td>
                    <td style="padding: 8px 10px;">{_esc(str(principal.get("affiliation", "")))}</td>
                    <td style="padding: 8px 10px; font-weight: 600; color: {colour};">
                        {_esc(str(principal.get("permission_label", "")))}
                        {(" &mdash; " + _esc("; ".join(flags))) if flags else ""}
                    </td>
                    <td style="padding: 8px 10px; text-align: center;">{"yes" if caps.get("push") else "&mdash;"}</td>
                    <td style="padding: 8px 10px; text-align: center;">{"yes" if caps.get("merge") else "&mdash;"}</td>
                    <td style="padding: 8px 10px; text-align: center;">{"yes" if caps.get("settings") else "&mdash;"}</td>
                    <td style="padding: 8px 10px; text-align: center;">{"yes" if caps.get("delete") else "&mdash;"}</td>
                    <td style="padding: 8px 10px; color: {colour};">{_esc(str(caps.get("risk", "")))}</td>
                </tr>"""

        if not any_data:
            return ""

        return f"""
        <div class="section">
            <h2>Access Inventory</h2>
            <p style="color: var(--secondary); margin-bottom: 8px;">
                Every principal with access to each repository, and the permission held.
                This section is <strong>not scored</strong> &mdash; it is the evidence an
                access review is conducted against. Sample it rather than trusting the
                summary above it.
            </p>
            <p style="color: var(--secondary); margin-bottom: 16px; font-size: 0.9em;">
                <strong>Where an auditor will push back:</strong> a permission granted
                directly to a user appears in no team roster, so a team-based review will
                never surface it. An outside collaborator is an external party holding
                standing access. Admin permits disabling branch protection, rotating
                secrets and deleting the repository &mdash; most holders need Maintain
                instead. Each row flagged below is a question to answer, not necessarily
                a defect.
            </p>
            <table style="width: 100%; border-collapse: collapse; font-size: 0.9em;">
                <tr style="background: #f3f4f6;">
                    <th style="padding: 10px; text-align: left;">Repository</th>
                    <th style="padding: 10px; text-align: left;">Principal</th>
                    <th style="padding: 10px; text-align: left;">Type</th>
                    <th style="padding: 10px; text-align: left;">Granted via</th>
                    <th style="padding: 10px; text-align: left;">Permission</th>
                    <th style="padding: 10px; text-align: center;">Push</th>
                    <th style="padding: 10px; text-align: center;">Merge</th>
                    <th style="padding: 10px; text-align: center;">Settings</th>
                    <th style="padding: 10px; text-align: center;">Delete</th>
                    <th style="padding: 10px; text-align: left;">Risk</th>
                </tr>
                {rows}
            </table>
            <p style="color: var(--secondary); margin-top: 16px; font-size: 0.85em;">
                This table contains usernames. Treat the report as a document holding
                personal data and store it accordingly &mdash; see PRIVACY.md.
            </p>
        </div>"""

    def _render_repo_details(self, repos: Dict[str, Any]) -> str:
        """Render detailed repository findings table"""
        html = '<table style="width: 100%; border-collapse: collapse; margin-top: 20px;">'
        html += '''
        <thead>
            <tr style="background: var(--light); border-bottom: 2px solid var(--border);">
                <th style="padding: 15px; text-align: left; font-weight: 600;">Repository</th>
                <th style="padding: 15px; text-align: center; font-weight: 600;">Checks</th>
                <th style="padding: 15px; text-align: center; font-weight: 600;">Passed</th>
                <th style="padding: 15px; text-align: center; font-weight: 600;">Failed</th>
                <th style="padding: 15px; text-align: center; font-weight: 600;">Score</th>
                <th style="padding: 15px; text-align: center; font-weight: 600;">Status</th>
            </tr>
        </thead>
        <tbody>
        '''
        
        for repo_name, repo_checks in sorted(repos.items()):
            passed = repo_checks.get("passed", 0)
            total = repo_checks.get("total", 1)
            failed = total - passed
            percentage = int((passed / total * 100)) if total > 0 else 0
            
            # Determine status color
            if percentage >= 90:
                status_color = "var(--success)"
                status = "EXCELLENT"
            elif percentage >= 70:
                status_color = "var(--warning)"
                status = "GOOD"
            elif percentage >= 50:
                status_color = "#f97316"
                status = "HIGH RISK"
            else:
                status_color = "var(--danger)"
                status = "CRITICAL"
            
            html += f'''
            <tr style="border-bottom: 1px solid var(--border); hover: background var(--light);">
                <td style="padding: 15px;"><strong>{_esc(str(repo_name))}</strong></td>
                <td style="padding: 15px; text-align: center;">{total}</td>
                <td style="padding: 15px; text-align: center; color: var(--success); font-weight: 600;">{passed}</td>
                <td style="padding: 15px; text-align: center; color: var(--danger); font-weight: 600;">{failed}</td>
                <td style="padding: 15px; text-align: center;"><strong>{percentage}%</strong></td>
                <td style="padding: 15px; text-align: center; color: {status_color}; font-weight: 600;">{status}</td>
            </tr>
            '''
        
        html += '</tbody></table>'
        return html

    def _render_failed_checks_summary(self, repos: Dict[str, Any]) -> str:
        """Render summary of all failed checks"""
        failed_checks = {}
        
        for repo_name, repo_checks in repos.items():
            for check_name, check_result in repo_checks.get("details", {}).items():
                if not check_result.get("passed", False):
                    if check_name not in failed_checks:
                        failed_checks[check_name] = []
                    failed_checks[check_name].append({
                        "repo": repo_name,
                        "message": check_result.get("message", "")
                    })
        
        if not failed_checks:
            return '<div class="org-section"><p style="color: var(--success); font-weight: 600;">All checks passed</p></div>'
        
        html = '<div class="org-section">'
        for check_name in sorted(failed_checks.keys()):
            repos_failed = failed_checks[check_name]
            html += f'''
            <div style="margin-bottom: 25px; padding: 15px; background: rgba(239, 68, 68, 0.05); border-left: 4px solid var(--danger); border-radius: 4px;">
                <div style="font-weight: 600; color: var(--primary); margin-bottom: 10px;">FAILED - {_esc(str(check_name))}</div>
                <div style="font-size: 0.9em; color: var(--secondary); margin-bottom: 10px;">
                    Found in {len(repos_failed)} repository/repositories
                </div>
            '''
            
            for repo_fail in repos_failed:
                html += f'''
                <div style="margin: 8px 0; padding: 8px; background: white; border-radius: 4px; font-size: 0.9em;">
                    <strong>Repository: {_esc(str(repo_fail['repo']))}</strong>
                    <div style="color: var(--secondary); margin-top: 4px;">Status: {_esc(str(repo_fail['message']))}</div>
                </div>
                '''
            
            html += '</div>'
        
        html += '</div>'
        return html

    def _render_recommendations(self, score: float) -> str:
        """Render recommendations based on score"""
        recommendations = {}
        
        if score < 50:
            recommendations = {
                "CRITICAL PRIORITY": [
                    "Enable 2FA for all organization members immediately",
                    "Configure branch protection rules on ALL main branches",
                    "Enable secrets scanning on all repositories",
                    "Require code reviews before merging (minimum 1 approval)",
                    "Audit repository access and remove unnecessary permissions",
                    "Enable dependency vulnerability alerts",
                    "Set up commit signing enforcement on critical repos",
                ]
            }
        elif score < 70:
            recommendations = {
                "HIGH PRIORITY": [
                    "Enforce commit signing on sensitive repositories",
                    "Implement comprehensive branch protection policies",
                    "Enable dependency vulnerability alerts on all repos",
                    "Add SECURITY.md to public repositories",
                    "Configure PR review requirements",
                    "Audit and rotate SSH keys and personal tokens",
                ],
                "MEDIUM PRIORITY": [
                    "Add CODEOWNERS files to repositories",
                    "Implement .gitignore for secrets prevention",
                ]
            }
        elif score < 90:
            recommendations = {
                "MEDIUM PRIORITY": [
                    "Add CODEOWNERS files to remaining repositories",
                    "Implement SECURITY.md files across all repositories",
                    "Ensure all sensitive repos are private",
                    "Regular audit of collaborator access (quarterly)",
                ],
                "GOOD PRACTICES": [
                    "Document security policies for new team members",
                    "Schedule monthly security audits",
                ]
            }
        else:
            recommendations = {
                "EXCELLENT POSTURE": [
                    "Maintain current security practices",
                    "Continue regular monthly audits and updates",
                    "Stay informed about GitHub security updates",
                    "Share security practices with team members",
                    "Consider implementing additional security tools",
                ]
            }

        html = '<div class="org-section">'
        for priority, items in recommendations.items():
            html += f'<div style="margin-bottom: 20px;"><strong style="font-size: 1.1em; color: var(--primary);">{priority}</strong>'
            for item in items:
                html += f'<div style="margin: 8px 0 8px 20px; color: var(--secondary);">• {item}</div>'
            html += '</div>'
        html += '</div>'
        
        return html

    @staticmethod
    def _get_risk_css_class(score: float) -> str:
        """Get CSS class for risk badge"""
        if score >= 90:
            return "low"
        elif score >= 70:
            return "medium"
        elif score >= 50:
            return "high"
        else:
            return "critical"
