"""Wiki content with proper formatting and control details"""

WIKI_GETTING_STARTED = """
<h2>Getting Started with GitHub Security Auditor</h2>

<h3>Step 1: Create a GitHub Personal Access Token</h3>
<ol>
    <li>Go to <a href="https://github.com/settings/tokens?type=beta" target="_blank">GitHub Settings → Developer settings → Fine-grained tokens</a></li>
    <li>Generate a new token, scoped to the organization or specific repositories you want to audit</li>
    <li>Grant <strong>read-only</strong> access to:
        <ul>
            <li><code>Metadata</code> - required for every repository</li>
            <li><code>Administration</code> - branch protection, rulesets, collaborators</li>
            <li><code>Contents</code> - SECURITY.md, CODEOWNERS, .gitignore, workflow files</li>
            <li><code>Dependabot alerts</code> - dependency vulnerability scanning status</li>
            <li><code>Secret scanning alerts</code> - secret scanning and push protection status</li>
        </ul>
    </li>
    <li>Copy the token</li>
</ol>
<p>Do not grant <code>repo</code> on a classic token. It confers full write access to
every repository, and this tool never writes anything - it only reads settings
through the GitHub API.</p>

<div class="info-box">
    <strong>Security Note:</strong> This token has access to your repositories. Store it securely and never commit it to version control.
</div>

<h3>Step 2: Start an Audit</h3>
<ol>
    <li>Click "Start New Audit" button on home page</li>
    <li>Paste your GitHub token</li>
    <li>Enter your organization name or username</li>
    <li>Click "Start Audit"</li>
</ol>

<h3>Step 3: Wait for Results</h3>
<p>The audit will run in the background. You'll see a progress page while it's running. Duration depends on repository count:</p>
<ul>
    <li>Small org (&lt;10 repos): 2-3 minutes</li>
    <li>Medium org (10-50 repos): 5-8 minutes</li>
    <li>Large org (50+ repos): 10-20 minutes</li>
</ul>

<h3>Step 4: Review Results</h3>
<p>Once complete, dashboard displays:</p>
<ul>
    <li>Overall compliance score (0-100%)</li>
    <li>Risk level assessment</li>
    <li>Number of passed/failed checks</li>
    <li>Options to download reports</li>
</ul>

<h3>Step 5: Download Reports</h3>
<p>Two report formats available:</p>
<ul>
    <li><strong>HTML Report:</strong> Visual format with detailed findings, compliance mapping, recommendations</li>
    <li><strong>JSON Report:</strong> Machine-readable format for integration with other tools</li>
</ul>

<h3>Step 6: Schedule Regular Audits</h3>
<p>Recommended: Run audits monthly to track progress and catch new issues.</p>
"""

WIKI_ORG_CHECKS = """
<h2>Organization-Level Checks</h2>
<p>These 5 checks examine your GitHub organization's core security settings.</p>

<div class="control-box">
    <h3>1. Two-Factor Authentication (2FA) Enforcement</h3>
    <p><strong>What it checks:</strong> Is 2FA required for all organization members?</p>
    <p><strong>Why it matters:</strong> 2FA is the most effective defense against account takeover. Even if passwords are compromised, unauthorized access is prevented.</p>
    <p><strong>Status meanings:</strong></p>
    <ul>
        <li><strong>PASSED:</strong> All members required to use 2FA</li>
        <li><strong>FAILED:</strong> 2FA not required, or some members don't have it enabled</li>
    </ul>
    <p><strong>How to fix if failing:</strong></p>
    <ul>
        <li>Organization Settings → Security</li>
        <li>Enable "Require two-factor authentication"</li>
        <li>Members have 1-30 days to enable 2FA</li>
        <li>Communicate deadline to team</li>
    </ul>
    <p><strong>Compliance impact:</strong> Required for SOC2, NIST, ISO27001, CIS</p>
</div>

<div class="control-box">
    <h3>2. SSO Configuration</h3>
    <p><strong>What it checks:</strong> Is SAML Single Sign-On configured?</p>
    <p><strong>Why it matters:</strong> SSO enables centralized identity management, faster offboarding, and consistent access control policies.</p>
    <p><strong>Status meanings:</strong></p>
    <ul>
        <li><strong>PASSED:</strong> SAML SSO is configured and enabled</li>
        <li><strong>FAILED:</strong> SSO not configured (requires Enterprise)</li>
    </ul>
    <p><strong>⚠️ Note:</strong> This feature requires GitHub Enterprise. Free/Pro/Team plans don't support SSO.</p>
    <p><strong>Compliance impact:</strong> SOC2 (CC6.1), NIST (AC-2, IA-2), ISO27001 (A.9.2.1), CIS (5.1)</p>
</div>

<div class="control-box">
    <h3>3. Access Control Policies</h3>
    <p><strong>What it checks:</strong> Does the organization have members with defined access levels?</p>
    <p><strong>Why it matters:</strong> Principle of least privilege ensures users have minimum necessary permissions, reducing risk from compromised accounts.</p>
    <p><strong>Status meanings:</strong></p>
    <ul>
        <li><strong>PASSED:</strong> Members configured with appropriate roles</li>
        <li><strong>FAILED:</strong> No members or access not properly configured</li>
    </ul>
    <p><strong>How to fix if failing:</strong></p>
    <ul>
        <li>Organization Settings → Members</li>
        <li>Assign appropriate roles: Owner, Maintainer, or Member</li>
        <li>Review permissions quarterly</li>
        <li>Remove access for inactive members</li>
    </ul>
    <p><strong>Compliance impact:</strong> SOC2, NIST, ISO27001, CIS</p>
</div>

<div class="control-box">
    <h3>4. Audit Logging</h3>
    <p><strong>What it checks:</strong> Are audit logs being recorded and accessible?</p>
    <p><strong>Why it matters:</strong> Audit logs provide forensic capability for security investigations, compliance audits, and tracking unauthorized changes.</p>
    <p><strong>Status meanings:</strong></p>
    <ul>
        <li><strong>PASSED:</strong> Audit logs enabled and accessible</li>
        <li><strong>FAILED:</strong> Logs not available (requires Enterprise)</li>
    </ul>
    <p><strong>⚠️ Note:</strong> This feature requires GitHub Enterprise. Free/Pro/Team plans don't record audit logs.</p>
    <p><strong>What's logged:</strong> Member invitations, 2FA changes, permission modifications, repository creation, key uploads</p>
    <p><strong>Compliance impact:</strong> SOC2 (CC6.1, CC7.2), NIST (AU-2, AU-3), ISO27001 (A.12.4.1), CIS (5.3)</p>
</div>

<div class="control-box">
    <h3>5. Member Privileges Configuration</h3>
    <p><strong>What it checks:</strong> Are member privileges properly configured?</p>
    <p><strong>Why it matters:</strong> Ensures members have appropriate roles and restrictions are in place to prevent unauthorized actions.</p>
    <p><strong>Status meanings:</strong></p>
    <ul>
        <li><strong>PASSED:</strong> Members have appropriate privilege levels</li>
        <li><strong>FAILED:</strong> Privilege configuration issues detected</li>
    </ul>
    <p><strong>Role types:</strong></p>
    <ul>
        <li><strong>Owner:</strong> Full access, can manage billing and members</li>
        <li><strong>Maintainer:</strong> Can manage repositories and teams</li>
        <li><strong>Member:</strong> Default access to team repositories</li>
    </ul>
    <p><strong>Compliance impact:</strong> SOC2, NIST, ISO27001, CIS</p>
</div>
"""

WIKI_COMPLIANCE = """
<h2>Compliance Standards Explained</h2>
<p>This auditor maps each control to 4 major compliance frameworks. Choose the standard(s) that apply to your organization.</p>

<div class="control-box">
    <h3>SOC 2 Trust Services Criteria</h3>
    <p><strong>Full name:</strong> Service Organization Control Framework</p>
    <p><strong>Who needs it:</strong> SaaS companies, cloud service providers, any company processing customer data</p>
    <p><strong>What it covers:</strong></p>
    <ul>
        <li>Security - Protection from unauthorized access</li>
        <li>Availability - System uptime and performance</li>
        <li>Processing Integrity - Accurate and complete processing</li>
        <li>Confidentiality - Protection of sensitive information</li>
        <li>Privacy - Responsible personal data handling</li>
    </ul>
    <p><strong>Certification:</strong> Requires independent auditor (annual audit)</p>
    <p><strong>Cost:</strong> $15,000-50,000 for audit</p>
    <p><strong>Use case:</strong> Customers often require this for enterprise contracts</p>
</div>

<div class="control-box">
    <h3>NIST SP 800-53 Rev. 5</h3>
    <p><strong>Full name:</strong> National Institute of Standards and Technology - Security Controls</p>
    <p><strong>Who needs it:</strong> Federal contractors, government agencies, critical infrastructure operators</p>
    <p><strong>What it covers:</strong></p>
    <ul>
        <li>Access Control - Who can do what</li>
        <li>Identification & Authentication - Verifying identities</li>
        <li>Audit & Accountability - Tracking actions</li>
        <li>System & Communications Protection - Encryption and security</li>
        <li>System Development Lifecycle - Secure software practices</li>
    </ul>
    <p><strong>Certification:</strong> Required for federal contracts (FedRAMP)</p>
    <p><strong>Scope:</strong> 800+ security controls across 23 families</p>
    <p><strong>Use case:</strong> Mandatory for any U.S. government work</p>
</div>

<div class="control-box">
    <h3>ISO/IEC 27001:2022</h3>
    <p><strong>Full name:</strong> International Organization for Standardization - Information Security Management System</p>
    <p><strong>Who needs it:</strong> Global enterprises, multinational organizations, regulated industries</p>
    <p><strong>What it covers:</strong></p>
    <ul>
        <li>Information Security Governance - Policies and roles</li>
        <li>Access Control - User permissions and authentication</li>
        <li>Cryptography - Encryption and key management</li>
        <li>Physical & Environmental Security - Data center protection</li>
        <li>Operations - Incident response and change management</li>
    </ul>
    <p><strong>Certification:</strong> Requires independent auditor (annual recertification)</p>
    <p><strong>Scope:</strong> 114 controls across 14 domains</p>
    <p><strong>Use case:</strong> International standard, widely recognized globally</p>
</div>

<div class="control-box">
    <h3>CIS Controls v8</h3>
    <p><strong>Full name:</strong> Center for Internet Security - Critical Security Controls</p>
    <p><strong>Who needs it:</strong> All organizations (good starting point for any business)</p>
    <p><strong>What it covers:</strong></p>
    <ul>
        <li>Inventory Management - Asset tracking</li>
        <li>Access Control Management - Secure authentication</li>
        <li>Vulnerability & Patch Management - Fixing security issues</li>
        <li>Secure Configuration - Hardening systems</li>
        <li>Account Management - User provisioning/deprovisioning</li>
    </ul>
    <p><strong>Certification:</strong> No formal certification, but widely recognized</p>
    <p><strong>Prioritization:</strong> Controls grouped by implementation difficulty and impact</p>
    <p><strong>Use case:</strong> Best practices based on real-world threat data, easiest to start with</p>
</div>

<h3>Compliance Score Reference</h3>
<table>
    <tr>
        <th>Score Range</th>
        <th>Risk Level</th>
        <th>What It Means</th>
        <th>Action Required</th>
    </tr>
    <tr>
        <td>90-100%</td>
        <td><strong style="color: #3fb950;">LOW RISK</strong></td>
        <td>Excellent security posture</td>
        <td>Maintain current practices, monitor for new threats</td>
    </tr>
    <tr>
        <td>70-89%</td>
        <td><strong style="color: #d29922;">MEDIUM RISK</strong></td>
        <td>Good practices, room for improvement</td>
        <td>Address gaps within next quarter</td>
    </tr>
    <tr>
        <td>50-69%</td>
        <td><strong style="color: #f59e0b;">HIGH RISK</strong></td>
        <td>Significant security gaps</td>
        <td>Create action plan immediately, prioritize fixes</td>
    </tr>
    <tr>
        <td>0-49%</td>
        <td><strong style="color: #ef4444;">CRITICAL RISK</strong></td>
        <td>Major security failures</td>
        <td>Address urgent items immediately, escalate to leadership</td>
    </tr>
</table>
"""

WIKI_INTERPRETING = """
<h2>Interpreting Your Audit Results</h2>

<h3>Understanding the Overall Score</h3>
<p>The compliance score represents what percentage of security controls are properly configured:</p>
<p><code>Score = (Passed Checks / Total Checks) × 100%</code></p>

<h3>Risk Level Meanings</h3>
<div class="control-box">
    <h4>LOW RISK (90-100%)</h4>
    <p>Your organization has strong security practices and is well-positioned for compliance audits. Focus on maintaining these practices and staying informed about new threats.</p>
</div>

<div class="control-box">
    <h4>MEDIUM RISK (70-89%)</h4>
    <p>You have good practices but identified gaps should be addressed. Create a roadmap to close gaps within the next quarter.</p>
</div>

<div class="control-box">
    <h4>HIGH RISK (50-69%)</h4>
    <p>Significant gaps exist that could impact your security posture or compliance status. Create action plan immediately and prioritize fixes by impact.</p>
</div>

<div class="control-box">
    <h4>CRITICAL RISK (0-49%)</h4>
    <p>Major security failures detected. Address urgent items immediately and escalate to leadership for resource allocation.</p>
</div>

<h3>Passed vs Failed Checks</h3>
<p><strong>Passed checks:</strong> Security controls that are properly configured and working as intended.</p>
<p><strong>Failed checks:</strong> Security controls that are missing, misconfigured, or unavailable on your plan tier.</p>

<div class="info-box">
    <strong>Note:</strong> Some failures are expected on lower GitHub plans (SSO, Audit Logging require Enterprise).
</div>

<h3>Compliance by Standards</h3>
<p>Each standard has its own score because:</p>
<ul>
    <li>Different standards have different requirements</li>
    <li>Some checks only apply to enterprise plans</li>
    <li>Some controls map to multiple frameworks</li>
    <li>Your organization may pass different checks for each standard</li>
</ul>

<h3>Compliance Gaps Analysis</h3>
<p>Reports list specific controls not met, including:</p>
<ul>
    <li>Which standard requires this control</li>
    <li>Which specific control is missing</li>
    <li>Current status and failure reason</li>
    <li>Recommended remediation steps</li>
</ul>

<h3>Recommendations Priority Levels</h3>
<ul>
    <li><strong>CRITICAL:</strong> Address immediately, compliance at risk</li>
    <li><strong>HIGH:</strong> Address within next quarter</li>
    <li><strong>MEDIUM:</strong> Address within 6 months</li>
    <li><strong>GOOD:</strong> Nice to have, consider for enhanced security</li>
</ul>

<h3>Action Plan Template</h3>
<ol>
    <li><strong>Review Score:</strong> Check compliance score and risk level</li>
    <li><strong>Identify Gaps:</strong> Note which checks failed and why</li>
    <li><strong>Prioritize:</strong> Focus on CRITICAL and HIGH items first</li>
    <li><strong>Assign Owner:</strong> Who is responsible for each fix?</li>
    <li><strong>Set Timeline:</strong> When should each be completed?</li>
    <li><strong>Track Progress:</strong> Re-run audit monthly</li>
    <li><strong>Celebrate Wins:</strong> Share improvements with team</li>
</ol>

<h3>Re-running Audits</h3>
<p>Schedule regular audits to track progress:</p>
<ul>
    <li><strong>Monthly:</strong> Recommended frequency</li>
    <li><strong>Quarterly:</strong> Minimum frequency</li>
    <li><strong>Before/After Major Changes:</strong> Verify impact of configuration changes</li>
</ul>
<p>Use the History page to compare scores over time and demonstrate security improvements.</p>
"""

WIKI_FAQ = """
<h2>Frequently Asked Questions</h2>

<div class="control-box">
    <h4>How often should I run audits?</h4>
    <p>We recommend running audits monthly. This helps you:</p>
    <ul>
        <li>Detect configuration changes quickly</li>
        <li>Track security improvements over time</li>
        <li>Provide evidence for compliance auditors</li>
        <li>Catch new security issues early</li>
    </ul>
</div>

<div class="control-box">
    <h4>What if I'm not using GitHub Enterprise?</h4>
    <p>You'll see expected failures for:</p>
    <ul>
        <li>SSO Configuration (Enterprise only)</li>
        <li>Audit Logging (Enterprise only)</li>
    </ul>
    <p>These are not security failures - just limitations of your GitHub plan. Focus on the controls available to you on your current plan.</p>
</div>

<div class="control-box">
    <h4>Is this tool free?</h4>
    <p>Yes! This tool is open source and free to use. No subscriptions, no data collection, no external services required.</p>
</div>

<div class="control-box">
    <h4>Can I share results with my team?</h4>
    <p>Download the HTML or JSON report and share it. The HTML report is self-contained and opens in any browser.</p>
</div>

<div class="control-box">
    <h4>What if a check fails but I know it's configured?</h4>
    <p>Some checks require specific permissions or plan features. Common issues:</p>
    <ul>
        <li><strong>Token permissions:</strong> The token needs Administration and Contents access (fine-grained), or <code>read:org</code> (classic) for organization-level checks</li>
        <li><strong>User role:</strong> Several checks require organization owner access, not just membership</li>
        <li><strong>Plan limitations:</strong> Some features require a paid plan - see the applicability notes in the report</li>
    </ul>
    <p>Checks that cannot be evaluated show as "Not Checked" or "N/A" rather than
    "Failed" - check the message on that row for the specific reason.</p>
</div>

<div class="control-box">
    <h4>Does this tool access my code?</h4>
    <p>No. This tool only checks security settings and configuration. It never accesses, analyzes, or stores your actual code.</p>
</div>

<div class="control-box">
    <h4>How does this relate to GitHub's native security features?</h4>
    <p>This tool complements GitHub's features:</p>
    <ul>
        <li><strong>GitHub Security Alerts:</strong> Notifies of known vulnerabilities in dependencies</li>
        <li><strong>Dependabot:</strong> Automated dependency updates and security patches</li>
        <li><strong>Code Scanning:</strong> Static analysis in CI/CD pipeline</li>
        <li><strong>Secret Scanning:</strong> Detects exposed secrets and tokens</li>
    </ul>
    <p>This auditor verifies these features are enabled and properly configured.</p>
</div>

<div class="control-box">
    <h4>Can I integrate this with my CI/CD?</h4>
    <p>Yes! Download the JSON report and use it in your pipeline. The JSON format is machine-readable for integration with other tools and automation.</p>
</div>

<div class="control-box">
    <h4>What are the system requirements?</h4>
    <p>Minimum requirements:</p>
    <ul>
        <li>Python 3.7 or higher</li>
        <li>2GB RAM</li>
        <li>Internet connection (for GitHub API calls)</li>
        <li>macOS, Linux, or Windows</li>
    </ul>
</div>

<div class="control-box">
    <h4>Is my GitHub token stored anywhere?</h4>
    <p>No. Your GitHub token is:</p>
    <ul>
        <li>✅ Entered only in your browser</li>
        <li>✅ NOT stored on disk</li>
        <li>✅ NOT logged or captured</li>
        <li>✅ Only used for API calls to GitHub</li>
        <li>✅ Session-specific and temporary</li>
    </ul>
</div>
"""


WIKI_APPLICABILITY = """
<h2>What applies to your account</h2>
<p>Not every check can run against every GitHub account. Some controls exist only on
organizations, some only on paid plans, and some need repository admin on the token.
A check that cannot apply is reported <strong>Not Applicable</strong> and is
<strong>excluded from the score</strong> &mdash; it is never counted as a failure.</p>

<p>This is why the report shows a <strong>coverage</strong> figure next to the score.
A 60% score over 29 scored checks is a different statement from 60% over all 36.
Read the coverage line before the score.</p>

<h3>Result states</h3>
<table>
<tr><th>State</th><th>Meaning</th><th>In the score</th></tr>
<tr><td>Passed</td><td>Control is configured</td><td>yes</td></tr>
<tr><td>Failed</td><td>Control is missing or misconfigured</td><td>yes</td></tr>
<tr><td>Not Checked</td><td>Could not determine &mdash; token permission, plan add-on, or an unrecognised API field</td><td><strong>no</strong></td></tr>
<tr><td>N/A</td><td>Cannot apply &mdash; wrong account type, plan restriction, or a prerequisite already reported</td><td><strong>no</strong></td></tr>
</table>
<p>The last two are deliberately distinct: the first means <em>we could not find out</em>,
the second means <em>there is nothing to find out</em>.</p>

<h3>Organization checks (9 of 40)</h3>
<p>None of these exist on a personal account. There is no membership policy, no default
repository permission and no organization Actions policy to read. All eight require
<strong>organization owner</strong> access on the token; with member access they return
Not Checked.</p>
<table>
<tr><th>Check</th><th>Personal</th><th>Org (Free)</th><th>Team</th><th>Enterprise</th></tr>
<tr><td>2FA Enforcement</td><td>N/A</td><td>yes</td><td>yes</td><td>yes</td></tr>
<tr><td>SSO Configuration</td><td>N/A</td><td>N/A</td><td colspan="2">not implemented</td></tr>
<tr><td>Default Repository Permission</td><td>N/A</td><td>yes</td><td>yes</td><td>yes</td></tr>
<tr><td>Member Repository Creation</td><td>N/A</td><td>yes</td><td>yes</td><td>yes</td></tr>
<tr><td>Audit Logging</td><td>N/A</td><td>N/A</td><td>N/A</td><td>not implemented</td></tr>
<tr><td>Actions Allowed Actions Policy</td><td>N/A</td><td>yes</td><td>yes</td><td>yes</td></tr>
<tr><td>Actions Default Token Permissions</td><td>N/A</td><td>yes</td><td>yes</td><td>yes</td></tr>
<tr><td>Actions Pull Request Approval</td><td>N/A</td><td>yes</td><td>yes</td><td>yes</td></tr>
</table>
<p><strong>SSO and Audit Logging are honest placeholders.</strong> SAML status is not
exposed by the REST API and the audit log endpoint is absent from the client library.
Both always return Not Checked with an explanation.</p>

<h3>Branch protection depends on your plan</h3>
<p>Eleven repository checks depend on branch protection or a ruleset.</p>
<table>
<tr><th>Repository</th><th>Personal (any plan)</th><th>Org Free</th><th>Team / Enterprise</th></tr>
<tr><td>Public</td><td>enforced</td><td>enforced</td><td>enforced</td></tr>
<tr><td>Private</td><td>not established</td><td><strong>not enforced</strong></td><td>enforced</td></tr>
</table>
<p>GitHub states this directly on Settings &rarr; Rules for a private repository under a
free plan: <em>"Your rulesets won't be enforced on this private repository until you
upgrade this organization account to GitHub Team."</em></p>
<p>Where protection is not enforceable, those eleven checks report N/A rather than
failing. You are not marked down for a feature the plan does not provide, and the
finding still names the remediation.</p>
<p><strong>One missing setting produces one finding.</strong> If the default branch has no
protection, only <em>Branch Protection Rules</em> fails; the other ten report N/A and
point back at it. Otherwise a single setting would drive a third of the score.</p>

<h3>Secret scanning on private repositories</h3>
<p>Secrets Scanning and Push Protection are free on public repositories. On private
repositories they require the GitHub Secret Protection add-on; without it the API omits
the relevant block and both report Not Checked. That is indistinguishable from a token
without repository admin &mdash; if you see it, check both.</p>

<h3>Measured coverage</h3>
<table>
<tr><th>Target</th><th>Scored</th><th>Coverage</th></tr>
<tr><td>Personal account, free</td><td>25 of 64</td><td>39%</td></tr>
<tr><td>Personal account, paid</td><td>26 of 64</td><td>41%</td></tr>
<tr><td>Organization, free</td><td>28 of 64</td><td>44%</td></tr>
<tr><td>Organization, Team</td><td>29 of 64</td><td>45%</td></tr>
</table>
<p>Coverage below 100% is normal. To raise yours: grant the token organization owner
access (unlocks eight checks), grant repository admin (unlocks the Actions settings and
secret scanning checks), and move private repositories to a Team organization (brings the
eleven branch protection checks into scope).</p>
"""
