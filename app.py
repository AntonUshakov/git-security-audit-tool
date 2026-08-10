"""
GitHub Security Auditor - Web Application
Complete web interface with proper wiki rendering
"""

from flask import Flask, render_template_string, request, jsonify, send_file, abort
from werkzeug.utils import secure_filename
import secrets
from github_auditor import GitHubAuditor
from config import Config
from report_generator import ReportGenerator
import json
import os
from datetime import datetime
from pathlib import Path
import threading

_history_lock = threading.Lock()

# Import wiki content
try:
    from wiki_content import (
        WIKI_GETTING_STARTED,
        WIKI_ORG_CHECKS,
        WIKI_COMPLIANCE,
        WIKI_INTERPRETING,
        WIKI_FAQ,
        WIKI_APPLICABILITY
    )
except ImportError:
    # Fallback to inline if wiki_content.py not found
    WIKI_GETTING_STARTED = "<h2>Getting Started</h2><p>Coming soon...</p>"
    WIKI_ORG_CHECKS = "<h2>Organization Checks</h2><p>Coming soon...</p>"
    WIKI_COMPLIANCE = "<h2>Compliance Standards</h2><p>Coming soon...</p>"
    WIKI_INTERPRETING = "<h2>Interpreting Results</h2><p>Coming soon...</p>"
    WIKI_FAQ = "<h2>FAQ</h2><p>Coming soon...</p>"

def _safe_error(exc: Exception) -> str:
    """
    Return an error string safe to show in the UI.

    Exception text can carry request URLs and, in some client libraries,
    authorization headers. Never surface a raw exception to the browser.
    """
    status = getattr(exc, "status", None)
    if status == 401:
        return "GitHub rejected the token (401). Check that it is valid and not expired."
    if status == 403:
        return "GitHub returned 403. The token lacks the required scopes, or you hit a rate limit."
    if status == 404:
        return "Organization or user not found (404)."
    return f"Audit failed: {type(exc).__name__}. See server logs for details."


# Store audit results and session data
audit_sessions = {}
audit_history = {}

def create_app(org=None):
    """Create Flask application"""
    app = Flask(__name__)
    app.secret_key = secrets.token_bytes(32)
    
    # Create results directory
    results_dir = Path("audit_results")
    results_dir.mkdir(exist_ok=True)
    
    # Load audit history
    history_file = results_dir / "history.json"
    global audit_history
    if history_file.exists():
        with open(history_file, 'r') as f:
            audit_history = json.load(f)
    
    @app.route('/')
    def index():
        """Landing page with instructions"""
        return render_template_string(LANDING_PAGE_TEMPLATE)
    
    @app.route('/start')
    def start_audit_page():
        """Page to start new audit"""
        return render_template_string(START_AUDIT_TEMPLATE)
    
    @app.route('/api/start-audit', methods=['POST'])
    def start_audit():
        """Start new audit"""
        data = request.json
        github_token = data.get('token')
        account_type = data.get('account_type', 'auto')
        standard = data.get('standard', 'all')
        org_name = data.get('org')
        # Session ids are generated server-side. A client-supplied id would be
        # both guessable and overwritable by anyone who can reach the port.
        session_id = secrets.token_urlsafe(32)
        
        if not github_token or not org_name:
            return jsonify({"error": "Token and organization name required"}), 400
        
        def run_audit(token=github_token):
            auditor = None
            try:
                config = Config(github_token=token, org_name=org_name,
                                account_type=account_type)
                auditor = GitHubAuditor(config)
                results = auditor.audit_organization(verbose=False)
                
                results["standard_requested"] = standard
                audit_sessions[session_id] = {
                    "status": "completed",
                    "results": results,
                    "timestamp": datetime.now().isoformat(),
                    "org": org_name
                }
                
                # Save to history
                with _history_lock:
                    audit_history[session_id] = {
                        "org": org_name,
                        "timestamp": datetime.now().isoformat(),
                        "score": results['summary']['compliance_score']
                    }
                    history_file = Path("audit_results/history.json")
                    with open(history_file, 'w') as f:
                        json.dump(audit_history, f, indent=2)
                
            except Exception as e:
                audit_sessions[session_id] = {
                    "status": "error",
                    "error": _safe_error(e),
                    "timestamp": datetime.now().isoformat()
                }
            finally:
                # Drop every reference to the credential before the thread exits.
                token = None
                del auditor
        
        # Start audit in background
        audit_sessions[session_id] = {
            "status": "running",
            "timestamp": datetime.now().isoformat(),
            "org": org_name
        }
        
        thread = threading.Thread(target=run_audit)
        thread.start()
        
        return jsonify({"session_id": session_id, "status": "started"})
    
    @app.route('/api/audit-status/<session_id>')
    def audit_status(session_id):
        """Get audit status"""
        if session_id not in audit_sessions:
            return jsonify({"error": "Session not found"}), 404
        
        session = audit_sessions[session_id]
        return jsonify(session)
    
    @app.route('/dashboard/<session_id>')
    def dashboard(session_id):
        """View audit results dashboard"""
        if session_id not in audit_sessions:
            return render_template_string(ERROR_TEMPLATE, error="Session not found")
        
        session = audit_sessions[session_id]
        if session['status'] == 'running':
            return render_template_string(LOADING_TEMPLATE, session_id=session_id)
        elif session['status'] == 'error':
            return render_template_string(ERROR_TEMPLATE, error=session.get('error', 'Unknown error'))
        
        results = session['results']
        return render_template_string(DASHBOARD_TEMPLATE, results=results, session_id=session_id)
    
    @app.route('/api/report/<session_id>/<format>')
    def get_report(session_id, format):
        """Generate and download report"""
        if session_id not in audit_sessions:
            return jsonify({"error": "Session not found"}), 404
        
        session = audit_sessions[session_id]
        if session['status'] != 'completed':
            return jsonify({"error": "Audit not completed"}), 400
        
        results = session['results']
        org = session['org']
        
        # Create minimal config for report generation (doesn't need token)
        class MinimalConfig:
            def __init__(self, org_name):
                self.org_name = org_name
        
        config = MinimalConfig(org)
        generator = ReportGenerator(
            config, standard=results.get("standard_requested", "all")
        )
        
        if format not in ('html', 'json'):
            abort(404)

        # `org` is user-supplied. Without sanitisation "../../x" escapes the
        # results directory and writes an attacker-named file.
        safe_org = secure_filename(org) or "organization"
        safe_id = secure_filename(session_id)
        results_root = Path("audit_results").resolve()

        if format == 'html':
            content = generator.generate_html_report(results)
            mimetype = 'text/html'
        else:
            content = generator.generate_json_report(results)
            mimetype = 'application/json'

        filename = f"audit_{safe_org}_{safe_id}.{format}"
        target = (results_root / filename).resolve()
        if target.parent != results_root:
            abort(400)

        target.write_text(content, encoding='utf-8')
        return send_file(str(target), mimetype=mimetype,
                         as_attachment=True, download_name=filename)
    
    @app.route('/wiki')
    def wiki():
        """Documentation wiki"""
        return render_template_string(WIKI_TEMPLATE)
    
    @app.route('/wiki/<page>')
    def wiki_page(page):
        """Individual wiki page"""
        wiki_pages = {
            'getting-started': WIKI_GETTING_STARTED,
            'organization-checks': WIKI_ORG_CHECKS,
            'compliance-standards': WIKI_COMPLIANCE,
            'interpreting-results': WIKI_INTERPRETING,
            'applicability': WIKI_APPLICABILITY,
            'faq': WIKI_FAQ
        }
        
        if page not in wiki_pages:
            return render_template_string(WIKI_TEMPLATE)
        
        content = wiki_pages[page]
        return render_template_string(WIKI_PAGE_TEMPLATE, page=page, content=content, current_page=page)
    
    @app.route('/history')
    def history():
        """View audit history"""
        return render_template_string(HISTORY_TEMPLATE, history=audit_history)
    
    return app


# ============================================================================
# HTML TEMPLATES - WITH PROPER SAFE FILTER FOR WIKI CONTENT
# ============================================================================

LANDING_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>GitHub Security Auditor</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1419; color: #e6edf3; line-height: 1.6; }
        header { background: #010409; border-bottom: 1px solid #30363d; padding: 20px 0; }
        .container { max-width: 1200px; margin: 0 auto; padding: 0 20px; }
        h1 { font-size: 2.5em; margin-bottom: 10px; color: #79c0ff; }
        .subtitle { font-size: 1.1em; color: #8b949e; margin-bottom: 40px; }
        .hero { padding: 60px 0; text-align: center; }
        .cta-button { display: inline-block; background: #238636; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-size: 1.1em; margin: 10px; transition: all 0.3s; }
        .cta-button:hover { background: #2ea043; transform: translateY(-2px); }
        .secondary { background: #1f6feb; }
        .secondary:hover { background: #388bfd; }
        .features { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 30px; margin: 60px 0; }
        .feature { background: #161b22; padding: 30px; border-radius: 8px; border: 1px solid #30363d; }
        .feature h3 { color: #79c0ff; margin-bottom: 15px; font-size: 1.3em; }
        .feature p { color: #8b949e; }
        .nav { display: flex; gap: 20px; margin-bottom: 40px; }
        .nav a { color: #79c0ff; text-decoration: none; padding: 8px 12px; border-radius: 4px; }
        .nav a:hover { background: #30363d; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 40px 0; }
        .stat-card { background: #161b22; padding: 20px; border-radius: 8px; border-left: 4px solid #238636; }
        .stat-number { font-size: 2em; font-weight: bold; color: #79c0ff; }
        .stat-label { color: #8b949e; font-size: 0.9em; margin-top: 5px; }
        footer { border-top: 1px solid #30363d; padding: 40px 0; margin-top: 80px; color: #8b949e; text-align: center; }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>GitHub Security Auditor</h1>
            <p class="subtitle">Comprehensive security audit tool with compliance framework mapping</p>
            <div class="nav">
                <a href="/">Home</a>
                <a href="/wiki">Documentation</a>
                <a href="/history">History</a>
            </div>
        </div>
    </header>
    
    <main class="container">
        <div class="hero">
            <h2 style="font-size: 2em; margin-bottom: 20px;">Security Audit in Minutes</h2>
            <p style="color: #8b949e; font-size: 1.1em; margin-bottom: 30px;">
                Audit your GitHub organization against 40 security controls mapped to SOC2, NIST, ISO27001, and CIS standards.
            </p>
            <a href="/start" class="cta-button">Start New Audit</a>
            <a href="/wiki/getting-started" class="cta-button secondary">Read Guide</a>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">21</div>
                <div class="stat-label">Security Controls</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">4</div>
                <div class="stat-label">Compliance Standards</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">100%</div>
                <div class="stat-label">Open Source</div>
            </div>
        </div>
        
        <div class="features">
            <div class="feature">
                <h3>Complete Coverage</h3>
                <p>Audit 40 security controls across organization and repository settings.</p>
            </div>
            <div class="feature">
                <h3>Standards-Based</h3>
                <p>Maps to SOC2, NIST, ISO27001, and CIS Controls.</p>
            </div>
            <div class="feature">
                <h3>Compliance Ready</h3>
                <p>Professional reports with gap analysis and recommendations.</p>
            </div>
            <div class="feature">
                <h3>Easy to Use</h3>
                <p>Web interface for audit configuration and report generation.</p>
            </div>
            <div class="feature">
                <h3>Track Progress</h3>
                <p>Maintain audit history and track security improvements.</p>
            </div>
            <div class="feature">
                <h3>Well Documented</h3>
                <p>Comprehensive wiki with detailed explanations.</p>
            </div>
        </div>
    </main>
    
    <footer>
        <div class="container">
            <p>GitHub Security Auditor v1.1</p>
        </div>
    </footer>
</body>
</html>
"""

START_AUDIT_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Start Audit - GitHub Security Auditor</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1419; color: #e6edf3; }
        header { background: #010409; border-bottom: 1px solid #30363d; padding: 20px 0; }
        .container { max-width: 800px; margin: 0 auto; padding: 20px; }
        h1 { color: #79c0ff; margin-bottom: 30px; }
        .nav { display: flex; gap: 15px; margin-bottom: 30px; }
        .nav a { color: #79c0ff; background: #0d1117; border: 1px solid #30363d; padding: 10px 15px; text-decoration: none; border-radius: 4px; }
        .nav a:hover { background: #161b22; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-weight: 600; color: #e6edf3; }
        input { width: 100%; padding: 10px; background: #0d1117; border: 1px solid #30363d; color: #e6edf3; border-radius: 4px; font-size: 1em; }
        input:focus { outline: none; border-color: #79c0ff; }
        button { background: #238636; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 1em; width: 100%; margin-top: 20px; }
        button:hover { background: #2ea043; }
        .info { background: #161b22; border-left: 4px solid #79c0ff; padding: 15px; margin-bottom: 20px; border-radius: 4px; }
        .error { background: #161b22; border-left: 4px solid #ef4444; padding: 15px; margin-bottom: 20px; border-radius: 4px; color: #f85149; display: none; }
        a { color: #79c0ff; }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Start New Audit</h1>
            <div class="nav">
                <a href="/">Home</a>
                <a href="/wiki">Docs</a>
                <a href="/history">History</a>
            </div>
        </div>
    </header>
    
    <main class="container">
        <div class="info">
            <p><strong>Need help?</strong> Check the <a href="/wiki/getting-started">Getting Started guide</a>.</p>
        </div>
        
        <div class="error" id="errorMsg"></div>
        
        <form id="auditForm">
            <div class="form-group">
                <label for="token">GitHub Personal Access Token</label>
                <input type="password" id="token" name="token" placeholder="ghp_xxxxxxxxxxxx" required>
                <p style="font-size: 0.9em; color: #8b949e; margin-top: 8px;">
                    <a href="https://github.com/settings/tokens?type=beta">Create a fine-grained token</a> with
                    <strong>read-only</strong> access to: Metadata, Administration, Contents,
                    Dependabot alerts, Secret scanning alerts. This tool never needs write access.
                </p>
            </div>
            
            <div class="form-group">
                <label for="account_type">What are you auditing?</label>
                <select id="account_type" name="account_type"
                        style="width: 100%; padding: 12px; background: #0d1117; color: #e6edf3;
                               border: 1px solid #30363d; border-radius: 6px; font-size: 1em;">
                    <option value="organization">Organization</option>
                    <option value="user">Personal account</option>
                    <option value="auto">Detect automatically</option>
                </select>
                <p style="font-size: 0.9em; color: #8b949e; margin-top: 8px;">
                    Nine of the 40 checks are organization settings and do not exist on a
                    personal account. Choosing correctly avoids findings that cannot apply
                    to you &mdash; see <a href="/wiki/applicability">what applies to your account</a>.
                </p>
            </div>

            <div class="form-group">
                <label for="standard">Report standard</label>
                <select id="standard" name="standard"
                        style="width: 100%; padding: 12px; background: #0d1117; color: #e6edf3;
                               border: 1px solid #30363d; border-radius: 6px; font-size: 1em;">
                    <option value="all">All standards</option>
                    <option value="soc2">SOC 2 Trust Services Criteria</option>
                    <option value="nist">NIST SP 800-53 Rev. 5</option>
                    <option value="iso27001">ISO/IEC 27001:2022</option>
                    <option value="cis">CIS Controls v8.1</option>
                </select>
                <p style="font-size: 0.9em; color: #8b949e; margin-top: 8px;">
                    Choosing one framework produces a report containing that framework
                    and no other, with the score computed over its control set. The
                    access inventory is included either way.
                </p>
            </div>

            <div class="form-group">
                <label for="org">Organization or username</label>
                <input type="text" id="org" name="org" placeholder="your-org or username" required>
                <p style="font-size: 0.9em; color: #8b949e; margin-top: 8px;">
                    The name exactly as it appears in your GitHub URL
                </p>
            </div>
            
            <button type="submit">Start Audit</button>
        </form>
    </main>
    
    <script>
        document.getElementById('auditForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const token = document.getElementById('token').value;
            const org = document.getElementById('org').value;
            const accountType = document.getElementById('account_type').value;
            const standard = document.getElementById('standard').value;
            try {
                const response = await fetch('/api/start-audit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ token, org, account_type: accountType, standard })
                });
                if (!response.ok) throw new Error('Failed to start audit');
                const data = await response.json();
                window.location.href = `/dashboard/${data.session_id}`;
            } catch (error) {
                document.getElementById('errorMsg').textContent = error.message;
                document.getElementById('errorMsg').style.display = 'block';
            }
        });
    </script>
</body>
</html>
"""

LOADING_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Audit Running...</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1419; color: #e6edf3; display: flex; align-items: center; justify-content: center; height: 100vh; }
        .loader { text-align: center; }
        h1 { margin-bottom: 30px; color: #79c0ff; }
        .spinner { border: 4px solid #30363d; border-top: 4px solid #79c0ff; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        p { color: #8b949e; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="loader">
        <h1>Running Audit...</h1>
        <div class="spinner"></div>
        <p>This may take a few minutes depending on the number of repositories.</p>
    </div>
    <script>
        const sessionId = '{{ session_id }}';
        const checkStatus = async () => {
            try {
                const response = await fetch(`/api/audit-status/${sessionId}`);
                const session = await response.json();
                if (session.status === 'completed') {
                    window.location.href = `/dashboard/${sessionId}`;
                } else if (session.status === 'error') {
                    window.location.href = `/error?msg=${encodeURIComponent(session.error)}`;
                } else {
                    setTimeout(checkStatus, 2000);
                }
            } catch (error) {
                setTimeout(checkStatus, 2000);
            }
        };
        setTimeout(checkStatus, 2000);
    </script>
</body>
</html>
"""

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Audit Results - GitHub Security Auditor</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1419; color: #e6edf3; }
        header { background: #010409; border-bottom: 1px solid #30363d; padding: 20px 0; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #79c0ff; margin-bottom: 30px; }
        .nav { display: flex; gap: 15px; margin-bottom: 30px; }
        .nav a { color: #79c0ff; background: #0d1117; border: 1px solid #30363d; padding: 10px 15px; text-decoration: none; border-radius: 4px; }
        .nav a:hover { background: #161b22; }
        .score-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 30px; text-align: center; margin-bottom: 30px; }
        .score-number { font-size: 3em; font-weight: bold; color: #79c0ff; }
        .score-label { color: #8b949e; margin-top: 10px; }
        .risk-high { color: #3fb950; }
        .risk-medium { color: #d29922; }
        .risk-low { color: #f85149; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .summary-item { background: #161b22; padding: 20px; border-radius: 8px; border-left: 4px solid #79c0ff; }
        .summary-item .number { font-size: 1.8em; font-weight: bold; color: #79c0ff; }
        .summary-item .label { color: #8b949e; font-size: 0.9em; margin-top: 8px; }
        .button-group { display: flex; gap: 10px; margin-top: 30px; }
        .btn { padding: 10px 20px; background: #238636; color: white; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn:hover { background: #2ea043; }
        .btn-secondary { background: #1f6feb; }
        .btn-secondary:hover { background: #388bfd; }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Audit Results</h1>
            <div class="nav">
                <a href="/">Home</a>
                <a href="/start">New Audit</a>
                <a href="/history">History</a>
                <a href="/wiki">Docs</a>
            </div>
        </div>
    </header>
    
    <main class="container">
        <div class="score-card">
            <div class="score-number">{{ results['summary']['compliance_score'] }}%</div>
            <div class="score-label">Overall Compliance Score</div>
            <div class="score-label" style="margin-top: 10px; font-size: 1.1em;">
                <span class="risk-{{ 'high' if results['summary']['compliance_score'] >= 90 else 'medium' if results['summary']['compliance_score'] >= 70 else 'low' }}">
                    {{ results['summary']['risk_level'] }}
                </span>
            </div>
        </div>
        
        <div class="summary">
            <div class="summary-item">
                <div class="number">{{ results['summary']['passed_checks'] }}</div>
                <div class="label">Checks Passed</div>
            </div>
            <div class="summary-item">
                <div class="number">{{ results['summary']['failed_checks'] }}</div>
                <div class="label">Checks Failed</div>
            </div>
            <div class="summary-item">
                <div class="number">{{ results['summary']['total_checks'] }}</div>
                <div class="label">Total Checks</div>
            </div>
            <div class="summary-item">
                <div class="number">{{ results['checks'].get('repositories', {})|length }}</div>
                <div class="label">Repositories</div>
            </div>
        </div>
        
        <h2 style="margin-bottom: 20px;">Generate Reports</h2>
        <div class="button-group">
            <a href="/api/report/{{ session_id }}/html" class="btn">Download HTML Report</a>
            <a href="/api/report/{{ session_id }}/json" class="btn btn-secondary">Download JSON Report</a>
            <a href="/wiki/interpreting-results" class="btn btn-secondary">How to Interpret</a>
        </div>
    </main>
</body>
</html>
"""

ERROR_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Error</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1419; color: #e6edf3; display: flex; align-items: center; justify-content: center; height: 100vh; }
        .error-box { background: #161b22; border: 1px solid #f85149; border-radius: 8px; padding: 30px; max-width: 500px; text-align: center; }
        h1 { color: #f85149; margin-bottom: 15px; }
        p { color: #8b949e; margin-bottom: 20px; }
        a { color: #79c0ff; }
    </style>
</head>
<body>
    <div class="error-box">
        <h1>Error</h1>
        <p>{{ error }}</p>
        <a href="/start">Try Again</a>
    </div>
</body>
</html>
"""

HISTORY_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Audit History</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1419; color: #e6edf3; }
        header { background: #010409; border-bottom: 1px solid #30363d; padding: 20px 0; }
        .container { max-width: 1000px; margin: 0 auto; padding: 20px; }
        h1 { color: #79c0ff; margin-bottom: 30px; }
        .nav { display: flex; gap: 15px; margin-bottom: 30px; }
        .nav a { color: #79c0ff; background: #0d1117; border: 1px solid #30363d; padding: 10px 15px; text-decoration: none; border-radius: 4px; }
        .nav a:hover { background: #161b22; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #161b22; padding: 15px; text-align: left; border-bottom: 2px solid #30363d; }
        td { padding: 12px 15px; border-bottom: 1px solid #30363d; }
        tr:hover { background: #0d1117; }
        .score-high { color: #3fb950; }
        .score-medium { color: #d29922; }
        .score-low { color: #f85149; }
        a { color: #79c0ff; }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Audit History</h1>
            <div class="nav">
                <a href="/">Home</a>
                <a href="/start">New Audit</a>
                <a href="/wiki">Docs</a>
            </div>
        </div>
    </header>
    
    <main class="container">
        {% if history %}
        <table>
            <thead>
                <tr>
                    <th>Organization</th>
                    <th>Timestamp</th>
                    <th>Score</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {% for id, audit in history.items() %}
                <tr>
                    <td>{{ audit['org'] }}</td>
                    <td>{{ audit['timestamp'] }}</td>
                    <td class="{% if audit['score'] >= 90 %}score-high{% elif audit['score'] >= 70 %}score-medium{% else %}score-low{% endif %}">{{ audit['score'] }}%</td>
                    <td><a href="/dashboard/{{ id }}">View</a></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <p>No audits run yet. <a href="/start">Start one now</a>.</p>
        {% endif %}
    </main>
</body>
</html>
"""

WIKI_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Documentation - GitHub Security Auditor</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1419; color: #e6edf3; }
        header { background: #010409; border-bottom: 1px solid #30363d; padding: 20px 0; }
        .container { max-width: 1000px; margin: 0 auto; padding: 20px; display: grid; grid-template-columns: 250px 1fr; gap: 20px; }
        h1 { color: #79c0ff; margin-bottom: 30px; grid-column: 1 / -1; }
        .sidebar { background: #161b22; padding: 20px; border-radius: 8px; border: 1px solid #30363d; height: fit-content; }
        .sidebar h3 { color: #79c0ff; margin-bottom: 15px; font-size: 0.9em; text-transform: uppercase; }
        .sidebar a { display: block; color: #79c0ff; text-decoration: none; padding: 8px 0; border-bottom: 1px solid #30363d; }
        .sidebar a:last-child { border-bottom: none; }
        .sidebar a:hover { color: #58a6ff; }
        .content { background: #161b22; padding: 30px; border-radius: 8px; border: 1px solid #30363d; }
        .content h2 { color: #79c0ff; margin: 30px 0 15px 0; }
        .content p { color: #8b949e; margin-bottom: 15px; }
    </style>
</head>
<body>
    <header>
        <div class="container" style="grid-column: 1 / -1;">
            <h1>Documentation</h1>
        </div>
    </header>
    
    <div class="container">
        <div class="sidebar">
            <h3>Documentation</h3>
            <a href="/wiki/getting-started" onclick="return navigateTo('/wiki/getting-started')">Getting Started</a>
            <a href="/wiki/organization-checks" onclick="return navigateTo('/wiki/organization-checks')">Organization Checks</a>
            <a href="/wiki/compliance-standards" onclick="return navigateTo('/wiki/compliance-standards')">Compliance Standards</a>
            <a href="/wiki/interpreting-results" onclick="return navigateTo('/wiki/interpreting-results')">Interpreting Results</a>
            <a href="/wiki/faq" onclick="return navigateTo('/wiki/faq')">FAQ</a>
        </div>
        
        <div class="content">
            <h2>Welcome to Documentation</h2>
            <p>Choose a topic from the left menu to get started.</p>
        </div>
    </div>
    
    <script>
        function navigateTo(url) {
            window.location.href = url;
            return false;
        }
    </script>
</body>
</html>
"""

WIKI_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>{{ page }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1419; color: #e6edf3; }
        header { background: #010409; border-bottom: 1px solid #30363d; padding: 20px 0; }
        .header-container { max-width: 1000px; margin: 0 auto; padding: 0 20px; }
        .header-content { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .header-content h1 { color: #79c0ff; font-size: 1.5em; }
        .nav-top { display: flex; gap: 15px; }
        .nav-top a { color: #79c0ff; background: #0d1117; border: 1px solid #30363d; padding: 8px 15px; text-decoration: none; border-radius: 4px; font-size: 0.95em; }
        .nav-top a:hover { background: #161b22; }
        .nav-top a.active { background: #238636; border-color: #3fb950; color: white; font-weight: 600; }
        .container { max-width: 1000px; margin: 0 auto; padding: 20px; display: grid; grid-template-columns: 250px 1fr; gap: 20px; }
        .sidebar { background: #161b22; padding: 20px; border-radius: 8px; border: 1px solid #30363d; height: fit-content; }
        .sidebar h3 { color: #79c0ff; margin-bottom: 15px; font-size: 0.9em; text-transform: uppercase; }
        .sidebar a { display: block; color: #79c0ff; text-decoration: none; padding: 8px 12px; border-left: 2px solid transparent; margin-bottom: 5px; border-radius: 4px; }
        .sidebar a:hover { background: #0d1117; }
        .sidebar a.active { background: #238636; border-left-color: #3fb950; color: white; font-weight: 600; }
        .content { background: #161b22; padding: 30px; border-radius: 8px; border: 1px solid #30363d; }
        .content h2 { color: #79c0ff; margin: 30px 0 15px 0; font-size: 1.5em; }
        .content h3 { color: #79c0ff; margin: 20px 0 10px 0; font-size: 1.2em; }
        .content h4 { color: #79c0ff; margin: 15px 0 8px 0; }
        .content p { color: #8b949e; margin-bottom: 15px; line-height: 1.6; }
        .content ul { margin-left: 20px; color: #8b949e; margin-bottom: 15px; }
        .content li { margin-bottom: 8px; }
        .content ol { margin-left: 20px; color: #8b949e; margin-bottom: 15px; }
        .content table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .content th { background: #0d1117; padding: 10px; border: 1px solid #30363d; text-align: left; color: #79c0ff; font-weight: 600; }
        .content td { padding: 10px; border: 1px solid #30363d; }
        code { background: #0d1117; padding: 2px 6px; border-radius: 3px; color: #79c0ff; font-family: monospace; font-size: 0.9em; }
        .control-box { background: #0d1117; border-left: 4px solid #238636; padding: 15px; margin: 15px 0; border-radius: 4px; }
        .control-box h4 { margin-top: 0; }
        .info-box { background: #0d1117; border-left: 4px solid #79c0ff; padding: 15px; margin: 15px 0; border-radius: 4px; }
        a { color: #58a6ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <header>
        <div class="header-container">
            <div class="header-content">
                <h1>Documentation</h1>
                <div class="nav-top">
                    <a href="/">Home</a>
                    <a href="/wiki" class="active">Docs</a>
                    <a href="/history">History</a>
                </div>
            </div>
        </div>
    </header>
    
    <div class="container">
        <div class="sidebar">
            <h3>Documentation</h3>
            <a href="/wiki/getting-started" data-page="getting-started" onclick="return navigateTo('/wiki/getting-started')" {% if current_page == 'getting-started' %}class="active"{% endif %}>Getting Started</a>
            <a href="/wiki/organization-checks" data-page="organization-checks" onclick="return navigateTo('/wiki/organization-checks')" {% if current_page == 'organization-checks' %}class="active"{% endif %}>Organization Checks</a>
            <a href="/wiki/compliance-standards" data-page="compliance-standards" onclick="return navigateTo('/wiki/compliance-standards')" {% if current_page == 'compliance-standards' %}class="active"{% endif %}>Compliance Standards</a>
            <a href="/wiki/applicability" data-page="applicability" onclick="return navigateTo('/wiki/applicability')" {% if current_page == 'applicability' %}class="active"{% endif %}>What Applies To You</a>
            <a href="/wiki/interpreting-results" data-page="interpreting-results" onclick="return navigateTo('/wiki/interpreting-results')" {% if current_page == 'interpreting-results' %}class="active"{% endif %}>Interpreting Results</a>
            <a href="/wiki/faq" data-page="faq" onclick="return navigateTo('/wiki/faq')" {% if current_page == 'faq' %}class="active"{% endif %}>FAQ</a>
        </div>
        
        <div class="content">
            {{ content | safe }}
        </div>
    </div>
    
    <script>
        function navigateTo(url) {
            window.location.href = url;
            return false;
        }
        
        // Highlight active page on load
        document.addEventListener('DOMContentLoaded', function() {
            const currentPage = '{{ current_page }}';
            const links = document.querySelectorAll('.sidebar a');
            links.forEach(link => {
                const page = link.getAttribute('data-page');
                if (page === currentPage) {
                    link.classList.add('active');
                } else {
                    link.classList.remove('active');
                }
            });
        });
    </script>
</body>
</html>
"""


if __name__ == '__main__':
    import os

    app = create_app()
    # debug=True exposes the Werkzeug console, which renders the local
    # variables of the failing frame - including the GitHub token.
    debug = os.getenv("AUDITOR_DEBUG") == "1"
    host = os.getenv("AUDITOR_HOST", "127.0.0.1")
    print(f"GitHub Security Auditor running on http://{host}:5000")
    app.run(host=host, port=5000, debug=debug)
