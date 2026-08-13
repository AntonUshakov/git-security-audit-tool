"""
Single source of truth for the tool's version.

Read this everywhere a version needs to be shown - the CLI banner, the web
footer, and the JSON report - rather than writing the string a second time.
A literal copied into a template is exactly how "v1.1" survived nine engine
rewrites in the footer while CHANGELOG.md moved to 1.10.1.
"""

__version__ = "1.19.0"


def version_string() -> str:
    return f"GitHub Security Auditor v{__version__}"
