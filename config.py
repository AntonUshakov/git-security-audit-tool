"""
Configuration module
"""

import os
from typing import Optional


class Config:
    """Configuration class"""

    def __init__(
        self,
        github_token: Optional[str] = None,
        org_name: Optional[str] = None,
        account_type: str = "auto"
    ):
        """Initialize configuration"""
        self.github_token = github_token or os.getenv("GITHUB_TOKEN")
        self.org_name = org_name or os.getenv("GITHUB_ORG")

        # Which kind of account is being audited. Eight of the checks exist
        # only on organizations, so the answer changes what can be scored at
        # all - see APPLICABILITY.md.
        account_type = (account_type or "auto").lower()
        if account_type not in ("auto", "organization", "user"):
            raise ValueError(
                f"Unknown account type {account_type!r}. "
                "Expected 'auto', 'organization' or 'user'."
            )
        self.account_type = account_type

        if not self.github_token:
            raise ValueError(
                "GitHub token not provided. "
                "Set GITHUB_TOKEN environment variable or pass --token"
            )

        if not self.org_name:
            raise ValueError(
                "Organization name not provided. "
                "Set GITHUB_ORG environment variable or pass --org"
            )

        self.api_url = "https://api.github.com"
        self.timeout = 30

    def __repr__(self) -> str:
        return f"<Config org={self.org_name} account_type={self.account_type}>"
