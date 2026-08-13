"""
Access review — who can do what, and where an auditor will push back.

This module produces two things that serve different readers:

1. An **inventory**: every principal (user, team, outside collaborator) with
   access to each repository and the permission level they hold. This is the
   evidence an access review is actually conducted against. It is descriptive
   and is never scored.

2. **Findings**: the specific patterns an auditor challenges. Excessive
   permission is rarely a single misconfiguration — it is a shape, such as
   direct grants that bypass team-based review, or an external party holding
   push access. Findings flow through the same four-state model as every
   other check.

The distinction matters. A tool that only emits a score tells an auditor
nothing they can test. A tool that emits a roster lets them sample it.
"""

from typing import Any, Dict, Optional

from checks import _from_exception, fail, not_applicable, ok, unknown

#: Ordered least to most privileged. GitHub's own ordering.
PERMISSION_ORDER = ("pull", "triage", "push", "maintain", "admin")

#: Levels that let a principal change code or settings without review.
ELEVATED = ("push", "maintain", "admin")

#: Human-readable names. GitHub's API and UI disagree, so both are recorded.
PERMISSION_LABELS = {
    "pull": "Read",
    "triage": "Triage",
    "push": "Write",
    "maintain": "Maintain",
    "admin": "Admin",
}

#: GitHub uses two vocabularies for the same levels. The collaborators endpoint
#: returns push/pull; get_collaborator_permission returns write/read. Mapping
#: one to the other explicitly avoids a read-only user being silently bucketed
#: as something else by a dictionary lookup that misses.
PERMISSION_ALIASES = {
    "read": "pull",
    "write": "push",
    "none": None,
}

#: What each level actually permits. This is the column an access reviewer
#: reads: "Admin" means little without knowing it can delete the repository.
CAPABILITIES = {
    "pull":     {"push": False, "merge": False, "settings": False, "delete": False, "risk": "Minimal"},
    "triage":   {"push": False, "merge": False, "settings": False, "delete": False, "risk": "Low"},
    "push":     {"push": True,  "merge": True,  "settings": False, "delete": False, "risk": "Medium"},
    "maintain": {"push": True,  "merge": True,  "settings": True,  "delete": False, "risk": "High"},
    "admin":    {"push": True,  "merge": True,  "settings": True,  "delete": True,  "risk": "Critical"},
}


def normalise_permission(value):
    """Accept either GitHub vocabulary and return the canonical level."""
    if value is None:
        return None
    value = str(value).lower()
    if value in PERMISSION_ALIASES:
        return PERMISSION_ALIASES[value]
    return value if value in PERMISSION_ORDER else None


def capabilities_for(level):
    return CAPABILITIES.get(level, CAPABILITIES["pull"])


def highest_permission(permissions) -> Optional[str]:
    """Reduce a Permissions object to its highest granted level."""
    if permissions is None:
        return None
    for level in reversed(PERMISSION_ORDER):
        if getattr(permissions, level, False):
            return level
    return None


class AccessReview:
    """Builds the access inventory and the findings drawn from it."""

    #: An auditor asks about a repository with many administrators long before
    #: they ask about one with two. Three is a common threshold for a small
    #: team; it is reported, not enforced.
    ADMIN_COUNT_THRESHOLD = 3

    #: A single organization owner is a continuity risk; a large number is a
    #: standing-privilege risk. Auditors raise both.
    OWNER_COUNT_MIN = 2
    OWNER_COUNT_MAX = 5

    def __init__(self, org, is_organization: bool = True):
        self.org = org
        self.is_organization = is_organization
        self._outside_logins: Optional[set] = None

    # ------------------------------------------------------------------
    # Inventory
    # ------------------------------------------------------------------

    def _outside_collaborator_logins(self) -> Optional[set]:
        """Cached set of organization-wide outside collaborators."""
        if self._outside_logins is not None:
            return self._outside_logins
        if not self.is_organization:
            self._outside_logins = set()
            return self._outside_logins
        try:
            self._outside_logins = {
                user.login for user in self.org.get_outside_collaborators()
            }
        except Exception:
            self._outside_logins = None
        return self._outside_logins

    def repository_inventory(self, repo) -> Dict[str, Any]:
        """
        Every principal with access to one repository.

        Direct and team-derived access are distinguished, because that
        distinction is the whole basis of a team-based access review: a direct
        grant does not appear in any team roster and so escapes the review.
        """
        inventory: Dict[str, Any] = {
            "principals": [],
            "readable": True,
            "error": None,
        }

        outside = self._outside_collaborator_logins()

        try:
            direct_logins = {
                user.login for user in repo.get_collaborators(affiliation="direct")
            }
        except Exception as exc:
            inventory["readable"] = False
            inventory["error"] = _from_exception(exc, "Collaborators")["message"]
            return inventory

        try:
            collaborators = list(repo.get_collaborators())
        except Exception as exc:
            inventory["readable"] = False
            inventory["error"] = _from_exception(exc, "Collaborators")["message"]
            return inventory

        for user in collaborators:
            login = getattr(user, "login", None)
            if login is None:
                continue
            level = highest_permission(getattr(user, "permissions", None))
            if login in (outside or set()):
                affiliation = "outside collaborator"
            elif login in direct_logins:
                affiliation = "direct"
            else:
                affiliation = "via team or organization"

            inventory["principals"].append({
                "name": login,
                "kind": "user",
                "account_type": getattr(user, "type", "User"),
                "affiliation": affiliation,
                "permission": level,
                "permission_label": PERMISSION_LABELS.get(level, "unknown"),
                "capabilities": capabilities_for(level),
            })

        try:
            for team in repo.get_teams():
                permission = getattr(team, "permission", None)
                permission = normalise_permission(permission)
                inventory["principals"].append({
                    "name": getattr(team, "slug", None) or getattr(team, "name", "team"),
                    "kind": "team",
                    "account_type": "Team",
                    "affiliation": "team grant",
                    "permission": permission,
                    "permission_label": PERMISSION_LABELS.get(permission, "unknown"),
                    "capabilities": capabilities_for(permission),
                })
        except Exception:
            pass  # teams are unavailable on personal accounts

        inventory["principals"].sort(
            key=lambda p: (
                -PERMISSION_ORDER.index(p["permission"])
                if p["permission"] in PERMISSION_ORDER else 0,
                p["name"].lower(),
            )
        )
        return inventory

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def check_direct_grants(self, inventory) -> Dict[str, Any]:
        """
        Direct user grants on a repository owned by an organization.

        An access review is normally conducted against team membership. A
        permission granted directly to a user appears in no team roster, so it
        survives every review that samples teams — which is precisely why an
        auditor looks for it first.
        """
        if not inventory["readable"]:
            return unknown(inventory["error"] or "Collaborators are not readable")
        if not self.is_organization:
            return not_applicable(
                "Team-based access review does not apply to a personal account"
            )

        direct = [
            p for p in inventory["principals"]
            if p["kind"] == "user" and p["affiliation"] == "direct"
        ]
        if not direct:
            return ok("All access is granted through teams or organization membership")

        elevated = [p for p in direct if p["permission"] in ELEVATED]
        if elevated:
            names = ", ".join(
                f"{p['name']} ({p['permission_label']})" for p in elevated[:4]
            )
            return fail(
                f"{len(elevated)} user(s) hold elevated permission granted directly "
                f"rather than through a team: {names}. Direct grants appear in no "
                "team roster, so a team-based access review will not surface them"
            )
        return fail(
            f"{len(direct)} user(s) hold read access granted directly rather than "
            "through a team. Low risk, but outside the scope of a team-based review"
        )

    def check_outside_collaborators(self, repo, inventory) -> Dict[str, Any]:
        """External parties with access, and what level they hold."""
        if not inventory["readable"]:
            return unknown(inventory["error"] or "Collaborators are not readable")
        if self._outside_collaborator_logins() is None:
            return unknown(
                "Outside collaborators are only listable by an organization owner"
            )

        outside = [
            p for p in inventory["principals"]
            if p["affiliation"] == "outside collaborator"
        ]
        if not outside:
            return ok("No outside collaborators have access")

        elevated = [p for p in outside if p["permission"] in ELEVATED]
        private = bool(getattr(repo, "private", False))

        if elevated:
            names = ", ".join(
                f"{p['name']} ({p['permission_label']})" for p in elevated[:4]
            )
            scope = "private" if private else "public"
            return fail(
                f"{len(elevated)} outside collaborator(s) hold write or higher on this "
                f"{scope} repository: {names}. External parties with push access are "
                "the first thing an access review challenges — confirm each is still "
                "engaged and still needs this level"
            )
        return fail(
            f"{len(outside)} outside collaborator(s) hold read access. Not elevated, "
            "but each is an external party with standing access that should carry an "
            "expiry or a documented business reason"
        )

    def check_admin_concentration(self, inventory) -> Dict[str, Any]:
        """How many principals can change repository settings."""
        if not inventory["readable"]:
            return unknown(inventory["error"] or "Collaborators are not readable")

        admins = [p for p in inventory["principals"] if p["permission"] == "admin"]
        users = [p for p in admins if p["kind"] == "user"]
        teams = [p for p in admins if p["kind"] == "team"]

        if not admins:
            return ok("No collaborator or team holds repository admin")

        if len(users) > self.ADMIN_COUNT_THRESHOLD:
            shown = users[:5]
            names = ", ".join(p["name"] for p in shown)
            if len(users) > len(shown):
                names += ", ..."
            return fail(
                f"{len(users)} users hold repository admin ({names}). Admin can "
                "disable branch protection, rotate secrets and delete the repository. "
                "An auditor will ask why each needs it rather than Maintain"
            )
        if teams:
            return fail(
                f"{len(teams)} team(s) hold admin on this repository "
                f"({', '.join(p['name'] for p in teams[:3])}). Team-level admin grants "
                "settings control to every current and future member of that team"
            )
        return ok(
            f"{len(users)} user(s) hold repository admin, within a reviewable number"
        )

    def check_owner_count(self) -> Dict[str, Any]:
        """Organization owners hold standing privilege over everything."""
        if not self.is_organization:
            return not_applicable(
                "Organization ownership does not apply to a personal account"
            )
        try:
            owners = [user.login for user in self.org.get_members(role="admin")]
        except Exception as exc:
            return _from_exception(exc, "Organization owners")

        count = len(owners)
        if count == 0:
            return unknown("No organization owners were returned")
        if count < self.OWNER_COUNT_MIN:
            return fail(
                f"Only {count} organization owner ({owners[0]}). A single owner is a "
                "continuity risk: losing that account locks out billing, membership "
                "and security settings. Auditors raise this as an availability finding"
            )
        if count > self.OWNER_COUNT_MAX:
            return fail(
                f"{count} organization owners. Ownership carries standing privilege "
                "over every repository, secret and setting — an auditor will ask for "
                "a justification per owner and expect most to be Members instead"
            )
        return ok(f"{count} organization owners, within a defensible range")
