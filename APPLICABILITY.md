# What applies to your account

Not every check can run against every GitHub account. Some controls exist only
on organizations, some only on paid plans, and some need repository admin on the
token. A check that cannot apply is reported `not_applicable` and **excluded
from the score** — it is not counted as a failure.

This is why the report shows a **coverage** figure next to the score. A 60%
score over 29 scored checks is a different statement from 60% over all 36, and
you should read the coverage line before the score.

**Select your account type on the start screen.** Choosing "Organization" for a
personal account produces eight findings that cannot apply to you; choosing
"Personal account" for an organization silently drops eight real ones.

---

## Result states

| State | Meaning | In the score |
|---|---|---|
| `pass` | Control is configured | yes |
| `fail` | Control is missing or misconfigured | yes |
| `unknown` | Could not determine — token permission, plan add-on, or an API field this version does not recognise | **no** |
| `not_applicable` | Cannot apply here — wrong account type, plan restriction, or a prerequisite already reported | **no** |

`unknown` and `not_applicable` are deliberately distinct. The first means *we
could not find out*; the second means *there is nothing to find out*. Collapsing
them would hide real gaps in what the tool can see.

---

## Organization-level checks (8)

None of these exist on a personal account. There is no membership policy, no
default repository permission, and no organization Actions policy to read.

| Check | Personal | Organization (Free) | Team | Enterprise Cloud |
|---|---|---|---|---|
| 2FA Enforcement | n/a | ✅ | ✅ | ✅ |
| SSO Configuration | n/a | n/a (free plan) | ⚠️ not implemented | ⚠️ not implemented |
| Default Repository Permission | n/a | ✅ | ✅ | ✅ |
| Member Repository Creation | n/a | ✅ | ✅ | ✅ |
| Audit Logging | n/a | n/a (Enterprise only) | n/a | ⚠️ not implemented |
| Actions Allowed Actions Policy | n/a | ✅ | ✅ | ✅ |
| Actions Default Token Permissions | n/a | ✅ | ✅ | ✅ |
| Actions Pull Request Approval | n/a | ✅ | ✅ | ✅ |

All eight require **organization owner** access on the token. With read-only
member access they return `unknown`.

⚠️ **SSO and Audit Logging are honest placeholders.** SAML status is not exposed
by the REST API, and the audit log endpoint is absent from PyGithub. Both always
return `unknown` with an explanation. An Enterprise Cloud customer gains nothing
from these two today.

---

## Single-standard reports

Choose a framework on the start screen, or `--standard soc2|nist|iso27001|cis`.

A single-standard report contains **that framework and no other**. The
introduction, the control mappings, the gap analysis and the score all describe
one control set. A SOC 2 report that also scores NIST forces the reader to work
out which number applies to them, with the wrong one on the same page.

Scope is derived from the compliance mapping rather than a second hand-kept
list, so renaming a check cannot leave the two out of step. Today every check
maps to all four frameworks, so choosing one does not reduce the number of
checks run — it changes what the report says about them. If a future check maps
to only some frameworks, it will drop out of the others automatically.

`--standard all` (the default) keeps all four, as before.

The access inventory is included in every report regardless of the standard
selected. Access review is evidence for all four frameworks.

---

## Access review (4 checks + inventory)

An access review is the evidence auditors ask for first, and it is the one part
of this report that names people.

| Item | Personal | Organization | Requires |
|---|---|---|---|
| Access inventory (unscored) | partial | ✅ | repository read |
| Organization Owner Count | n/a | ✅ | organization owner |
| Direct Collaborator Grants | n/a | ✅ | repository admin |
| Outside Collaborator Access | n/a | ✅ | organization owner |
| Repository Admin Concentration | ✅ | ✅ | repository admin |

`Direct Collaborator Grants` compares direct user grants against team-derived
access, which has no meaning on a personal account — there are no teams to
review against. `Outside Collaborator Access` needs the organization-wide
outside collaborator list to classify a principal as external.

**The inventory is deliberately unscored.** A score gives an auditor a
conclusion; a roster lets them sample and reach their own. It lists every
principal per repository with the permission held, and flags the three patterns
that draw questions: a grant made directly to a user rather than through a team
(invisible to a team-based review), an external party holding standing access,
and admin permission (which permits disabling branch protection, rotating
secrets and deleting the repository).

⚠️ **The report now contains usernames.** It holds personal data and should be
stored and shared accordingly. See PRIVACY.md.

---

## Repository-level checks (31)

### Always available

Independent of account type and plan. Need only read access.

| Check | Notes |
|---|---|
| Repository Visibility | |
| SECURITY.md File | |
| CODEOWNERS File | |
| .gitignore Configuration | |
| Repository Activity | Flags no push in 365 days |
| Action Version Pinning | Reads workflow files |
| Workflow Permissions Declared | Reads workflow files |
| Untrusted Workflow Triggers | Reads workflow files |
| Self-Hosted Runner Exposure | Reads workflow files |
| Build Provenance Attestation | `not_applicable` if nothing is published |
| Dependency Scanning | |

The five workflow-file checks return `not_applicable` when a repository has no
`.github/workflows/`. Not using Actions is not a security failure.

### Branch protection — the plan matters most here

Eleven checks depend on branch protection or a ruleset:

- Branch Protection Rules
- Pull Request Reviews
- Status Checks Before Merge
- Commit Signing
- Dismiss Stale PR Reviews
- Code Owner Reviews
- Admin Bypass Prevention
- Linear History Required
- Force Push Protection
- Branch Deletion Protection
- Ruleset Enforcement Status

| Repository | Personal (any plan) | Organization Free | Team / Enterprise |
|---|---|---|---|
| Public | ✅ enforced | ✅ enforced | ✅ enforced |
| Private | ⚠️ not established | ❌ not enforced | ✅ enforced |

GitHub shows this directly when you open Settings → Rules on a private
repository under a free plan:

> Your rulesets won't be enforced on this private repository until you upgrade
> this organization account to GitHub Team.

When protection is not enforceable, the eleven checks report `not_applicable`
rather than failing — you cannot be marked down for a feature the plan does not
provide. The finding still names the remediation: upgrade to Team, or make the
repository public.

For a **personal** private repository the tool reports `unknown` rather than
assuming either way. GitHub's banner names a Team *organization* as the
requirement, so a paid personal plan is not established to lift the restriction.

**One missing setting produces one finding.** If the default branch has no
protection, only *Branch Protection Rules* fails; the other ten report
`not_applicable` and point back at it. Otherwise a single setting would account
for a third of the score.

### Secret scanning — needs a paid add-on on private repositories

| Check | Public repository | Private repository |
|---|---|---|
| Secrets Scanning | ✅ | needs GitHub Secret Protection |
| Push Protection | ✅ | needs GitHub Secret Protection |

Without the add-on the `security_and_analysis` block is absent from the API
response and both report `unknown`. This is indistinguishable from a token
without repository admin — if you see `unknown` here, check both.

### Actions settings — need repository admin

| Check | Requirement |
|---|---|
| Workflow Token Permissions | repository admin |
| Repository Actions Policy | repository admin |
| Action SHA Pinning Policy | repository admin |
| Fork Pull Request Workflows | repository admin |

`Fork Pull Request Workflows` grades a different control depending on
visibility. A private repository chooses whether fork workflows run at all; a
public one chooses which contributors need approval first.

⚠️ This check currently returns `unknown` in practice — the API field names for
the fork policy have not been confirmed and the candidate list has not matched a
live response. See `_FORK_WORKFLOW_KEYS` in `checks.py`.

---

## Measured coverage

Scored checks out of 64, for one public and one private repository:

| Target | Scored | Coverage |
|---|---|---|
| Personal account, free | 25 | 39% |
| Personal account, paid | 26 | 41% |
| Organization, free | 28 | 44% |
| Organization, Team | 29 | 45% |

Coverage below 100% is normal and expected. GitHub places a large share of these
controls behind paid tiers and admin permissions, and the tool reports what it
can actually see rather than guessing at the rest.

To raise your own coverage:

1. Grant the token **organization owner** access — unlocks all eight
   organization checks.
2. Grant **repository admin** — unlocks the four Actions settings checks, the
   secret scanning pair, and the rulesets listing.
3. Move private repositories to a **Team** organization — brings the eleven
   branch protection checks into scope.

---

## Token permissions

A fine-grained personal access token with **read-only** access to: Metadata,
Administration, Contents, Dependabot alerts, Secret scanning alerts. The tool
never writes anything and never needs write scopes.

If you use a classic token, `read:org` covers the organization checks. Do not
grant `repo` — it confers full write access to every repository, which a
read-only auditor has no use for.
