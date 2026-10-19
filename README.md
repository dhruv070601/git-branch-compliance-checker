# Git Branch Compliance Checker

A Python CLI that inspects GitHub branch protection, repository rulesets, and dependency vulnerability-alert settings through the GitHub REST API. It generates Markdown and JSON reports and can run in GitHub Actions. No third-party Python dependencies.

## Checks
- Default branch and repository metadata
- Required pull-request approvals and stale-review dismissal
- Code-owner reviews and required status checks
- Administrator enforcement, force-push and branch-deletion rules
- Visible repository rulesets
- Dependency vulnerability alerts
- Recommendations with PASS, WARN, INFO, or UNKNOWN statuses


## Run locally
Requires Python 3.10+ and internet access.
    python -m unittest discover -s tests -v

PowerShell: set a fine-grained token in the environment, then run:
    $env:GITHUB_TOKEN = "YOUR_FINE_GRAINED_TOKEN"
    python -m branch_audit.checker --repo OWNER/REPOSITORY --out-dir compliance-results

Never commit tokens or put them in source code. Use minimum read-only permissions needed to inspect repository administration/security settings.

## GitHub Actions
Tests run on pushes and pull requests. On pushes and manual dispatch, the workflow audits repository settings and uploads Markdown/JSON reports as artifacts. Manual dispatch accepts a target repository in OWNER/NAME format.

## Interpret results carefully
- UNKNOWN means the API could not verify a setting. GitHub may return 403/404 when the token lacks access; this is not proof that a control is disabled.
- Branch protection and rulesets may require repository administration read access.
- This is a configuration visibility checker, not a certification of security or compliance.