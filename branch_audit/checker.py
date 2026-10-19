"""Inspect GitHub repository branch protection and governance settings."""
import argparse, json, os, sys, urllib.error, urllib.parse, urllib.request
from pathlib import Path
API_ROOT = "https://api.github.com"
class GitHubAPI:
    def __init__(self, token=None, api_root=API_ROOT): self.token, self.api_root = token, api_root.rstrip("/")
    def get(self, path):
        headers = {"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","User-Agent":"git-branch-compliance-checker"}
        if self.token: headers["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request(self.api_root + path, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as res: return res.status, json.loads(res.read().decode("utf-8")) if res.status != 204 else {}
        except urllib.error.HTTPError as exc:
            try: body = json.loads(exc.read().decode("utf-8"))
            except Exception: body = {}
            return exc.code, body
def audit_repository(owner, repo, token=None, api=None):
    api = api or GitHubAPI(token); name = owner + "/" + repo; findings = []
    def add(status, check, detail, recommendation): findings.append({"status":status,"check":check,"detail":detail,"recommendation":recommendation})
    code, meta = api.get("/repos/" + owner + "/" + repo)
    if code != 200: raise RuntimeError("Could not read repository: HTTP " + str(code) + " " + str(meta.get("message","")))
    branch = meta.get("default_branch","")
    add("INFO","Repository metadata",name + " is " + ("private" if meta.get("private") else "public") + "; default branch: " + (branch or "(not set)") + ".","Keep the default branch intentional and document your release strategy.")
    if meta.get("archived"): add("WARN","Repository archived","GitHub marks this repository archived.","Confirm read-only status is intentional.")
    if branch:
        code, protection = api.get("/repos/" + owner + "/" + repo + "/branches/" + urllib.parse.quote(branch,safe="") + "/protection")
        if code == 200:
            reviews = protection.get("required_pull_request_reviews") or {}; checks = protection.get("required_status_checks") or {}
            contexts = checks.get("contexts") or checks.get("checks") or []
            required = reviews.get("required_approving_review_count",0)
            add("PASS" if reviews and required >= 1 else "WARN","Pull request reviews","Required approving reviews: " + str(required) + ".","Require at least one independent approval on important branches.")
            add("PASS" if reviews.get("dismiss_stale_reviews") else "WARN","Stale approvals","Stale approvals are dismissed." if reviews.get("dismiss_stale_reviews") else "Stale-review dismissal is not enabled in this response.","Dismiss approvals after new commits.")
            add("PASS" if reviews.get("require_code_owner_reviews") else "WARN","Code-owner reviews","Code-owner approval is required." if reviews.get("require_code_owner_reviews") else "Code-owner approval is not required.","Require CODEOWNERS review for critical paths where practical.")
            add("PASS" if contexts else "WARN","Required status checks",str(len(contexts)) + " required status check(s) configured.","Require passing CI tests and security checks before merging.")
            add("PASS" if checks.get("strict") else "WARN","Branch up to date","Required checks require the branch to be up to date." if checks.get("strict") else "Strict up-to-date checks are not enabled.","Consider requiring branches to be current with the base branch.")
            add("PASS" if protection.get("enforce_admins",{}).get("enabled") else "WARN","Administrator enforcement","Protection applies to administrators." if protection.get("enforce_admins",{}).get("enabled") else "Administrators may bypass protection.","Enable administrator enforcement unless there is a documented exception.")
            add("WARN" if protection.get("allow_force_pushes",{}).get("enabled") else "PASS","Force pushes","Force pushes are allowed." if protection.get("allow_force_pushes",{}).get("enabled") else "Force pushes are restricted.","Disable force pushes on shared release branches.")
            add("WARN" if protection.get("allow_deletions",{}).get("enabled") else "PASS","Branch deletion","Deletion is allowed." if protection.get("allow_deletions",{}).get("enabled") else "Deletion is restricted.","Prevent deletion of important branches.")
        elif code in (403,404): add("UNKNOWN","Branch protection","HTTP " + str(code) + ": protection may be absent or token access may be insufficient.","Run with a token that can read repository administration settings.")
        else: add("UNKNOWN","Branch protection","GitHub returned HTTP " + str(code) + ".","Check API access and repository permissions.")
    code, rules = api.get("/repos/" + owner + "/" + repo + "/rulesets?includes_parents=true")
    if code == 200 and isinstance(rules,list):
        active = [x for x in rules if x.get("enforcement") == "active"]
        add("PASS" if active else "WARN","Repository rulesets",str(len(active)) + " active ruleset(s) visible; " + str(len(rules)) + " total.","Use rulesets to standardize branch policies.")
    elif code in (403,404): add("UNKNOWN","Repository rulesets","Rulesets not visible (HTTP " + str(code) + "); this does not prove none exist.","Use a token with repository administration read access.")
    else: add("UNKNOWN","Repository rulesets","GitHub returned HTTP " + str(code) + ".","Check API access and permissions.")
    code, alerts = api.get("/repos/" + owner + "/" + repo + "/vulnerability-alerts")
    if code == 204: add("PASS","Dependency vulnerability alerts","GitHub reports vulnerability alerts enabled.","Keep dependency alerts enabled and review them promptly.")
    elif code == 404: add("UNKNOWN","Dependency vulnerability alerts","Alerts may be disabled or token access may be insufficient.","Verify Dependabot alerts in repository Settings > Security.")
    else: add("UNKNOWN","Dependency vulnerability alerts","Setting not readable (HTTP " + str(code) + ").","Check token permissions and repository security settings.")
    summary = {s:sum(1 for x in findings if x["status"]==s) for s in ("PASS","WARN","UNKNOWN","INFO")}
    return {"repository":name,"default_branch":branch,"finding_count":len(findings),"summary":summary,"findings":findings}
def render_markdown(report):
    lines = ["# Git Branch Compliance Report","","- **Repository:** `" + report["repository"] + "`","- **Default branch:** `" + report["default_branch"] + "`","","## Summary","","| Status | Count |","|---|---:|"]
    for status,count in report["summary"].items(): lines.append("| " + status + " | " + str(count) + " |")
    lines += ["","","## Checks",""]
    for x in report["findings"]: lines += ["### ["+x["status"]+"] "+x["check"],"",x["detail"],"","**Recommendation:** "+x["recommendation"],""]
    lines += ["---","_UNKNOWN means the API could not verify a setting; it does not prove the control is disabled._",""]
    return "\n".join(lines)
def main():
    parser=argparse.ArgumentParser(description="Audit GitHub branch protection and repository governance.")
    parser.add_argument("--repo",required=True,help="OWNER/NAME"); parser.add_argument("--out-dir",default="compliance-results"); args=parser.parse_args()
    parts=args.repo.split("/",1)
    if len(parts)!=2 or not all(parts): parser.error("--repo must be OWNER/NAME")
    try: report=audit_repository(parts[0],parts[1],os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"))
    except (RuntimeError,ValueError) as exc: print("Audit failed: "+str(exc),file=sys.stderr); return 2
    out=Path(args.out_dir); out.mkdir(parents=True,exist_ok=True)
    (out/"compliance-report.md").write_text(render_markdown(report),encoding="utf-8")
    (out/"compliance-report.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    print(render_markdown(report)); print("Reports saved to "+str(out.resolve())); return 0
if __name__=="__main__": raise SystemExit(main())