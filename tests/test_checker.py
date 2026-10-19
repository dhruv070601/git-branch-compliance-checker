import unittest
from branch_audit.checker import audit_repository, render_markdown
class FakeAPI:
    def __init__(self, responses): self.responses = responses
    def get(self, path): return self.responses.get(path, (404, {'message':'Not found'}))
class CheckerTests(unittest.TestCase):
    def test_protected_branch_reports_checks(self):
        responses = {'/repos/acme/demo':(200,{'default_branch':'main','private':False}),
          '/repos/acme/demo/branches/main/protection':(200,{'required_pull_request_reviews':{'required_approving_review_count':2,'dismiss_stale_reviews':True,'require_code_owner_reviews':True},'required_status_checks':{'strict':True,'contexts':['test','lint']},'enforce_admins':{'enabled':True},'allow_force_pushes':{'enabled':False},'allow_deletions':{'enabled':False}}),
          '/repos/acme/demo/rulesets?includes_parents=true':(200,[{'enforcement':'active'}]), '/repos/acme/demo/vulnerability-alerts':(204,{})}
        report=audit_repository('acme','demo',api=FakeAPI(responses))
        self.assertEqual(report['default_branch'],'main')
        self.assertTrue(any(x['check']=='Required status checks' and x['status']=='PASS' for x in report['findings']))
        self.assertTrue(any(x['check']=='Administrator enforcement' and x['status']=='PASS' for x in report['findings']))
    def test_api_permission_failure_is_unknown(self):
        responses={'/repos/acme/demo':(200,{'default_branch':'main','private':False}),'/repos/acme/demo/branches/main/protection':(404,{}),'/repos/acme/demo/rulesets?includes_parents=true':(403,{}),'/repos/acme/demo/vulnerability-alerts':(403,{})}
        report=audit_repository('acme','demo',api=FakeAPI(responses))
        self.assertTrue(all(x['status']=='UNKNOWN' for x in report['findings'] if x['check'] in ('Branch protection','Repository rulesets','Dependency vulnerability alerts')))
    def test_markdown_output(self):
        report={'repository':'acme/demo','default_branch':'main','summary':{'PASS':1,'WARN':0,'UNKNOWN':0,'INFO':0},'findings':[{'status':'PASS','check':'Required status checks','detail':'2 checks','recommendation':'Keep CI required.'}]}
        text=render_markdown(report); self.assertIn('# Git Branch Compliance Report',text); self.assertIn('UNKNOWN means',text)
if __name__=='__main__': unittest.main()