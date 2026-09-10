import json
import hashlib
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
CLI=ROOT/"remote-agent"
class ScaffoldTests(unittest.TestCase):
    def run_cli(self,*args,cwd=None):
        return subprocess.run([str(CLI),*args],cwd=cwd or ROOT,text=True,capture_output=True)

    def fresh_repository(self, parent):
        repo=Path(parent)/"repo"
        shutil.copytree(ROOT,repo,ignore=shutil.ignore_patterns(".git",".remote-agent","*.db","*.csv","*.out","evidence.json","captured.json","remote-agent.json","compiled-policy.json","policy-explain.json","why.json","restore-receipt.json","drill-receipt.json","tampered-*.json",".remote-agent-job-ids.json"))
        subprocess.run(["git","init","-q"],cwd=repo,check=True)
        subprocess.run(["git","config","user.name","Remote Agent Tests"],cwd=repo,check=True)
        subprocess.run(["git","config","user.email","tests@invalid"],cwd=repo,check=True)
        subprocess.run(["git","add","."],cwd=repo,check=True)
        subprocess.run(["git","commit","-qm","fixture baseline"],cwd=repo,check=True)
        initialized=subprocess.run([str(repo/"remote-agent"),"init","."],cwd=repo,text=True,capture_output=True)
        self.assertEqual(initialized.returncode,0,initialized.stderr)
        job=repo/"remote-job.md"
        job.write_text(job.read_text().replace("acceptance_commands:\n  - format\n  - unit\n  - type","acceptance_commands:\n  - format\n  - type"))
        return repo

    def test_init_refuses_conflicts_before_writing(self):
        with tempfile.TemporaryDirectory() as td:
            repo=Path(td)/"repo"
            (repo/"ci").mkdir(parents=True)
            sentinel=repo/"ci/unit-test"
            sentinel.write_text("sentinel-do-not-replace\n")
            subprocess.run(["git","init","-q"],cwd=repo,check=True)
            subprocess.run(["git","config","user.name","Remote Agent Tests"],cwd=repo,check=True)
            subprocess.run(["git","config","user.email","tests@invalid"],cwd=repo,check=True)
            subprocess.run(["git","add","."],cwd=repo,check=True)
            subprocess.run(["git","commit","-qm","fixture baseline"],cwd=repo,check=True)
            before=sentinel.read_bytes()
            result=self.run_cli("init",str(repo),cwd=td)
            self.assertEqual(result.returncode,2,result.stdout+result.stderr)
            self.assertIn("init would replace existing paths: ci/unit-test",result.stderr)
            self.assertEqual(sentinel.read_bytes(),before)
            self.assertFalse((repo/"remote-agent").exists())
            self.assertFalse((repo/"agent.db").exists())

    def test_init_rerun_preserves_contract_and_hides_local_state(self):
        with tempfile.TemporaryDirectory() as td:
            repo=Path(td)/"repo"
            repo.mkdir()
            subprocess.run(["git","init","-q"],cwd=repo,check=True)
            subprocess.run(["git","config","user.name","Remote Agent Tests"],cwd=repo,check=True)
            subprocess.run(["git","config","user.email","tests@invalid"],cwd=repo,check=True)
            (repo/"README.md").write_text("# fixture\n")
            subprocess.run(["git","add","README.md"],cwd=repo,check=True)
            subprocess.run(["git","commit","-qm","fixture baseline"],cwd=repo,check=True)
            first=self.run_cli("init",str(repo),cwd=td)
            self.assertEqual(first.returncode,0,first.stderr)
            status=subprocess.run(["git","status","--short"],cwd=repo,text=True,capture_output=True,check=True).stdout
            self.assertNotIn(".remote-agent-job-ids.json",status)
            self.assertNotIn("agent.db",status)
            job=repo/"remote-job.md"
            job.write_text(job.read_text().replace("job_id: fixture-job","job_id: reader-job").replace("branch: remote/fixture-job","branch: remote/reader-job").replace("workspace: .remote-agent/workspaces/fixture-job","workspace: .remote-agent/workspaces/reader-job"))
            subprocess.run(["git","add","."],cwd=repo,check=True)
            subprocess.run(["git","commit","-qm","adopt scaffold"],cwd=repo,check=True)
            head=subprocess.run(["git","rev-parse","HEAD"],cwd=repo,text=True,capture_output=True,check=True).stdout.strip()
            second=self.run_cli("init",str(repo),cwd=td)
            self.assertEqual(second.returncode,0,second.stderr)
            body=job.read_text()
            self.assertIn("job_id: reader-job",body)
            self.assertIn("branch: remote/reader-job",body)
            self.assertIn(f"base_sha: {head}",body)
            status=subprocess.run(["git","status","--short"],cwd=repo,text=True,capture_output=True,check=True).stdout
            self.assertNotIn(".remote-agent-job-ids.json",status)
            self.assertNotIn("agent.db",status)

    def test_validate_job_binds_identity_by_default(self):
        with tempfile.TemporaryDirectory() as td:
            good=Path(td)/"good.md"
            changed=Path(td)/"changed.md"
            body=(ROOT/"fixtures/remote-job.md").read_text()
            good.write_text(body)
            changed.write_text(body.replace("max_cost_usd: 2.00","max_cost_usd: 2.01"))
            first=self.run_cli("validate-job",str(good),cwd=td)
            second=self.run_cli("validate-job",str(changed),cwd=td)
            self.assertEqual(first.returncode,0,first.stderr)
            self.assertEqual(second.returncode,2,second.stdout+second.stderr)
            self.assertIn("job_id reused",second.stderr)

    def test_dispatch_refuses_policy_and_schema_before_effects(self):
        with tempfile.TemporaryDirectory() as td:
            repo=self.fresh_repository(td)
            policy=repo/"remote-policy.yml"
            policy.write_text(policy.read_text().replace("allow_publish: false","allow_publish: true"))
            corrupt=subprocess.run([str(repo/"remote-agent"),"dispatch","remote-job.md","--adapter","local-fixture"],cwd=repo,text=True,capture_output=True)
            self.assertEqual(corrupt.returncode,2,corrupt.stdout+corrupt.stderr)
            with sqlite3.connect(repo/"agent.db") as db:
                self.assertEqual(db.execute("select count(*) from attempts where job_id='fixture-job'").fetchone()[0],0)
                self.assertEqual(db.execute("select count(*) from effects where job_id='fixture-job'").fetchone()[0],0)
            self.assertNotEqual(subprocess.run(["git","show-ref","--verify","--quiet","refs/heads/remote/fixture-job"],cwd=repo).returncode,0)
            policy.write_text((repo/"fixtures/remote-policy.yml").read_text())
            job=repo/"remote-job.md"
            job.write_text(job.read_text().replace("schema_version: 1","schema_version: 999"))
            unsupported=subprocess.run([str(repo/"remote-agent"),"dispatch","remote-job.md","--adapter","local-fixture"],cwd=repo,text=True,capture_output=True)
            self.assertEqual(unsupported.returncode,2,unsupported.stdout+unsupported.stderr)
            self.assertIn("unsupported schema_version",unsupported.stderr)
            with sqlite3.connect(repo/"agent.db") as db:
                self.assertEqual(db.execute("select count(*) from attempts where job_id='fixture-job'").fetchone()[0],0)

    def test_agentcore_missing_target_refuses_without_dispatch(self):
        with tempfile.TemporaryDirectory() as td:
            repo=self.fresh_repository(td)
            refused=subprocess.run([str(repo/"remote-agent"),"dispatch","remote-job.md","--adapter","agentcore"],cwd=repo,text=True,capture_output=True)
            self.assertEqual(refused.returncode,2,refused.stdout+refused.stderr)
            self.assertIn("adapter target unavailable: agentcore",refused.stderr)
            with sqlite3.connect(repo/"agent.db") as db:
                self.assertEqual(db.execute("select count(*) from attempts where job_id='fixture-job'").fetchone()[0],0)

    def test_policy_explain_requires_and_consumes_compiled_policy(self):
        with tempfile.TemporaryDirectory() as td:
            repo=self.fresh_repository(td)
            missing=subprocess.run([str(repo/"remote-agent"),"policy","explain","compiled-policy.json","--job","remote-job.md"],cwd=repo,text=True,capture_output=True)
            self.assertEqual(missing.returncode,2,missing.stdout+missing.stderr)
            compiled=subprocess.run([str(repo/"remote-agent"),"policy","compile","remote-policy.yml","--runtime","local-fixture"],cwd=repo,text=True,capture_output=True)
            self.assertEqual(compiled.returncode,0,compiled.stderr)
            explained=subprocess.run([str(repo/"remote-agent"),"policy","explain","compiled-policy.json","--job","remote-job.md"],cwd=repo,text=True,capture_output=True)
            self.assertEqual(explained.returncode,0,explained.stderr)
            report=json.loads(explained.stdout)
            compiled_body=json.loads((repo/"compiled-policy.json").read_text())
            self.assertEqual(report["compiled_policy_digest"],compiled_body["compiled_policy_digest"])
            self.assertEqual(report["allowed_paths"],["docs/"])
            self.assertEqual(report["network"]["result"],"denied")

    def test_gate_rejects_tampered_sha_digest_and_reviewer(self):
        with tempfile.TemporaryDirectory() as td:
            repo=self.fresh_repository(td)
            receipt=repo/"fixtures/gate-receipt.json"
            valid=subprocess.run([str(repo/"remote-agent"),"gate","verify",str(receipt)],cwd=repo,text=True,capture_output=True)
            self.assertEqual(valid.returncode,0,valid.stderr)
            original=json.loads(receipt.read_text())
            mutations={"head_sha":"2"*40,"evidence_digest":"sha256:"+"3"*64,"reviewer":"tampered"}
            for field,value in mutations.items():
                bad=dict(original); bad[field]=value
                candidate=repo/f"tampered-{field}.json"; candidate.write_text(json.dumps(bad))
                refused=subprocess.run([str(repo/"remote-agent"),"gate","verify",str(candidate)],cwd=repo,text=True,capture_output=True)
                self.assertEqual(refused.returncode,2,field+refused.stdout+refused.stderr)

    def test_evidence_capture_binds_full_proof_and_bundle_digest(self):
        with tempfile.TemporaryDirectory() as td:
            repo=self.fresh_repository(td)
            dispatched=subprocess.run([str(repo/"remote-agent"),"dispatch","remote-job.md","--adapter","local-fixture"],cwd=repo,text=True,capture_output=True)
            self.assertEqual(dispatched.returncode,0,dispatched.stderr)
            captured=subprocess.run([str(repo/"remote-agent"),"evidence","capture","fixture-job","--db","agent.db","--branch","remote/fixture-job","--output","captured.json"],cwd=repo,text=True,capture_output=True)
            self.assertEqual(captured.returncode,0,captured.stderr)
            packet=json.loads((repo/"captured.json").read_text())
            self.assertTrue((repo/"handoff.md").is_file())
            manifest=json.loads((repo/"handoff-manifest.json").read_text())
            self.assertEqual(manifest["evidence_digest"],packet["bundle_digest"])
            self.assertTrue(packet["commands"])
            self.assertTrue(packet["effects"])
            self.assertTrue(packet["usage"])
            self.assertTrue(packet["artifacts"])
            self.assertTrue(packet["changed_paths"])
            claimed=packet.pop("bundle_digest")
            encoded=json.dumps(packet,sort_keys=True,separators=(",",":")).encode()
            self.assertEqual(claimed,"sha256:"+hashlib.sha256(encoded).hexdigest())
            verified=subprocess.run([str(repo/"remote-agent"),"verify-evidence","captured.json","--branch","remote/fixture-job"],cwd=repo,text=True,capture_output=True)
            self.assertEqual(verified.returncode,0,verified.stderr)

    def test_economics_window_is_required_and_scoped(self):
        with tempfile.TemporaryDirectory() as td:
            db=Path(td)/"agent.db"
            with sqlite3.connect(db) as con:
                con.executescript((ROOT/"migrations/001_canonical.sql").read_text())
                con.executescript((ROOT/"fixtures/economics.sql").read_text())
            fixture=Path(td)/"fixture.csv"; empty=Path(td)/"empty.csv"; absent=Path(td)/"absent.csv"
            one=self.run_cli("economics-report","--db",str(db),"--window","fixture-window","--output",str(fixture),cwd=td)
            two=self.run_cli("economics-report","--db",str(db),"--window","empty-window","--output",str(empty),cwd=td)
            missing=self.run_cli("economics-report","--db",str(db),"--window","definitely-absent","--output",str(absent),cwd=td)
            self.assertEqual(one.returncode,0,one.stderr)
            self.assertEqual(two.returncode,0,two.stderr)
            self.assertEqual(missing.returncode,2,missing.stdout+missing.stderr)
            self.assertNotEqual(fixture.read_bytes(),empty.read_bytes())
            self.assertFalse(absent.exists())

    def test_why_reports_predicates_and_exact_versions(self):
        with tempfile.TemporaryDirectory() as td:
            repo=self.fresh_repository(td)
            self.assertEqual(subprocess.run([str(repo/"remote-agent"),"dispatch","remote-job.md","--adapter","local-fixture"],cwd=repo,text=True,capture_output=True).returncode,0)
            result=subprocess.run([str(repo/"remote-agent"),"why","fixture-job","--db","agent.db"],cwd=repo,text=True,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            report=json.loads(result.stdout)
            self.assertTrue(any(p["result"]=="passed" for p in report["predicates"]))
            self.assertTrue(any(p["result"]=="failed" for p in report["predicates"]))
            self.assertEqual(report["versions_read"]["schema_version"],1)
            self.assertIn("job_version",report["versions_read"])
            self.assertIn("policy_digests",report["versions_read"])

    def test_restore_requires_decision_receipt_and_never_replaces(self):
        with tempfile.TemporaryDirectory() as td:
            repo=self.fresh_repository(td)
            target=repo/"restored-agent.db"; receipt=repo/"restore-receipt.json"
            missing=subprocess.run([str(repo/"remote-agent"),"restore","--backup","agent.backup.db","--target",str(target)],cwd=repo,text=True,capture_output=True)
            self.assertEqual(missing.returncode,2,missing.stdout+missing.stderr)
            self.assertFalse(target.exists())
            existing=repo/"existing.db"; existing.write_bytes(b"do-not-replace")
            before=existing.read_bytes()
            blocked=subprocess.run([str(repo/"remote-agent"),"restore","--backup","agent.backup.db","--target",str(existing),"--incident-decision","fixtures/incident-decision.json","--receipt",str(receipt)],cwd=repo,text=True,capture_output=True)
            self.assertEqual(blocked.returncode,2,blocked.stdout+blocked.stderr)
            self.assertEqual(existing.read_bytes(),before)
            restored=subprocess.run([str(repo/"remote-agent"),"restore","--backup","agent.backup.db","--target",str(target),"--incident-decision","fixtures/incident-decision.json","--receipt",str(receipt)],cwd=repo,text=True,capture_output=True)
            self.assertEqual(restored.returncode,0,restored.stderr)
            proof=json.loads(receipt.read_text())
            self.assertEqual(proof["result"],"RESTORED")
            self.assertTrue(proof["preflight_receipt_written_before_target"])
            self.assertEqual(proof["target_mode"],"no-replacement")

    def test_drill_executes_boundaries_and_denial_controls(self):
        with tempfile.TemporaryDirectory() as td:
            result=self.run_cli("drill","--create-temp","--expected-suffix","remote-agent-failure-range","--receipt","drill-receipt.json",cwd=td)
            self.assertEqual(result.returncode,0,result.stderr)
            receipt=json.loads((Path(td)/"drill-receipt.json").read_text())
            cases={case["case"]:case for case in receipt["cases"]}
            for name in ("before_transaction_kill","inside_transaction_kill","after_transaction_kill","filesystem_denial","network_denial","filesystem_allowed_control","network_allowed_control"):
                self.assertIn(name,cases)
                self.assertTrue(cases[name]["executed"])
            self.assertFalse(cases["filesystem_denial"]["target_created"])
            self.assertEqual(cases["network_denial"]["connections_observed"],0)

    def test_valid_and_invalid_contracts(self):
        with tempfile.TemporaryDirectory() as td:
            good=self.run_cli("validate-job",str(ROOT/"fixtures/remote-job.md"),cwd=td)
            self.assertEqual(good.returncode,0,good.stderr)
            bad=Path(td)/"bad.md"
            bad.write_text((ROOT/"fixtures/remote-job.md").read_text().replace("1"*40,"main"))
            result=self.run_cli("validate-job",str(bad))
            self.assertEqual(result.returncode,2)
            self.assertIn("dispatch_started=false",result.stderr)
            empty=Path(td)/"empty-objective.md"
            empty.write_text((ROOT/"fixtures/remote-job.md").read_text().replace("objective: Write one deterministic documentation fixture and return exact commit evidence.","objective:"))
            empty_result=self.run_cli("validate-job",str(empty))
            self.assertEqual(empty_result.returncode,2)
            self.assertIn("objective must be a nonempty string",empty_result.stderr)
            failures=ROOT/"fixtures/failures/jobs"
            for name in ("mutable-sha.md","placeholder.md","overlap.md","unknown-command.md","nonpositive-limit.md"):
                refused=self.run_cli("validate-job",str(failures/name))
                self.assertEqual(refused.returncode,2,name)
            registry=Path(td)/"registry.json"
            self.assertEqual(self.run_cli("validate-job",str(ROOT/"fixtures/remote-job.md"),"--registry",str(registry),"--reserve").returncode,0)
            reused=self.run_cli("validate-job",str(failures/"reused-id.md"),"--registry",str(registry))
            self.assertEqual(reused.returncode,2)
    def test_schema_has_canonical_tables_and_foreign_keys(self):
        with tempfile.TemporaryDirectory() as td:
            db=Path(td)/"agent.db"
            with closing(sqlite3.connect(db)) as con:
                con.executescript((ROOT/"migrations/001_canonical.sql").read_text())
                tables={r[0] for r in con.execute("select name from sqlite_master where type='table'")}
                self.assertTrue({"jobs","attempts","events","effects","evidence","policy_decisions"}<=tables)
                self.assertEqual(con.execute("pragma foreign_key_check").fetchall(),[])
    def test_scorecard_and_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/"score.csv"
            ok=self.run_cli("runtime-scorecard","--attempt",str(ROOT/"fixtures/evidence/local.json"),"--attempt",str(ROOT/"fixtures/evidence/remote.json"),"--output",str(out))
            self.assertEqual(ok.returncode,0,ok.stderr)
            self.assertEqual(len(out.read_text().splitlines()),4)
            bad=self.run_cli("runtime-scorecard","--attempt",str(ROOT/"fixtures/evidence/local.json"),"--attempt",str(ROOT/"fixtures/evidence/mismatch.json"),"--output",str(out))
            self.assertEqual(bad.returncode,2)
    def test_repository_checks_reject_negative_fixtures(self):
        commands=[
            ([str(ROOT/"ci/format-check"),str(ROOT/"fixtures/failures/format-tabs.py")],ROOT),
            ([str(ROOT/"ci/unit-test"),str(ROOT/"fixtures/failures/unit")],ROOT),
            ([str(ROOT/"ci/type-check"),str(ROOT/"fixtures/failures/type-no-future.py")],ROOT),
        ]
        for command,cwd in commands:
            self.assertNotEqual(subprocess.run(command,cwd=cwd,text=True,capture_output=True).returncode,0)
        bad=self.run_cli("verify-evidence",str(ROOT/"fixtures/failures/evidence-sha-mismatch.json"),"--expected-sha","1"*40)
        self.assertEqual(bad.returncode,2)
        unknown=self.run_cli("policy","compile",str(ROOT/"fixtures/failures/policy-unknown.yml"),"--runtime","local-fixture")
        self.assertEqual(unknown.returncode,2)
    def test_aggregate_gate_requires_closed_sha_bound_result_set(self):
        with tempfile.TemporaryDirectory() as td:
            result_path=Path(td)/"results.json"
            names=("format","unit","types","evidence","independent-review")
            sources={"format":"repository-check","unit":"repository-check","types":"repository-check","evidence":"evidence-verifier","independent-review":"review-registry"}
            body={"schema_version":1,"head_sha":"1"*40,"acceptance_digest":"sha256:"+"2"*64,"results":[{"name":name,"status":"success","head_sha":"1"*40,"source":sources[name]} for name in names]}
            result_path.write_text(json.dumps(body))
            passed=subprocess.run([str(ROOT/"ci/aggregate-gate"),str(result_path)],cwd=ROOT,text=True,capture_output=True)
            self.assertEqual(passed.returncode,0,passed.stderr)
            for mutation in ("missing","duplicate","skipped","sha"):
                changed=json.loads(json.dumps(body))
                if mutation=="missing": changed["results"].pop()
                if mutation=="duplicate": changed["results"].append(dict(changed["results"][0]))
                if mutation=="skipped": changed["results"][0]["status"]="skipped"
                if mutation=="sha": changed["results"][0]["head_sha"]="3"*40
                result_path.write_text(json.dumps(changed))
                refused=subprocess.run([str(ROOT/"ci/aggregate-gate"),str(result_path)],cwd=ROOT,text=True,capture_output=True)
                self.assertEqual(refused.returncode,2,mutation)
    def test_economics_queue_and_upgrade(self):
        with tempfile.TemporaryDirectory() as td:
            db=Path(td)/"agent.db"
            with closing(sqlite3.connect(db)) as con:
                con.executescript((ROOT/"migrations/001_canonical.sql").read_text())
                con.executescript((ROOT/"fixtures/economics.sql").read_text())
                con.commit()
            report=Path(td)/"economics.csv"
            result=self.run_cli("economics-report","--db",str(db),"--window","fixture-window","--output",str(report))
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn("cost_per_accepted=undefined",report.read_text())
            with closing(sqlite3.connect(db)) as con:
                self.assertEqual(con.execute("select count(*) from billing_imports where billing_id='bill-econ-a2'").fetchone()[0],1)
                self.assertEqual(con.execute("select state from budget_reservations where reservation_id='reservation-b'").fetchone()[0],"blocked")
            qdb=Path(td)/"queue.db"
            with closing(sqlite3.connect(qdb)) as con:
                con.executescript((ROOT/"migrations/001_canonical.sql").read_text())
                con.executescript((ROOT/"fixtures/queue.sql").read_text())
                con.commit()
            first=self.run_cli("queue","claim","queue-one","--attempt-id","queue-a1","--resource","docs/shared.md","--worker-limit","2","--db",str(qdb))
            self.assertEqual(first.returncode,0,first.stderr)
            overlap=self.run_cli("queue","claim","queue-two","--attempt-id","queue-a2","--resource","docs/shared.md","--worker-limit","2","--db",str(qdb))
            self.assertEqual(overlap.returncode,2)
            token=first.stdout.strip().split("fencing_token=")[1]
            stale=self.run_cli("queue","release","queue-one","--attempt-id","queue-a1","--fencing-token","0","--db",str(qdb))
            self.assertEqual(stale.returncode,2)
            released=self.run_cli("queue","release","queue-one","--attempt-id","queue-a1","--fencing-token",token,"--db",str(qdb))
            self.assertEqual(released.returncode,0,released.stderr)
            disjoint=self.run_cli("queue","claim","queue-two","--attempt-id","queue-a2","--resource","docs/two.md","--cost","8","--budget","10","--worker-limit","2","--db",str(qdb))
            self.assertEqual(disjoint.returncode,0,disjoint.stderr)
            budget=self.run_cli("queue","claim","queue-three","--attempt-id","queue-a3","--resource","docs/three.md","--cost","8","--budget","10","--worker-limit","2","--db",str(qdb))
            self.assertEqual(budget.returncode,2)
            self.assertIn("BUDGET_APPROVAL_REQUIRED",budget.stdout)
            self.assertEqual(self.run_cli("stop-queue","--db",str(qdb),"--reason","test").returncode,0)
            stopped=self.run_cli("queue","claim","queue-four","--attempt-id","queue-a4","--resource","docs/four.md","--worker-limit","3","--db",str(qdb))
            self.assertEqual(stopped.returncode,2)
            self.assertIn("QUEUE_STOPPED",stopped.stderr)
            cap=Path(td)/"capacity.csv"
            self.assertEqual(self.run_cli("capacity-report","--db",str(qdb),"--output",str(cap)).returncode,0)
            config=Path(td)/"remote-agent.json"; config.write_text('{"scaffold_version":1,"schema_version":1}\n')
            plan=Path(td)/"plan.json"
            self.assertEqual(self.run_cli("upgrade","plan","--config",str(config),"--output",str(plan)).returncode,0)
            body=json.loads(plan.read_text())
            self.assertEqual(self.run_cli("upgrade","apply","--config",str(config),"--plan",str(plan),"--digest",body["plan_digest"]).returncode,0)
    def test_drill_creates_inspectable_recovery_data(self):
        with tempfile.TemporaryDirectory() as td:
            result=self.run_cli("drill","--create-temp","--expected-suffix","remote-agent-failure-range","--receipt","drill-receipt.json",cwd=td)
            self.assertEqual(result.returncode,0,result.stderr)
            receipt=json.loads((Path(td)/"drill-receipt.json").read_text())
            self.assertEqual(receipt["result"],"PASS")
            with closing(sqlite3.connect(Path(td)/"agent.db")) as db:
                self.assertEqual(db.execute("select state from jobs where job_id='drill-job'").fetchone()[0],"running")
                self.assertTrue(db.execute("select 1 from policy_decisions where result='denied'").fetchone())
            with closing(sqlite3.connect(Path(td)/"mock-effects.db")) as db:
                self.assertEqual(db.execute("select count(*) from effects where status='completed'").fetchone()[0],2)
if __name__=="__main__": unittest.main()
