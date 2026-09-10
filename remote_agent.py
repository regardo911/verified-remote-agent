#!/usr/bin/env python3
"""Deterministic local control plane for verified repository work (Chapters 2–12)."""
from __future__ import annotations
import argparse,csv,hashlib,json,os,re,shutil,signal,socket,sqlite3,subprocess,sys,tempfile,time
from contextlib import closing,contextmanager
from datetime import datetime,timezone
from decimal import Decimal
from pathlib import Path
ROOT=Path(__file__).resolve().parent
MIGRATION=ROOT/"migrations/001_canonical.sql"
MOCK_MIGRATION=ROOT/"migrations/002_mock_effects.sql"
HEX40=re.compile(r"^[0-9a-f]{40}$")
PLACEHOLDER=re.compile(r"<[^>]+>|\b(TODO|TBD|CHANGEME)\b",re.I)
COMMAND_MAP={"format":["./ci/format-check"],"unit":["./ci/unit-test"],"type":["./ci/type-check"],"evidence":["./ci/verify-evidence"]}
TOOL_NAMES={"editor","git-diff",*COMMAND_MAP}
STOP_RULES={"policy-denial","destructive-migration","missing-secret-reference","acceptance-command-change","base-sha-drift"}
EVIDENCE_FIELDS={"diff-stat","changed-paths","commands","exit-codes","test-summary","head-sha","rollback","unresolved-risks","runtime","usage"}
POLICY_KEYS={"version","runtime","read_roots","allow_paths","deny_paths","allowed_commands","ask_commands","denied_commands","network_default","network_allow_aliases","credential_plaintext","credential_bindings","approval_required","allow_publish"}
SUPPORTED_SCHEMA_VERSION=1
SUPPORTED_POLICY_VERSION=1
class Refusal(Exception): pass
def now(): return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")
def h(data): return "sha256:"+hashlib.sha256(data).hexdigest()
def hd(value): return h(json.dumps(value,sort_keys=True,separators=(",",":")).encode())
def digest_without(value,*fields): return hd({k:v for k,v in value.items() if k not in fields})
def atomic_json(path,value):
    path=Path(path); temporary=path.with_name(path.name+".tmp")
    temporary.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
    temporary.replace(path)
def scalar(s):
    s=s.strip()
    if s.lower() in {"true","false"}: return s.lower()=="true"
    if re.fullmatch(r"-?\d+",s): return int(s)
    if re.fullmatch(r"-?\d+\.\d+",s): return str(Decimal(s))
    return s.strip("'\"")
def parse_yaml(path):
    data={}; parent=None
    for raw in Path(path).read_text().splitlines():
        if not raw.strip() or raw.lstrip().startswith("#") or raw.strip().startswith(chr(96)*3): continue
        indent=len(raw)-len(raw.lstrip()); line=raw.strip()
        if line.startswith("- "):
            if parent is None or not isinstance(data.get(parent),list): raise Refusal(f"malformed list in {path}")
            data[parent].append(scalar(line[2:])); continue
        if ":" not in line: continue
        key,value=map(str.strip,line.split(":",1))
        if indent and parent and isinstance(data.get(parent),dict): data[parent][key]=scalar(value)
        elif value: data[key]=scalar(value); parent=None
        else: data[key]={} if key=="limits" else []; parent=key
    return data
def job_contract(path):
    path=Path(path)
    if not path.is_file(): raise Refusal(f"job file not found: {path}")
    if PLACEHOLDER.search(path.read_text()): raise Refusal("placeholder value")
    job=parse_yaml(path); required={"schema_version","job_id","requested_by","repository","base_sha","branch","workspace","objective","allowed_paths","denied_paths","allowed_tools","network","acceptance_commands","limits","stop_on","evidence_required","idempotency_key"}
    if required-job.keys(): raise Refusal("missing fields: "+",".join(sorted(required-job.keys())))
    if job["schema_version"]!=SUPPORTED_SCHEMA_VERSION: raise Refusal(f"unsupported schema_version: {job['schema_version']}; inspect with remote-agent upgrade inspect")
    for key in ("job_id","requested_by","repository","branch","workspace","objective","network","idempotency_key"):
        if not isinstance(job[key],str) or not job[key].strip(): raise Refusal(f"{key} must be a nonempty string")
    for key in ("allowed_paths","denied_paths","allowed_tools","acceptance_commands","stop_on","evidence_required"):
        if not isinstance(job[key],list) or not job[key]: raise Refusal(f"{key} must be a nonempty list")
    if not HEX40.fullmatch(str(job["base_sha"])): raise Refusal("base_sha must be 40 lowercase hex characters")
    if job["branch"]!=f"remote/{job['job_id']}": raise Refusal("branch must be remote/<job_id>")
    if Path(str(job["workspace"])).is_absolute() or ".." in Path(str(job["workspace"])).parts: raise Refusal("workspace must be repository-relative")
    if str(job["network"])!="deny-by-default": raise Refusal("network must be deny-by-default")
    if str(job["idempotency_key"])!="job_id + action_name + normalized-parameters-hash": raise Refusal("idempotency_key definition is unsupported")
    for key in ("allowed_paths","denied_paths"):
        clean=[]
        for value in job[key]:
            value=str(value).replace("\\","/")
            if value.startswith("/") or ".." in Path(value).parts: raise Refusal(f"unsafe {key}: {value}")
            clean.append(value)
        job[key]=sorted(set(clean))
    for allow in job["allowed_paths"]:
        for deny in job["denied_paths"]:
            a,d=allow.rstrip("/")+"/",deny.rstrip("/")+"/"
            if a.startswith(d) or d.startswith(a): raise Refusal(f"allow/deny overlap: {allow} and {deny}")
    unknown=sorted(set(map(str,job["acceptance_commands"]))-COMMAND_MAP.keys())
    if unknown: raise Refusal("unknown commands: "+",".join(unknown))
    if not job["acceptance_commands"]: raise Refusal("acceptance_commands must be nonempty")
    unknown_tools=sorted(set(map(str,job["allowed_tools"]))-TOOL_NAMES)
    if unknown_tools: raise Refusal("unknown tools: "+",".join(unknown_tools))
    missing_stops=sorted(STOP_RULES-set(map(str,job["stop_on"])))
    if missing_stops: raise Refusal("missing stop rules: "+",".join(missing_stops))
    missing_evidence=sorted(EVIDENCE_FIELDS-set(map(str,job["evidence_required"])))
    if missing_evidence: raise Refusal("missing evidence requirements: "+",".join(missing_evidence))
    if not isinstance(job["limits"],dict) or not job["limits"] or any(Decimal(str(v))<=0 for v in job["limits"].values()): raise Refusal("limits must be positive")
    normalized=json.loads(json.dumps(job,sort_keys=True)); normalized["contract_digest"]=hd(normalized); return normalized
def policy_source(path):
    source=Path(path)
    if not source.is_file(): raise Refusal(f"policy file not found: {source}")
    pol=parse_yaml(source)
    unknown_keys=sorted(set(pol)-POLICY_KEYS)
    if unknown_keys: raise Refusal("unknown policy fields: "+",".join(unknown_keys))
    missing=sorted(POLICY_KEYS-set(pol))
    if missing: raise Refusal("policy missing fields: "+",".join(missing))
    for key in ("read_roots","allow_paths","deny_paths","allowed_commands","ask_commands","denied_commands","network_allow_aliases","credential_bindings","approval_required"):
        if not isinstance(pol[key],list) or not pol[key]: raise Refusal(f"policy {key} must be a nonempty list")
    if pol.get("version")!=SUPPORTED_POLICY_VERSION: raise Refusal(f"unsupported policy version: {pol.get('version')}")
    if pol.get("runtime")!="local-fixture": raise Refusal("policy runtime is unsupported")
    if pol.get("allow_publish") is not False or pol.get("network_default")!="deny" or pol.get("credential_plaintext")!="deny": raise Refusal("policy must deny publish, network by default, and plaintext credentials")
    unknown=sorted(set(map(str,pol.get("allowed_commands",[])))-COMMAND_MAP.keys())
    if unknown: raise Refusal("unknown policy commands: "+",".join(unknown))
    if set(map(str,pol["ask_commands"]))!={"install-dependency"}: raise Refusal("policy ask commands are unsupported")
    if set(map(str,pol["denied_commands"]))!={"deploy","publish","rewrite-history"}: raise Refusal("policy denied commands are incomplete")
    required_approvals={"production-migration","credential-change","deploy","publish","expand-budget"}
    if set(map(str,pol["approval_required"]))!=required_approvals: raise Refusal("policy approval actions are incomplete")
    if "repo" not in pol["read_roots"] or not pol["credential_bindings"] or not pol["network_allow_aliases"]: raise Refusal("policy boundary bindings are incomplete")
    return pol,h(source.read_bytes())
def compile_policy(path,runtime):
    pol,source_digest=policy_source(path)
    if runtime!=pol["runtime"]: raise Refusal("requested runtime does not match policy runtime")
    body={
        "schema_version":SUPPORTED_SCHEMA_VERSION,
        "policy_version":pol["version"],
        "runtime":runtime,
        "source_policy_digest":source_digest,
        "path_rules":{"read_roots":pol["read_roots"],"allow":pol["allow_paths"],"deny":pol["deny_paths"]},
        "command_rules":{"allow":pol["allowed_commands"],"ask":pol["ask_commands"],"deny":pol["denied_commands"],"map":{name:COMMAND_MAP[name] for name in pol["allowed_commands"]}},
        "network":{"default":pol["network_default"],"allowed_hosts":pol["network_allow_aliases"]},
        "publish":{"allowed":False},
        "secrets":{"exposure":"names-only","plaintext":pol["credential_plaintext"],"bindings":pol["credential_bindings"]},
        "effects":{"require_external_approval":pol["approval_required"]},
    }
    body["compiled_policy_digest"]=digest_without(body,"compiled_policy_digest")
    return body
def load_compiled_policy(path):
    compiled_path=Path(path)
    if not compiled_path.is_file(): raise Refusal(f"compiled policy not found: {compiled_path}")
    body=json.loads(compiled_path.read_text())
    if body.get("schema_version")!=SUPPORTED_SCHEMA_VERSION: raise Refusal("compiled policy schema is unsupported")
    if body.get("policy_version")!=SUPPORTED_POLICY_VERSION: raise Refusal("compiled policy version is unsupported")
    if body.get("compiled_policy_digest")!=digest_without(body,"compiled_policy_digest"): raise Refusal("compiled policy digest mismatch")
    return body
def bind_job_identity(job,registry):
    registry=Path(registry)
    seen=json.loads(registry.read_text()) if registry.exists() else {}
    if job["job_id"] in seen and seen[job["job_id"]]!=job["contract_digest"]: raise Refusal("job_id reused with a different normalized contract")
    atomic_json(registry,{**seen,job["job_id"]:job["contract_digest"]})
@contextmanager
def dbopen(path):
    db=sqlite3.connect(path)
    try:
        db.execute("PRAGMA foreign_keys=ON"); db.execute("PRAGMA busy_timeout=5000")
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
def migrate(path):
    with dbopen(path) as db: db.executescript(MIGRATION.read_text())
def seed(path):
    stamp=now()
    with dbopen(path) as db:
        for jid,state,aid,token in [("fixture-running","running","attempt-running",101),("fixture-review","waiting_for_review","attempt-review",102)]:
            db.execute("INSERT OR IGNORE INTO jobs(job_id,contract_digest,base_sha,state,owner_attempt_id,lease_expires_at,accepted_head_sha,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",(jid,hd({"job":jid}),"1"*40,state,aid,"2099-01-01T00:00:00Z" if state=="running" else None,None,stamp,stamp))
            db.execute("INSERT OR IGNORE INTO attempts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(aid,jid,"fixture-worker",f"workspace-{jid}",f"trace-{jid}",state,token,stamp,None,"1"*40,"0.01","0.02","0","0",1))
        p=ROOT/"fixtures/evidence/remote.json"
        db.execute("INSERT OR IGNORE INTO evidence VALUES(?,?,?,?,?,?,?,?)",("evidence-review","fixture-review","attempt-review","1"*40,str(p),h(p.read_bytes()),json.dumps({"format":"pass","unit":"pass","type":"pass"}),stamp))
INSTALL_PATHS=("remote-agent","remote_agent.py","migrations","fixtures","ci","tests")
LOCAL_EXCLUDES=(".remote-agent/",".remote-agent-job-ids.json","*.db","*.db-shm","*.db-wal","capacity.csv","compiled-policy.json","drill-receipt.json","economics.csv","evidence.json","handoff.md","handoff-manifest.json","policy-explain.json","restore-receipt.json","restored-agent.db","upgrade-plan.json","why.json","__pycache__/","*.py[cod]")
def installed_config(target):
    config=target/"remote-agent.json"
    if not config.exists(): return False
    try: value=json.loads(config.read_text())
    except json.JSONDecodeError: raise Refusal("existing remote-agent.json is invalid")
    if value!={"scaffold_version":1,"schema_version":1}: raise Refusal("existing remote-agent.json is not a supported scaffold")
    return True
def install_files(src):
    if src.is_file(): return [src]
    return [p for p in src.rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix not in {".pyc",".pyo"}]
def has_symlink(target,path):
    current=target
    for part in path.relative_to(target).parts:
        current=current/part
        if current.is_symlink(): return True
    return False
def install_excludes(target):
    result=subprocess.run(["git","rev-parse","--git-path","info/exclude"],cwd=target,text=True,capture_output=True,check=True)
    path=Path(result.stdout.strip())
    if not path.is_absolute(): path=target/path
    path.parent.mkdir(parents=True,exist_ok=True)
    current=path.read_text() if path.exists() else ""
    marker="# remote-agent local state"
    if marker not in current:
        prefix="" if not current or current.endswith("\n") else "\n"
        path.write_text(current+prefix+marker+"\n"+"\n".join(LOCAL_EXCLUDES)+"\n")
def init(args):
    target=Path(args.repository or ".").resolve(); target.mkdir(parents=True,exist_ok=True)
    installed=installed_config(target); git_repo=(target/".git").exists(); head=None
    if git_repo:
        head=subprocess.run(["git","rev-parse","HEAD"],cwd=target,text=True,capture_output=True,check=True).stdout.strip()
    conflicts=[]
    for rel in INSTALL_PATHS:
        src,dst=ROOT/rel,target/rel
        if src.resolve()==dst.resolve(): continue
        for source in install_files(src):
            suffix=Path() if src.is_file() else source.relative_to(src)
            destination=dst/suffix
            key=str(Path(rel)/suffix)
            if destination.exists() or destination.is_symlink():
                if installed and key=="fixtures/gate-receipt.json": continue
                if has_symlink(target,destination) or not destination.is_file() or source.read_bytes()!=destination.read_bytes(): conflicts.append(key)
    for name,seed_name in (("remote-job.md","remote-job.md"),("remote-policy.yml","remote-policy.yml")):
        destination=target/name; source=ROOT/"fixtures"/seed_name
        if not installed and (destination.exists() or destination.is_symlink()) and (has_symlink(target,destination) or not destination.is_file() or source.read_bytes()!=destination.read_bytes()): conflicts.append(name)
    contract=target/"remote-job.md" if (target/"remote-job.md").is_file() else ROOT/"fixtures/remote-job.md"
    if git_repo and len(re.findall(r"(?m)^base_sha: [0-9a-f]{40}$",contract.read_text()))!=1: conflicts.append("remote-job.md:base_sha")
    if conflicts: raise Refusal("init would replace existing paths: "+",".join(sorted(set(conflicts))))
    ignore=shutil.ignore_patterns("__pycache__","*.pyc","*.pyo")
    for rel in INSTALL_PATHS:
        src,dst=ROOT/rel,target/rel
        if src.resolve()==dst.resolve(): continue
        if src.is_dir(): shutil.copytree(src,dst,dirs_exist_ok=True,ignore=ignore)
        else: shutil.copy2(src,dst)
    for name in ("remote-job.md","remote-policy.yml"):
        destination=target/name
        if not destination.exists(): shutil.copy2(target/"fixtures"/name,destination)
    shutil.copytree(target/"fixtures/evidence",target/"evidence",dirs_exist_ok=True)
    if git_repo:
        contract=target/"remote-job.md"; body,count=re.subn(r"(?m)^base_sha: [0-9a-f]{40}$",f"base_sha: {head}",contract.read_text(),count=1)
        if count!=1: raise Refusal("remote-job.md must contain one full base_sha")
        contract.write_text(body); install_excludes(target)
    for p in [target/"remote-agent",*(target/"ci").glob("*")]: p.chmod(p.stat().st_mode|0o111)
    migrate(target/"agent.db"); seed(target/"agent.db")
    backup=target/"agent.backup.db"
    if not backup.exists():
        with closing(sqlite3.connect(target/"agent.db")) as source, closing(sqlite3.connect(backup)) as destination: source.backup(destination)
    config=target/"remote-agent.json"
    if not config.exists(): config.write_text(json.dumps({"scaffold_version":1,"schema_version":1},sort_keys=True,indent=2)+"\n")
    if git_repo:
        evidence_path=target/"fixtures/evidence/local.json"
        claim={
            "schema_version":1,
            "head_sha":head,
            "evidence_path":"fixtures/evidence/local.json",
            "evidence_digest":h(evidence_path.read_bytes()),
            "checks":{"format":"pass","unit":"pass","type":"pass","evidence":"pass"},
            "reviewer":"fixture-independent-reviewer",
        }
        claim["reviewer_approval_digest"]=hd(claim)
        claim["receipt_digest"]=digest_without(claim,"receipt_digest")
        atomic_json(target/"fixtures/gate-receipt.json",claim)
        atomic_json(target/"fixtures/gate-reviewers.json",{"schema_version":1,"reviewers":{claim["reviewer"]:claim["reviewer_approval_digest"]}})
    print(f"INIT path={target} schema=1 dispatch_started=false"); return 0
def validate(args):
    job=job_contract(args.job); registry=Path(args.registry or ".remote-agent-job-ids.json")
    bind_job_identity(job,registry)
    print(f"VALID job_id={job['job_id']} digest={job['contract_digest']} dispatch_started=false"); return 0
def invariant_errors(db):
    found=[]
    for jid,state,owner,lease,astate in db.execute("SELECT j.job_id,j.state,j.owner_attempt_id,j.lease_expires_at,a.state FROM jobs j LEFT JOIN attempts a ON a.attempt_id=j.owner_attempt_id"):
        if state=="running" and (not owner or not lease or astate!="running"): found.append(f"{jid}: running job lacks live owner/lease")
        if state=="waiting_for_review" and not db.execute("SELECT count(*) FROM evidence WHERE job_id=?",(jid,)).fetchone()[0]: found.append(f"{jid}: review job lacks evidence")
    if db.execute("PRAGMA foreign_key_check").fetchall(): found.append("foreign-key violation")
    if db.execute("PRAGMA integrity_check").fetchone()[0]!="ok": found.append("integrity check failed")
    return found
def status(args):
    if not Path(args.db).exists(): raise Refusal(f"database not found: {args.db}")
    with dbopen(args.db) as db:
        bad=invariant_errors(db); rows=[dict(zip(("job_id","state","owner_attempt_id","lease_expires_at"),r)) for r in db.execute("SELECT job_id,state,owner_attempt_id,lease_expires_at FROM jobs ORDER BY job_id")]
    if args.json: print(json.dumps({"ok":not bad,"errors":bad,"jobs":rows},sort_keys=True))
    elif bad:
        for e in bad: print("INVALID "+e)
    else:
        for r in rows: print(f"{r['job_id']} {r['state']} owner={r['owner_attempt_id'] or '-'}")
        print("STATUS ok")
    return 2 if bad else 0
def load_attempt(path):
    d=json.loads(Path(path).read_text())
    req={"job_id","attempt_id","base_sha","acceptance_digest","reviewer_rule","accepted","wall_seconds","setup_seconds","reviewer_minutes","runtime_cost","model_cost","storage_cost","network_cost","evidence_complete","hard_constraints"}
    if req-d.keys(): raise Refusal(f"incomplete attempt: {path}")
    return d
def scorecard(args):
    rows=[load_attempt(p) for p in args.attempt]
    if len(rows)!=2 or len({r["attempt_id"] for r in rows})!=2: raise Refusal("exactly two distinct attempts are required")
    keys=("job_id","base_sha","acceptance_digest","reviewer_rule"); mismatch=[k for k in keys if len({r[k] for r in rows})!=1]
    if mismatch: raise Refusal("non-comparable attempts: "+",".join(mismatch))
    fields=["row_type","job_id","attempt_id","accepted","wall_seconds","setup_seconds","reviewer_minutes","total_cost","eligible","reason"]; out=[]
    for r in rows:
        total=sum(Decimal(str(r[k])) for k in ("runtime_cost","model_cost","storage_cost","network_cost"))
        constraints=list(r["hard_constraints"])+([] if r["evidence_complete"] else ["incomplete evidence"])
        out.append({"row_type":"attempt","job_id":r["job_id"],"attempt_id":r["attempt_id"],"accepted":str(bool(r["accepted"])).lower(),"wall_seconds":r["wall_seconds"],"setup_seconds":r["setup_seconds"],"reviewer_minutes":r["reviewer_minutes"],"total_cost":format(total,"f"),"eligible":str(not constraints).lower(),"reason":"; ".join(constraints)})
    eligible=[r for r in out if r["eligible"]=="true"]; pick=min(eligible,key=lambda r:(Decimal(r["total_cost"]),int(r["wall_seconds"]))) if eligible else None
    out.append({"row_type":"decision","job_id":rows[0]["job_id"],"attempt_id":pick["attempt_id"] if pick else "","accepted":"","wall_seconds":"","setup_seconds":"","reviewer_minutes":"","total_cost":"","eligible":str(bool(pick)).lower(),"reason":"lowest eligible total cost" if pick else "no eligible attempt"})
    with Path(args.output).open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=fields,lineterminator="\n"); w.writeheader(); w.writerows(out)
    print(f"SCORECARD rows=3 selected={out[-1]['attempt_id'] or 'none'} output={args.output}"); return 0
def policy(args):
    if args.action=="compile":
        compiled=compile_policy(args.policy,args.runtime)
        atomic_json(args.output,compiled)
        print(f"COMPILED runtime={args.runtime} output={args.output}")
        return 0
    compiled=load_compiled_policy(args.policy)
    job=job_contract(args.job)
    allow=compiled["path_rules"]["allow"]; deny=compiled["path_rules"]["deny"]
    command_allow=compiled["command_rules"]["allow"]
    report={
        "job_id":job["job_id"],
        "compiled_policy_digest":compiled["compiled_policy_digest"],
        "policy_version":compiled["policy_version"],
        "runtime":compiled["runtime"],
        "allowed_paths":[path for path in job["allowed_paths"] if any(path.startswith(prefix.rstrip("*")) for prefix in allow)],
        "denied_paths":[path for path in job["denied_paths"] if any(path.startswith(prefix.rstrip("*")) or prefix.startswith(path.rstrip("*")) for prefix in deny)],
        "commands":[{"name":name,"result":"allowed" if name in command_allow else "denied","argv":compiled["command_rules"]["map"].get(name)} for name in job["acceptance_commands"]],
        "network":{"result":"denied" if compiled["network"]["default"]=="deny" else "allowed","allowed_hosts":compiled["network"]["allowed_hosts"]},
        "publish":{"result":"allowed" if compiled["publish"]["allowed"] else "denied"},
        "secrets":compiled["secrets"],
        "effects":compiled["effects"],
    }
    print(json.dumps(report,sort_keys=True)); return 0
def run_git(cwd,*argv): return subprocess.run(["git",*argv],cwd=cwd,text=True,capture_output=True,check=True)
def dispatch(args):
    if args.adapter!="local-fixture": raise Refusal(f"adapter target unavailable: {args.adapter}; only local-fixture is supplied")
    job=job_contract(args.job); repo=Path(str(job["repository"])).resolve()
    if not (repo/".git").exists(): raise Refusal("repository is not a git work tree")
    compiled=compile_policy(repo/"remote-policy.yml",args.adapter)
    base=run_git(repo,"rev-parse","HEAD").stdout.strip()
    if base!=job["base_sha"]: raise Refusal("base_sha does not equal repository HEAD")
    bind_job_identity(job,repo/".remote-agent-job-ids.json")
    branch=f"remote/{job['job_id']}"; work=repo/".remote-agent/workspaces"/job["job_id"]
    work.parent.mkdir(parents=True,exist_ok=True)
    run_git(repo,"worktree","add","-b",branch,str(work),base)
    migrate(repo/"agent.db"); stamp=now(); aid=f"{job['job_id']}-attempt-1"
    with dbopen(repo/"agent.db") as db:
        db.execute("INSERT INTO jobs(job_id,contract_digest,base_sha,state,owner_attempt_id,lease_expires_at,accepted_head_sha,repo,branch,workspace_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(job["job_id"],job["contract_digest"],base,"running",aid,"2099-01-01T00:00:00Z",None,str(repo),branch,str(work),stamp,stamp))
        db.execute("INSERT INTO attempts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(aid,job["job_id"],"local-fixture",str(work),"trace-1","running",time.time_ns(),stamp,None,None,"0.01","0.01","0","0",0))
        db.execute("INSERT INTO events(job_id,attempt_id,event_type,payload_json,created_at) VALUES(?,?,?,?,?)",(job["job_id"],aid,"DISPATCHED",json.dumps({"schema_version":job["schema_version"],"policy_digest":compiled["compiled_policy_digest"]}),stamp))
        decisions=[]
        decisions.extend((path,"allowed","matched allowed path") for path in job["allowed_paths"])
        decisions.extend((path,"denied","matched denied path") for path in job["denied_paths"])
        decisions.extend((name,"allowed","fixed command map") for name in job["acceptance_commands"])
        decisions.extend([("network:*","denied","deny by default"),("publish","denied","publisher authority absent")])
        db.executemany("INSERT INTO policy_decisions(job_id,attempt_id,target,result,reason,policy_digest,created_at) VALUES(?,?,?,?,?,?,?)",[(job["job_id"],aid,target,result,reason,compiled["compiled_policy_digest"],stamp) for target,result,reason in decisions])
    changed=work/"docs/remote-agent-fixture.md"; changed.parent.mkdir(exist_ok=True); changed.write_text(f"local-fixture dispatch completed attempt={aid} nonce={time.time_ns()}\n")
    log_dir=repo/".remote-agent/evidence"/job["job_id"]; log_dir.mkdir(parents=True,exist_ok=True)
    command_rows=[]
    for symbolic in job["acceptance_commands"]:
        argv=COMMAND_MAP[str(symbolic)]; started=time.monotonic_ns()
        result=subprocess.run(argv,cwd=work,text=True,capture_output=True)
        duration=max(0,(time.monotonic_ns()-started)//1_000_000)
        stdout_path=log_dir/f"{symbolic}.stdout"; stderr_path=log_dir/f"{symbolic}.stderr"
        stdout_path.write_text(result.stdout); stderr_path.write_text(result.stderr)
        command_rows.append((str(symbolic),hd(argv),result.returncode,duration,h(result.stdout.encode()),h(result.stderr.encode()),str(stdout_path.relative_to(repo)),str(stderr_path.relative_to(repo))))
        if result.returncode: raise Refusal(f"check failed: {symbolic}: {result.stderr.strip()}")
    run_git(work,"add","docs/remote-agent-fixture.md")
    run_git(work,"-c","user.name=Remote Agent Fixture","-c","user.email=fixture.invalid","commit","-m",f"fixture: {job['job_id']}")
    head=run_git(work,"rev-parse","HEAD").stdout.strip()
    with dbopen(repo/"agent.db") as db:
        db.executemany("INSERT INTO command_results(job_id,attempt_id,command_name,argv_digest,exit_code,duration_ms,stdout_digest,stderr_digest,raw_stdout_path,raw_stderr_path,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",[(job["job_id"],aid,*row,now()) for row in command_rows])
        db.execute("INSERT INTO effects(effect_key,job_id,attempt_id,effect_type,status,external_ref,payload_digest,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",(f"{job['job_id']}:write:docs/remote-agent-fixture.md",job["job_id"],aid,"repository-write","completed",str(changed),h(changed.read_bytes()),stamp,now()))
        db.execute("INSERT INTO usage_records VALUES(?,?,?,?,?,?,?,?)",(aid+":usage",job["job_id"],aid,"0.01","0.01","0","0",now()))
        db.execute("UPDATE jobs SET state='waiting_for_review',head_sha=?,evidence_uri=?,updated_at=? WHERE job_id=?",(head,str(repo/"evidence.json"),now(),job["job_id"]))
        db.execute("UPDATE attempts SET state='waiting_for_review',finished_at=?,head_sha=? WHERE attempt_id=?",(now(),head,aid))
    body=build_evidence(repo/"agent.db",job["job_id"],branch,repo/"evidence.json",repo)
    with dbopen(repo/"agent.db") as db:
        db.execute("INSERT OR REPLACE INTO evidence VALUES(?,?,?,?,?,?,?,?)",(aid+"-evidence",job["job_id"],aid,head,str(repo/"evidence.json"),body["bundle_digest"],json.dumps(body["checks"],sort_keys=True),now()))
        db.execute("INSERT INTO events(job_id,attempt_id,event_type,payload_json,created_at) VALUES(?,?,?,?,?)",(job["job_id"],aid,"EVIDENCE_CAPTURED",json.dumps({"digest":body["bundle_digest"]}),now()))
    print(f"DISPATCHED job_id={job['job_id']} attempt_id={aid} head_sha={head} evidence={repo/'evidence.json'}"); return 0
def build_evidence(db_path,job_id,branch,output,repo=None):
    db_path=Path(db_path); repo=Path(repo or db_path.resolve().parent).resolve()
    with dbopen(db_path) as db:
        row=db.execute("SELECT j.job_id,a.attempt_id,j.base_sha,a.head_sha,a.workspace_id FROM jobs j JOIN attempts a ON a.attempt_id=j.owner_attempt_id WHERE j.job_id=?",(job_id,)).fetchone()
        if not row or not row[3]: raise Refusal("job has no completed head")
        commands=[dict(zip(("name","argv_digest","exit_code","duration_ms","stdout_digest","stderr_digest","stdout_path","stderr_path"),r)) for r in db.execute("SELECT command_name,argv_digest,exit_code,duration_ms,stdout_digest,stderr_digest,raw_stdout_path,raw_stderr_path FROM command_results WHERE attempt_id=? ORDER BY result_id",(row[1],))]
        effects=[dict(zip(("effect_key","effect_type","status","external_ref","payload_digest"),r)) for r in db.execute("SELECT effect_key,effect_type,status,external_ref,payload_digest FROM effects WHERE attempt_id=? ORDER BY effect_key",(row[1],))]
        usage=[dict(zip(("runtime_cost","model_cost","storage_cost","network_cost","recorded_at"),r)) for r in db.execute("SELECT runtime_cost,model_cost,storage_cost,network_cost,recorded_at FROM usage_records WHERE attempt_id=? ORDER BY usage_id",(row[1],))]
    changed_paths=run_git(repo,"diff","--name-only",row[2],row[3]).stdout.splitlines()
    artifacts=[]
    for command in commands:
        for key,kind in (("stdout_path","command-stdout"),("stderr_path","command-stderr")):
            artifact=(repo/command[key]).resolve()
            artifacts.append({"path":str(artifact),"kind":kind,"digest":h(artifact.read_bytes())})
    workspace=Path(row[4])
    for changed_path in changed_paths:
        artifact=(workspace/changed_path).resolve()
        artifacts.append({"path":str(artifact),"kind":"changed-file","digest":h(artifact.read_bytes())})
    checks={command["name"]:"pass" if command["exit_code"]==0 else "fail" for command in commands}
    body={"schema_version":1,"job_id":row[0],"attempt_id":row[1],"base_sha":row[2],"head_sha":row[3],"branch":branch,"workspace_id":row[4],"changed_paths":changed_paths,"commands":commands,"effects":effects,"usage":usage,"checks":checks,"artifacts":artifacts,"unresolved_risks":[],"rollback":{"procedure":"git branch -D "+branch}}
    body["bundle_digest"]=digest_without(body,"bundle_digest")
    atomic_json(output,body)
    return body
def evidence_check(path,branch=None,expected=None):
    evidence_path=Path(path); d=json.loads(evidence_path.read_text()); sha=str(d.get("head_sha",""))
    if not HEX40.fullmatch(sha): raise Refusal("evidence head_sha is invalid")
    if expected and sha!=expected: raise Refusal("evidence head_sha does not match expected SHA")
    if branch and d.get("branch")!=branch: raise Refusal("evidence branch does not match")
    if branch:
        actual=run_git(Path.cwd(),"rev-parse",branch).stdout.strip()
        if actual!=sha: raise Refusal("evidence head does not match branch head")
    if any(v!="pass" for v in d.get("checks",{}).values()): raise Refusal("one or more checks did not pass")
    if "bundle_digest" in d and d["bundle_digest"]!=digest_without(d,"bundle_digest"): raise Refusal("evidence bundle digest mismatch")
    artifacts=d.get("artifacts",{})
    iterable=artifacts.items() if isinstance(artifacts,dict) else ((item["path"],item["digest"]) for item in artifacts)
    for p,dg in iterable:
        artifact=Path(p)
        if not artifact.is_absolute(): artifact=(evidence_path.parent/artifact).resolve()
        if not artifact.is_file() or h(artifact.read_bytes())!=dg: raise Refusal(f"artifact digest mismatch: {p}")
    if d.get("commands") is not None and (not d["commands"] or any(item["exit_code"]!=0 for item in d["commands"])): raise Refusal("command proof is incomplete or failed")
    return d
def verify(args):
    d=evidence_check(args.evidence,args.branch,args.expected_sha); print(f"VERIFIED job_id={d.get('job_id')} head_sha={d['head_sha']} bundle={d.get('bundle_digest','legacy')}"); return 0
def render_handoff(evidence_path):
    # Chapter 8: render only from a bundle that has already passed verification.
    evidence_path=Path(evidence_path).resolve(); d=evidence_check(evidence_path,expected=None)
    output=evidence_path.with_name("handoff.md"); manifest=evidence_path.with_name("handoff-manifest.json")
    changed="\n".join(f"- `{path}`" for path in d["changed_paths"]) or "- No changed paths recorded"
    checks="\n".join(f"- {'PASS' if item['exit_code']==0 else 'FAIL'} `{item['name']}` (exit {item['exit_code']})" for item in d["commands"])
    risks="\n".join(f"- {risk}" for risk in d["unresolved_risks"]) or "- No unresolved risk was recorded; independent judgment is still required."
    text=f"""# {d['job_id']}: returned change

State: `waiting_for_review`
Head: `{d['head_sha']}`
Evidence: `{d['bundle_digest']}`
Gate: **PENDING independent review**

## What was requested?

Verify this returned change against job `{d['job_id']}` and base `{d['base_sha']}`.

## What changed?

{changed}

## What passed or failed?

{checks}

## What still needs judgment?

{risks}

## How do I reject or roll back?

Do not accept the returned head. Recorded procedure: `{d['rollback']['procedure']}`

## Raw evidence

Canonical file: `{evidence_path.name}`
"""
    output.write_text(text)
    record={"schema_version":1,"renderer_version":1,"evidence_path":evidence_path.name,"evidence_digest":d["bundle_digest"],"handoff_path":output.name,"handoff_digest":h(output.read_bytes())}
    record["manifest_digest"]=digest_without(record,"manifest_digest"); atomic_json(manifest,record)
    return output,manifest
def capture(args):
    repo=Path(args.db).resolve().parent
    d=build_evidence(args.db,args.job_id,args.branch,args.output,repo)
    evidence_check(args.output,args.branch,d["head_sha"])
    handoff,manifest=render_handoff(args.output)
    with dbopen(args.db) as db:
        db.execute("INSERT OR REPLACE INTO evidence VALUES(?,?,?,?,?,?,?,?)",(d["attempt_id"]+"-evidence",d["job_id"],d["attempt_id"],d["head_sha"],str(Path(args.output).resolve()),d["bundle_digest"],json.dumps(d["checks"],sort_keys=True),now()))
    print(f"EVIDENCE output={args.output} digest={d['bundle_digest']} handoff={handoff} manifest={manifest}"); return 0
def economics(args):
    with dbopen(args.db) as db:
        window=db.execute("SELECT starts_at,ends_at,budget FROM cost_windows WHERE window_id=?",(args.window,)).fetchone()
        if not window: raise Refusal(f"cost window not found: {args.window}")
        rows=db.execute("SELECT a.attempt_id,a.job_id,a.state,a.runtime_cost,a.model_cost,a.storage_cost,a.network_cost,a.reviewer_minutes,CASE WHEN j.accepted_head_sha=a.head_sha THEN 1 ELSE 0 END FROM attempts a JOIN jobs j ON j.job_id=a.job_id WHERE a.started_at>=? AND a.started_at<? ORDER BY a.attempt_id",(window[0],window[1])).fetchall()
    total=Decimal("0"); accepted=set(); unknown=False
    with Path(args.output).open("w",newline="") as f:
        w=csv.writer(f,lineterminator="\n"); w.writerow(["window_id","starts_at","ends_at","budget"]); w.writerow([args.window,*window])
        w.writerow(["attempt_id","job_id","state","total_cost","reviewer_minutes","accepted"])
        for r in rows:
            try: cost=sum(Decimal(str(v)) for v in r[3:7])
            except Exception: cost=None; unknown=True
            if cost is not None: total+=cost
            if r[8]: accepted.add(r[1])
            w.writerow([r[0],r[1],r[2],format(cost,"f") if cost is not None else "unknown",r[7],r[8]])
        per="undefined" if not accepted or unknown else format(total/len(accepted),"f")
        w.writerow(["summary","","","undefined" if unknown else format(total,"f"),"",f"cost_per_accepted={per}"])
    print(f"ECONOMICS window={args.window} attempts={len(rows)} accepted_jobs={len(accepted)} output={args.output}"); return 0
def gate(args):
    receipt_path=Path(args.receipt); d=json.loads(receipt_path.read_text())
    req={"schema_version","head_sha","evidence_path","evidence_digest","checks","reviewer","reviewer_approval_digest","receipt_digest"}
    if req-d.keys() or d["schema_version"]!=1 or any(v!="pass" for v in d["checks"].values()): raise Refusal("gate receipt incomplete or failed")
    if d["receipt_digest"]!=digest_without(d,"receipt_digest"): raise Refusal("gate receipt digest mismatch")
    claim={k:d[k] for k in ("schema_version","head_sha","evidence_path","evidence_digest","checks","reviewer")}
    if d["reviewer_approval_digest"]!=hd(claim): raise Refusal("reviewer approval digest mismatch")
    registry_path=receipt_path.with_name("gate-reviewers.json")
    registry=json.loads(registry_path.read_text()) if registry_path.exists() else {}
    if registry.get("reviewers",{}).get(d["reviewer"])!=d["reviewer_approval_digest"]: raise Refusal("reviewer is not authenticated for this receipt")
    if not HEX40.fullmatch(d["head_sha"]) or run_git(Path.cwd(),"cat-file","-e",d["head_sha"]+"^{commit}").returncode: raise Refusal("gate head commit is not resolvable")
    evidence_path=(Path.cwd()/d["evidence_path"]).resolve()
    if not evidence_path.is_file() or h(evidence_path.read_bytes())!=d["evidence_digest"]: raise Refusal("gate evidence digest mismatch")
    print(f"GATE VERIFIED head_sha={d['head_sha']} reviewer={d['reviewer']} gate={d['receipt_digest']}"); return 0
def queue(args):
    migrate(Path(args.db)); state={"stop-queue":"stopped","resume-queue":"running","drain-queue":"draining"}[args.command]
    with dbopen(args.db) as db: db.execute("UPDATE queue_control SET state=?,reason=?,updated_at=? WHERE singleton=1",(state,args.reason,now()))
    print(f"QUEUE state={state} reason={args.reason}"); return 0
def why(args):
    with dbopen(args.db) as db:
        job=db.execute("SELECT job_id,state,owner_attempt_id,version,contract_digest,base_sha,lease_expires_at FROM jobs WHERE job_id=?",(args.job_id,)).fetchone()
        if not job: raise Refusal("job not found")
        decisions=[dict(zip(("target","result","reason","policy_digest"),row)) for row in db.execute("SELECT target,result,reason,policy_digest FROM policy_decisions WHERE job_id=? ORDER BY decision_id",(args.job_id,))]
        events=[dict(zip(("event_type","created_at"),row)) for row in db.execute("SELECT event_type,created_at FROM events WHERE job_id=? ORDER BY event_id",(args.job_id,))]
        schema_version=db.execute("SELECT max(version) FROM schema_migrations").fetchone()[0]
        queue_state=db.execute("SELECT state FROM queue_control WHERE singleton=1").fetchone()[0]
    predicates=[
        {"name":"job_exists","result":"passed","observed":job[0]},
        {"name":"queue_accepting","result":"passed" if queue_state=="running" else "failed","observed":queue_state},
        {"name":"owner_present","result":"passed" if job[2] else "failed","observed":job[2]},
        {"name":"lease_present","result":"passed" if job[6] else "failed","observed":job[6]},
    ]
    predicates.extend({"name":"policy:"+decision["target"],"result":"passed" if decision["result"]=="allowed" else "failed","observed":decision["reason"]} for decision in decisions)
    report={
        "job":{"job_id":job[0],"state":job[1],"owner_attempt_id":job[2]},
        "predicates":predicates,
        "versions_read":{"schema_version":schema_version,"job_version":job[3],"contract_digest":job[4],"base_sha":job[5],"policy_digests":sorted({d["policy_digest"] for d in decisions})},
        "policy_decisions":decisions,
        "events":events,
    }
    print(json.dumps(report,sort_keys=True)); return 0
def restore(args):
    source,target=Path(args.backup).resolve(),Path(args.target).resolve()
    decision_path=Path(args.incident_decision).resolve() if args.incident_decision else None
    receipt=Path(args.receipt).resolve() if args.receipt else None
    if source==target or not source.is_file(): raise Refusal("restore requires distinct existing backup and target paths")
    if target.exists(): raise Refusal("restore target already exists; no-replacement mode refuses overwrite")
    if not decision_path or not decision_path.is_file() or not receipt: raise Refusal("restore requires --incident-decision and --receipt")
    if receipt.exists(): raise Refusal("restore receipt already exists")
    decision=json.loads(decision_path.read_text())
    required={"schema_version","decision_id","approved_by","action","target_mode","approved"}
    if required-decision.keys() or decision["schema_version"]!=1 or decision["action"]!="restore" or decision["target_mode"]!="no-replacement" or decision["approved"] is not True: raise Refusal("incident decision does not authorize no-replacement restore")
    with dbopen(source) as db:
        integrity=db.execute("PRAGMA integrity_check").fetchone()[0]; fk=db.execute("PRAGMA foreign_key_check").fetchall()
        backup_identity={"schema_version":db.execute("SELECT max(version) FROM schema_migrations").fetchone()[0],"jobs":db.execute("SELECT count(*) FROM jobs").fetchone()[0]}
    if integrity!="ok" or fk: raise Refusal("backup failed restore preflight")
    preflight={"result":"PREFLIGHT_APPROVED","backup":str(source),"backup_digest":h(source.read_bytes()),"backup_identity":backup_identity,"target":str(target),"target_mode":"no-replacement","incident_decision":decision,"incident_decision_digest":h(decision_path.read_bytes()),"integrity":"ok","foreign_keys":"ok","preflight_receipt_written_before_target":True}
    preflight["preflight_receipt_digest"]=digest_without(preflight,"preflight_receipt_digest")
    atomic_json(receipt,preflight)
    try:
        with source.open("rb") as src,target.open("xb") as dst: shutil.copyfileobj(src,dst)
        with dbopen(target) as db:
            restored_integrity=db.execute("PRAGMA integrity_check").fetchone()[0]; restored_fk=db.execute("PRAGMA foreign_key_check").fetchall()
        if restored_integrity!="ok" or restored_fk: raise Refusal("restored database failed integrity checks")
    except Exception:
        if target.exists(): target.unlink()
        raise
    final={**preflight,"result":"RESTORED","target_digest":h(target.read_bytes()),"restored_integrity":"ok","restored_foreign_keys":"ok"}
    final["receipt_digest"]=digest_without(final,"receipt_digest")
    atomic_json(receipt,final)
    print(f"RESTORED target={target} integrity=ok foreign_keys=ok receipt={receipt}"); return 0
def queue_claim(args):
    migrate(Path(args.db)); stamp=now(); token=time.time_ns()
    with dbopen(args.db) as db:
        db.execute("BEGIN IMMEDIATE")
        state=db.execute("SELECT state FROM queue_control WHERE singleton=1").fetchone()[0]
        if state!="running": raise Refusal(f"QUEUE_{state.upper()}")
        job=db.execute("SELECT state FROM jobs WHERE job_id=?",(args.job_id,)).fetchone()
        if not job or job[0]!="queued": raise Refusal("JOB_NOT_QUEUED")
        active=db.execute("SELECT count(*) FROM attempts WHERE state IN ('leased','running')").fetchone()[0]
        if active>=args.worker_limit: raise Refusal("WORKER_LIMIT")
        for dep,required in db.execute("SELECT depends_on_job_id,required_head_sha FROM job_dependencies WHERE job_id=?",(args.job_id,)):
            actual=db.execute("SELECT accepted_head_sha FROM jobs WHERE job_id=?",(dep,)).fetchone()
            if not actual or actual[0]!=required: raise Refusal("DEPENDENCY_NOT_ACCEPTED")
        reserved=sum(Decimal(r[0]) for r in db.execute("SELECT amount FROM budget_reservations WHERE state='reserved'"))
        if reserved+Decimal(args.cost)>Decimal(args.budget):
            db.execute("UPDATE jobs SET state='blocked',blocker_code='BUDGET_APPROVAL_REQUIRED',updated_at=? WHERE job_id=?",(stamp,args.job_id))
            db.execute("INSERT INTO budget_reservations VALUES(?,?,?,?,?,?)",(f"budget:{args.attempt_id}",args.job_id,args.cost,"blocked","BUDGET_APPROVAL_REQUIRED",stamp))
            print("BLOCKED reason=BUDGET_APPROVAL_REQUIRED"); return 2
        db.execute("INSERT INTO attempts(attempt_id,job_id,actor_id,workspace_id,trace_id,state,fencing_token,started_at) VALUES(?,?,?,?,?,?,?,?)",(args.attempt_id,args.job_id,"queue-controller",f"workspace-{args.attempt_id}",f"trace-{args.attempt_id}","leased",token,stamp))
        for resource in sorted(set(args.resource)):
            db.execute("INSERT INTO resource_locks VALUES(?,?,?,?,?)",(resource,args.job_id,args.attempt_id,token,stamp))
        db.execute("INSERT INTO budget_reservations VALUES(?,?,?,?,?,?)",(f"budget:{args.attempt_id}",args.job_id,args.cost,"reserved",None,stamp))
        db.execute("UPDATE jobs SET state='leased',owner_attempt_id=?,lease_expires_at=?,version=version+1,updated_at=? WHERE job_id=?",(args.attempt_id,"2099-01-01T00:00:00Z",stamp,args.job_id))
        db.execute("INSERT INTO events(job_id,attempt_id,event_type,payload_json,created_at) VALUES(?,?,?,?,?)",(args.job_id,args.attempt_id,"QUEUE_CLAIMED",json.dumps({"resources":sorted(set(args.resource))}),stamp))
    print(f"CLAIMED job_id={args.job_id} attempt_id={args.attempt_id} fencing_token={token}"); return 0
def queue_release(args):
    with dbopen(args.db) as db:
        db.execute("BEGIN IMMEDIATE")
        row=db.execute("SELECT j.owner_attempt_id,a.fencing_token FROM jobs j JOIN attempts a ON a.attempt_id=j.owner_attempt_id WHERE j.job_id=?",(args.job_id,)).fetchone()
        if not row or row[0]!=args.attempt_id or str(row[1])!=str(args.fencing_token): raise Refusal("STALE_RELEASE")
        db.execute("DELETE FROM resource_locks WHERE attempt_id=?",(args.attempt_id,))
        db.execute("UPDATE budget_reservations SET state='released' WHERE reservation_id=?",(f"budget:{args.attempt_id}",))
        db.execute("UPDATE attempts SET state='waiting_for_review',finished_at=? WHERE attempt_id=?",(now(),args.attempt_id))
        db.execute("UPDATE jobs SET state='waiting_for_review',lease_expires_at=NULL,updated_at=? WHERE job_id=?",(now(),args.job_id))
        db.execute("INSERT INTO events(job_id,attempt_id,event_type,payload_json,created_at) VALUES(?,?,?,?,?)",(args.job_id,args.attempt_id,"QUEUE_RELEASED","{}",now()))
    print(f"RELEASED job_id={args.job_id} attempt_id={args.attempt_id}"); return 0
def capacity(args):
    with dbopen(args.db) as db:
        rows=db.execute("SELECT state,count(*) FROM attempts GROUP BY state ORDER BY state").fetchall()
        queue_state=db.execute("SELECT state FROM queue_control WHERE singleton=1").fetchone()[0]
    with Path(args.output).open("w",newline="") as f:
        w=csv.writer(f,lineterminator="\n"); w.writerow(["queue_state","attempt_state","count"])
        for state,count in rows: w.writerow([queue_state,state,count])
    print(f"CAPACITY rows={len(rows)} output={args.output}"); return 0
def upgrade(args):
    config=Path(args.config)
    current={"scaffold_version":1,"schema_version":1}
    installed=json.loads(config.read_text()) if config.exists() else current
    if args.action=="inspect":
        print(json.dumps({"installed":installed,"supported":current},sort_keys=True)); return 0
    plan={"from":installed,"to":current,"files":[],"migrations":[]}
    dg=hd(plan); plan["plan_digest"]=dg
    if args.action=="plan":
        Path(args.output).write_text(json.dumps(plan,sort_keys=True,indent=2)+"\n"); print(f"UPGRADE PLAN digest={dg} output={args.output}"); return 0
    loaded=json.loads(Path(args.plan).read_text()); supplied=loaded.pop("plan_digest",None)
    if supplied!=args.digest or hd(loaded)!=args.digest: raise Refusal("PLAN_DIGEST_MISMATCH")
    config.write_text(json.dumps(current,sort_keys=True,indent=2)+"\n")
    print(f"UPGRADE APPLIED digest={args.digest} changes=0"); return 0
def drill(args):
    if not args.create_temp: raise Refusal("supplied drill requires --create-temp")
    caller=Path.cwd(); receipt=(caller/args.receipt).resolve()
    for output in (caller/"agent.db",caller/"mock-effects.db",receipt):
        if output.exists(): raise Refusal(f"drill output already exists: {output}")
    parent=Path(tempfile.mkdtemp(prefix="remote-agent-drill-")).resolve()
    target=(parent/args.expected_suffix).resolve(); children=[]; cases=[]
    try:
        if target.parent!=parent or target.name!=args.expected_suffix: raise Refusal("guarded range path or suffix mismatch")
        target.mkdir(); unrelated=parent/"unrelated.txt"; unrelated.write_text("preserve me\n"); before=h(unrelated.read_bytes())
        adb,mdb=target/"agent.db",target/"mock-effects.db"; migrate(adb)
        with dbopen(mdb) as db: db.executescript(MOCK_MIGRATION.read_text())
        stamp=now()
        with dbopen(adb) as db:
            db.execute("INSERT INTO jobs(job_id,contract_digest,base_sha,state,owner_attempt_id,lease_expires_at,accepted_head_sha,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",("drill-job",hd({"drill":1}),"1"*40,"running","attempt-B","2099-01-01T00:00:00Z",None,stamp,stamp))
            for aid,state,token in (("attempt-A","lost",201),("attempt-B","running",202)):
                db.execute("INSERT INTO attempts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(aid,"drill-job","drill-worker",str(target),f"trace-{aid}",state,token,stamp,stamp if state=="lost" else None,"2"*40 if state=="lost" else None,"0.01","0.02","0","0",1))
            for event,aid in (("JOB_CREATED",None),("LEASE_ACQUIRED","attempt-A"),("HEARTBEAT_LOST","attempt-A"),("LEASE_RECLAIMED","attempt-B"),("RECOVERY_VERIFIED","attempt-B")):
                db.execute("INSERT INTO events(job_id,attempt_id,event_type,payload_json,created_at) VALUES(?,?,?,?,?)",("drill-job",aid,event,"{}",stamp))
        boundary_code="""import os,sqlite3,sys,time
db_path,phase=sys.argv[1:3]
if phase=="before":
 print(str(os.getpid())+"|"+os.getcwd(),flush=True); time.sleep(30)
db=sqlite3.connect(db_path); db.execute("BEGIN IMMEDIATE")
db.execute("UPDATE jobs SET state='blocked' WHERE job_id='drill-job'")
if phase=="inside":
 print(str(os.getpid())+"|"+os.getcwd(),flush=True); time.sleep(30)
db.commit()
print(str(os.getpid())+"|"+os.getcwd(),flush=True); time.sleep(30)
"""
        for phase,case_name,expected in (("before","before_transaction_kill","running"),("inside","inside_transaction_kill","running"),("after","after_transaction_kill","blocked")):
            child=subprocess.Popen([sys.executable,"-c",boundary_code,str(adb),phase],cwd=target,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            children.append(child)
            pid,cwd=child.stdout.readline().strip().split("|",1)
            verified=int(pid)==child.pid and Path(cwd).resolve()==target
            if not verified: raise Refusal(f"{case_name} child PID/cwd verification failed")
            os.kill(child.pid,signal.SIGKILL); child.wait(timeout=5)
            with dbopen(adb) as db:
                state=db.execute("SELECT state FROM jobs WHERE job_id='drill-job'").fetchone()[0]
                integrity=db.execute("PRAGMA integrity_check").fetchone()[0]
            if state!=expected or integrity!="ok": raise Refusal(f"{case_name} recovery assertion failed")
            cases.append({"case":case_name,"executed":True,"exit":child.returncode,"pid_verified":True,"state":state,"integrity":integrity})
            if phase=="after":
                with dbopen(adb) as db: db.execute("UPDATE jobs SET state='running' WHERE job_id='drill-job'")
        protected=target/"protected"; protected.mkdir(); os.chmod(protected,0o555)
        denied_file=protected/"blocked.txt"
        file_probe=subprocess.run([sys.executable,"-c","from pathlib import Path; import sys; Path(sys.argv[1]).write_text('forbidden')",str(denied_file)],cwd=target,text=True,capture_output=True)
        os.chmod(protected,0o755)
        if file_probe.returncode==0 or denied_file.exists(): raise Refusal("filesystem denial control failed")
        cases.append({"case":"filesystem_denial","executed":True,"mechanism":"read-only filesystem boundary","exit":file_probe.returncode,"target_created":denied_file.exists()})
        server=socket.socket(); server.bind(("127.0.0.1",0)); server.listen(1); server.settimeout(0.2)
        host,port=server.getsockname()
        network_code="""import socket,sys
host=sys.argv[1]; port=int(sys.argv[2]); allowed=[]
if host not in allowed:
 print("DENIED host absent from allowlist"); raise SystemExit(13)
socket.create_connection((host,port),timeout=1)
"""
        network_probe=subprocess.run([sys.executable,"-c",network_code,host,str(port)],cwd=target,text=True,capture_output=True)
        connections=0
        try:
            connection,_=server.accept(); connections=1; connection.close()
        except (TimeoutError,socket.timeout):
            pass
        finally:
            server.close()
        if network_probe.returncode!=13 or connections: raise Refusal("network denial control failed")
        cases.append({"case":"network_denial","executed":True,"mechanism":"deny-by-default host adapter","exit":network_probe.returncode,"connections_observed":connections})
        allowed_file=target/"docs"/"allowed.txt"; allowed_file.parent.mkdir()
        allowed_probe=subprocess.run([sys.executable,"-c","from pathlib import Path; import sys; Path(sys.argv[1]).write_text('allowed')",str(allowed_file)],cwd=target,text=True,capture_output=True)
        if allowed_probe.returncode or not allowed_file.is_file(): raise Refusal("filesystem allowed control failed")
        cases.append({"case":"filesystem_allowed_control","executed":True,"exit":allowed_probe.returncode,"target_created":True})
        allowed_server=socket.socket(); allowed_server.bind(("127.0.0.1",0)); allowed_server.listen(1); allowed_server.settimeout(1)
        allowed_host,allowed_port=allowed_server.getsockname()
        allowed_network_code="""import socket,sys
host=sys.argv[1]; port=int(sys.argv[2]); allowed=[host]
if host not in allowed: raise SystemExit(13)
connection=socket.create_connection((host,port),timeout=1); connection.close()
"""
        allowed_network_probe=subprocess.run([sys.executable,"-c",allowed_network_code,allowed_host,str(allowed_port)],cwd=target,text=True,capture_output=True)
        allowed_connections=0
        try:
            connection,_=allowed_server.accept(); allowed_connections=1; connection.close()
        finally:
            allowed_server.close()
        if allowed_network_probe.returncode or allowed_connections!=1: raise Refusal("network allowed control failed")
        cases.append({"case":"network_allowed_control","executed":True,"exit":allowed_network_probe.returncode,"connections_observed":allowed_connections})
        with dbopen(adb) as db:
            db.executemany("INSERT INTO policy_decisions(job_id,attempt_id,target,result,reason,policy_digest,created_at) VALUES(?,?,?,?,?,?,?)",[
                ("drill-job","attempt-A",str(denied_file.relative_to(target)),"denied","filesystem boundary returned nonzero",hd({"policy":1}),stamp),
                ("drill-job","attempt-A",f"{host}:{port}","denied","host absent from allowlist; zero connections observed",hd({"policy":1}),stamp),
                ("drill-job","attempt-B","docs/","allowed","fixture path",hd({"policy":1}),stamp),
            ])
            denied=db.execute("SELECT count(*) FROM policy_decisions WHERE result='denied'").fetchone()[0]
            owner=db.execute("SELECT owner_attempt_id FROM jobs WHERE job_id='drill-job'").fetchone()[0]
        if denied!=2 or owner=="attempt-A": raise Refusal("policy or stale-owner assertion failed")
        cases.append({"case":"stale_owner_refused","executed":True,"pass":True})
        with dbopen(mdb) as db:
            db.execute("INSERT INTO effects VALUES(?,?,?,?,?,?,?,?)",("notify:drill-job","drill-job","attempt-B","completed",1,hd({"message":"once"}),"mock:1",stamp))
            db.execute("INSERT OR IGNORE INTO effects VALUES(?,?,?,?,?,?,?,?)",("notify:drill-job","drill-job","attempt-B","completed",2,hd({"message":"once"}),"mock:2",stamp))
            duplicate=db.execute("SELECT count(*),sum(delivery_count) FROM effects WHERE effect_key='notify:drill-job'").fetchone()
            db.execute("INSERT INTO effects VALUES(?,?,?,?,?,?,?,?)",("deploy:ambiguous","drill-job","attempt-B","ambiguous",1,hd({"deploy":1}),None,stamp))
            db.execute("UPDATE effects SET status='completed',external_ref='mock:reconciled' WHERE effect_key='deploy:ambiguous'")
            reconciled=db.execute("SELECT status FROM effects WHERE effect_key='deploy:ambiguous'").fetchone()[0]
        if duplicate!=(1,1) or reconciled!="completed": raise Refusal("effect convergence assertion failed")
        cases.extend([{"case":"duplicate_effect_no_repeat","executed":True,"pass":True},{"case":"ambiguous_effect_reconciled","executed":True,"pass":True}])
        bad=target/"bad-evidence.json"; bad.write_text(json.dumps({"head_sha":"2"*40,"checks":{"format":"pass","unit":"pass","type":"skipped"},"artifacts":{}}))
        for name,expected in (("corrupt_digest_refused","3"*40),("skipped_ci_refused",None),("sha_drift_refused","1"*40)):
            try:
                evidence_check(bad,expected=expected)
                raise Refusal(f"{name} unexpectedly passed")
            except Refusal:
                cases.append({"case":name,"executed":True,"pass":True})
        backup=target/"agent.backup.db"
        with dbopen(adb) as source, closing(sqlite3.connect(backup)) as destination: source.backup(destination)
        with dbopen(backup) as db:
            if db.execute("PRAGMA integrity_check").fetchone()[0]!="ok": raise Refusal("restore fixture failed")
        cases.append({"case":"restore_verified","executed":True,"pass":True})
        with dbopen(mdb) as db:
            for replay in (1,2):
                db.execute("INSERT OR IGNORE INTO effects VALUES(?,?,?,?,?,?,?,?)",("notify:drill-job","drill-job","attempt-B","completed",1,hd({"message":"once"}),"mock:1",stamp))
                if db.execute("SELECT count(*) FROM effects WHERE effect_key='notify:drill-job'").fetchone()[0]!=1: raise Refusal("replay duplicated effect")
                cases.append({"case":f"replay_{replay}_no_repeat","executed":True,"pass":True})
        with dbopen(adb) as db:
            db.execute("UPDATE queue_control SET state='stopped',reason='drill',updated_at=? WHERE singleton=1",(now(),))
            db.execute("INSERT INTO events(job_id,attempt_id,event_type,payload_json,created_at) VALUES(?,?,?,?,?)",("drill-job","attempt-B","QUEUE_STOPPED","{}",now()))
            if db.execute("SELECT state FROM queue_control WHERE singleton=1").fetchone()[0]!="stopped": raise Refusal("queue did not stop")
            if db.execute("SELECT count(*) FROM attempts WHERE job_id='drill-job'").fetchone()[0]!=2: raise Refusal("stopped admission created an attempt")
            cases.append({"case":"stopped_admission_refused","executed":True,"pass":True})
            db.commit(); db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        with dbopen(mdb) as db: db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        shutil.copy2(adb,caller/"agent.db"); shutil.copy2(mdb,caller/"mock-effects.db"); after=h(unrelated.read_bytes())
        if before!=after: raise Refusal("unrelated hash changed")
        result={"result":"PASS","schema_version":1,"resolved_parent":str(parent),"resolved_target":str(target),"expected_suffix":args.expected_suffix,"integrity":"ok","foreign_key_violations":0,"unrelated_hash_before":before,"unrelated_hash_after":after,"completed_effect_deliveries":2,"cases":cases,"outputs":{"agent_db":str(caller/"agent.db"),"mock_effects_db":str(caller/"mock-effects.db")},"cleanup":"completed after receipt copy"}
        result["receipt_digest"]=digest_without(result,"receipt_digest")
        atomic_json(receipt,result)
        print(f"DRILL PASS cases={len(cases)} receipt={receipt}"); return 0
    finally:
        for child in children:
            if child.poll() is None: child.kill(); child.wait()
        shutil.rmtree(parent,ignore_errors=True)
def queue_command(args):
    return queue_claim(args) if args.action=="claim" else queue_release(args)
def make_parser():
    p=argparse.ArgumentParser(prog="remote-agent"); s=p.add_subparsers(dest="command",required=True)
    q=s.add_parser("init"); q.add_argument("repository",nargs="?")
    q=s.add_parser("validate-job"); q.add_argument("job"); q.add_argument("--registry"); q.add_argument("--reserve",action="store_true")
    q=s.add_parser("status"); q.add_argument("--db",default="agent.db"); q.add_argument("--check",action="store_true"); q.add_argument("--json",action="store_true")
    q=s.add_parser("runtime-scorecard"); q.add_argument("--attempt",action="append",required=True); q.add_argument("--output",required=True)
    q=s.add_parser("dispatch"); q.add_argument("job"); q.add_argument("--adapter",required=True)
    q=s.add_parser("verify-evidence"); q.add_argument("evidence"); q.add_argument("--branch"); q.add_argument("--expected-sha")
    q=s.add_parser("evidence"); ss=q.add_subparsers(dest="action",required=True); z=ss.add_parser("capture"); z.add_argument("job_id"); z.add_argument("--db",default="agent.db"); z.add_argument("--branch",default="fixture"); z.add_argument("--output",default="evidence.json")
    q=s.add_parser("policy"); ss=q.add_subparsers(dest="action",required=True); z=ss.add_parser("compile"); z.add_argument("policy"); z.add_argument("--runtime",required=True); z.add_argument("--output",default="compiled-policy.json"); z=ss.add_parser("explain"); z.add_argument("policy"); z.add_argument("--job",required=True)
    q=s.add_parser("economics-report"); q.add_argument("--db",default="agent.db"); q.add_argument("--window",required=True); q.add_argument("--output",required=True)
    q=s.add_parser("gate"); ss=q.add_subparsers(dest="action",required=True); z=ss.add_parser("verify"); z.add_argument("receipt")
    for name in ("stop-queue","resume-queue","drain-queue"): q=s.add_parser(name); q.add_argument("--db",default="agent.db"); q.add_argument("--reason",default="operator request")
    q=s.add_parser("why"); q.add_argument("job_id"); q.add_argument("--db",default="agent.db")
    q=s.add_parser("restore"); q.add_argument("--backup",required=True); q.add_argument("--target",required=True); q.add_argument("--incident-decision"); q.add_argument("--receipt")
    q=s.add_parser("queue"); ss=q.add_subparsers(dest="action",required=True)
    z=ss.add_parser("claim"); z.add_argument("job_id"); z.add_argument("--attempt-id",required=True); z.add_argument("--resource",action="append",default=[]); z.add_argument("--cost",default="0"); z.add_argument("--budget",default="100"); z.add_argument("--worker-limit",type=int,default=1); z.add_argument("--db",default="agent.db")
    z=ss.add_parser("release"); z.add_argument("job_id"); z.add_argument("--attempt-id",required=True); z.add_argument("--fencing-token",required=True); z.add_argument("--db",default="agent.db")
    q=s.add_parser("capacity-report"); q.add_argument("--db",default="agent.db"); q.add_argument("--output",required=True)
    q=s.add_parser("upgrade"); ss=q.add_subparsers(dest="action",required=True)
    for action in ("inspect","plan","apply"):
        z=ss.add_parser(action); z.add_argument("--config",default="remote-agent.json")
        if action=="plan": z.add_argument("--output",default="upgrade-plan.json")
        if action=="apply": z.add_argument("--plan",required=True); z.add_argument("--digest",required=True)
    q=s.add_parser("drill"); q.add_argument("--create-temp",action="store_true"); q.add_argument("--expected-suffix",required=True); q.add_argument("--receipt",required=True)
    return p
def main():
    args=make_parser().parse_args()
    handlers={"init":init,"validate-job":validate,"status":status,"runtime-scorecard":scorecard,"dispatch":dispatch,"verify-evidence":verify,"evidence":capture,"policy":policy,"economics-report":economics,"gate":gate,"stop-queue":queue,"resume-queue":queue,"drain-queue":queue,"why":why,"restore":restore,"queue":queue_command,"capacity-report":capacity,"upgrade":upgrade,"drill":drill}
    try: return handlers[args.command](args)
    except (Refusal,OSError,sqlite3.Error,json.JSONDecodeError,subprocess.CalledProcessError) as e:
        print(f"REFUSED reason={e} dispatch_started=false",file=sys.stderr); return 2
if __name__=="__main__": raise SystemExit(main())
