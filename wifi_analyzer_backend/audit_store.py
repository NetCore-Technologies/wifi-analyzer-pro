"""Local append-only hash-chained security audit ledger."""
from __future__ import annotations
import hashlib, json, os, re, sqlite3, uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from .site_history import default_history_path

ZERO_HASH = "0" * 64
MAX_AUDIT_LIMIT = 200
_ACTION = re.compile(r"^[a-z][a-z0-9_.-]{1,95}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
_META = {"username","role","permission","required_permission","enabled","adapter_id","schedule_id","error_code","http_status","result_count","changed_fields","reason_code","site_id"}

def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

def _digest(previous, payload):
    return hashlib.sha256(previous.encode("ascii") + b"\n" + _canonical(payload).encode()).hexdigest()

def _time(value):
    if value is None: value = datetime.now(timezone.utc)
    elif isinstance(value, str):
        try: value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc: raise ValueError("occurred_at must be ISO-8601") from exc
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("occurred_at must include a timezone")
    return value.astimezone(timezone.utc).isoformat()

def _metadata(value):
    if value is None: return {}
    if not isinstance(value, dict): raise ValueError("metadata must be an object")
    safe = {}
    for key, item in value.items():
        if key not in _META: continue
        if item is None or isinstance(item, (bool, int)): safe[key] = item
        elif isinstance(item, str): safe[key] = item[:128]
        elif isinstance(item, (list, tuple)):
            safe[key] = [str(x)[:64] for x in item[:20] if isinstance(x, (str, int))]
    if len(_canonical(safe).encode()) > 4096: raise ValueError("metadata too large")
    return safe

class SecurityAuditStore:
    def __init__(self, path=None):
        self.path = Path(path).expanduser() if path else default_history_path().with_name("security-audit.sqlite3")

    @contextmanager
    def _db(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        db = sqlite3.connect(str(self.path), timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("""CREATE TABLE IF NOT EXISTS security_audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
            occurred_at TEXT NOT NULL, request_id TEXT, actor_id TEXT, actor_username TEXT,
            actor_role TEXT, action TEXT NOT NULL, target_type TEXT, target_id TEXT,
            outcome TEXT NOT NULL, metadata_json TEXT NOT NULL, previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL UNIQUE)""")
        db.execute("CREATE INDEX IF NOT EXISTS idx_audit_actor ON security_audit_events(actor_username,id DESC)")
        db.execute("""CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON security_audit_events
            BEGIN SELECT RAISE(ABORT,'security audit events are append-only'); END""")
        db.execute("""CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON security_audit_events
            BEGIN SELECT RAISE(ABORT,'security audit events are append-only'); END""")
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()
            if os.name != "nt" and self.path.exists():
                try: os.chmod(self.path, 0o600)
                except OSError: pass

    @staticmethod
    def _actor(actor):
        if actor is None: return None, None, None
        if not isinstance(actor, dict): raise ValueError("actor must be an identity object")
        uid, name, role = actor.get("id"), actor.get("username"), actor.get("role")
        if uid is not None and (not isinstance(uid,str) or not re.fullmatch(r"[a-f0-9]{32}",uid)): raise ValueError("invalid actor id")
        if name is not None and (not isinstance(name,str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,63}",name)): raise ValueError("invalid actor username")
        if role is not None and role not in {"owner","admin","network_admin","analyst","viewer"}: raise ValueError("invalid actor role")
        return uid,name,role

    def record(self, action, *, actor=None, target_type=None, target_id=None, outcome="success", metadata=None, request_id=None, occurred_at=None):
        if not isinstance(action,str) or not _ACTION.fullmatch(action): raise ValueError("invalid action")
        if target_type is not None and (not isinstance(target_type,str) or not _ACTION.fullmatch(target_type)): raise ValueError("invalid target_type")
        if target_id is not None and (not isinstance(target_id,str) or not _ID.fullmatch(target_id)): raise ValueError("invalid target_id")
        if outcome not in {"success","denied","failure"}: raise ValueError("invalid outcome")
        if request_id is not None and (not isinstance(request_id,str) or not re.fullmatch(r"[A-Za-z0-9._:-]{1,80}",request_id)): raise ValueError("invalid request_id")
        uid,name,role=self._actor(actor)
        payload={"event_id":uuid.uuid4().hex,"occurred_at":_time(occurred_at),"request_id":request_id,"actor_id":uid,"actor_username":name,"actor_role":role,"action":action,"target_type":target_type,"target_id":target_id,"outcome":outcome,"metadata":_metadata(metadata)}
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT event_hash FROM security_audit_events ORDER BY id DESC LIMIT 1").fetchone()
            previous=row["event_hash"] if row else ZERO_HASH
            digest=_digest(previous,payload)
            db.execute("""INSERT INTO security_audit_events
                (event_id,occurred_at,request_id,actor_id,actor_username,actor_role,action,target_type,target_id,outcome,metadata_json,previous_hash,event_hash)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (payload["event_id"],payload["occurred_at"],request_id,uid,name,role,action,target_type,target_id,outcome,_canonical(payload["metadata"]),previous,digest))
            row_id=db.execute("SELECT last_insert_rowid()").fetchone()[0]
        return {"id":row_id,**payload,"previous_hash":previous,"event_hash":digest}

    @staticmethod
    def _row(row):
        return {"id":row["id"],"event_id":row["event_id"],"occurred_at":row["occurred_at"],"request_id":row["request_id"],
            "actor":{"id":row["actor_id"],"username":row["actor_username"],"role":row["actor_role"]} if row["actor_id"] else None,
            "action":row["action"],"target_type":row["target_type"],"target_id":row["target_id"],"outcome":row["outcome"],
            "metadata":json.loads(row["metadata_json"]),"previous_hash":row["previous_hash"],"event_hash":row["event_hash"]}

    def list_events(self, *, limit=50, before_id=None, action=None, outcome=None, actor_username=None):
        if isinstance(limit,bool) or not isinstance(limit,int) or not 1<=limit<=MAX_AUDIT_LIMIT: raise ValueError("limit must be between 1 and 200")
        if before_id is not None and (isinstance(before_id,bool) or not isinstance(before_id,int) or before_id<1): raise ValueError("invalid before_id")
        if action is not None and (not isinstance(action,str) or not _ACTION.fullmatch(action)): raise ValueError("invalid action")
        if outcome is not None and outcome not in {"success","denied","failure"}: raise ValueError("invalid outcome")
        if actor_username is not None and (not isinstance(actor_username,str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,63}",actor_username)): raise ValueError("invalid actor_username")
        clauses,values=[],[]
        for key,value in (("id <",before_id),("action =",action),("outcome =",outcome),("actor_username =",actor_username)):
            if value is not None: clauses.append(key+" ?"); values.append(value)
        where=" WHERE "+" AND ".join(clauses) if clauses else ""
        with self._db() as db: rows=db.execute("SELECT * FROM security_audit_events"+where+" ORDER BY id DESC LIMIT ?",(*values,limit)).fetchall()
        return [self._row(row) for row in rows]

    def verify_chain(self):
        with self._db() as db: rows=db.execute("SELECT * FROM security_audit_events ORDER BY id").fetchall()
        previous=ZERO_HASH; verified=0
        for row in rows:
            payload={"event_id":row["event_id"],"occurred_at":row["occurred_at"],"request_id":row["request_id"],"actor_id":row["actor_id"],"actor_username":row["actor_username"],"actor_role":row["actor_role"],"action":row["action"],"target_type":row["target_type"],"target_id":row["target_id"],"outcome":row["outcome"],"metadata":json.loads(row["metadata_json"])}
            if row["previous_hash"]!=previous or row["event_hash"]!=_digest(previous,payload): break
            previous=row["event_hash"]; verified+=1
        return {"valid":verified==len(rows),"verified_count":verified,"event_count":len(rows),"latest_hash":previous,"tamper_evident_scope":"local_hash_chain"}

    def summary(self):
        with self._db() as db:
            count=db.execute("SELECT COUNT(*) FROM security_audit_events").fetchone()[0]
            latest=db.execute("SELECT occurred_at,event_hash FROM security_audit_events ORDER BY id DESC LIMIT 1").fetchone()
            rows=db.execute("SELECT outcome,COUNT(*) AS count FROM security_audit_events GROUP BY outcome").fetchall()
        return {"event_count":count,"latest_event_at":latest["occurred_at"] if latest else None,"latest_hash":latest["event_hash"] if latest else ZERO_HASH,"counts_by_outcome":{r["outcome"]:r["count"] for r in rows}}
