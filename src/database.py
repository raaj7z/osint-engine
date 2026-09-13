from __future__ import annotations
import json, os, sqlite3, uuid
from datetime import datetime, timezone
from typing import Any
from .models import InvestigationInput, InvestigationResult, Identifier

class OSINTDatabase:
    """Additive SQLite adapter over the crawler's existing database."""
    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or os.getenv("OSINT_DB_PATH", "data/crawler.db")
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=30000")
        self.conn.execute("PRAGMA foreign_keys=ON")

    def close(self): self.conn.close()
    @staticmethod
    def _now(): return datetime.now(timezone.utc).isoformat()
    @staticmethod
    def _json(v): return json.dumps(v, ensure_ascii=False, default=str)

    def migrate(self, schema_path: str):
        with open(schema_path, "r", encoding="utf-8") as f: self.conn.executescript(f.read())
        self.conn.commit()

    def create_investigation(self, target: str, target_type: str, source="manual", notes=None, actor_id=None):
        iid = str(uuid.uuid4()); actor_id = actor_id or f"actor-{uuid.uuid4().hex[:12]}"
        self.conn.execute("INSERT INTO sessions (session_id,target_username,urls_crawled,status) VALUES (?,?,?,'running')",
                          (iid, target, self._json([target]) if target_type == "url" else "[]"))
        self.conn.execute("INSERT INTO investigations (session_id,target_username,status,results) VALUES (?,?,'running',?)",
                          (iid, target, self._json({"source":source,"target_type":target_type,"notes":notes})))
        self.conn.execute("INSERT INTO actors (id,investigation_id,display_name,category,confidence_level) VALUES (?,? ,?,'unknown','insufficient')",
                          (actor_id, iid, target))
        self.conn.execute("INSERT INTO identifiers (investigation_id,actor_id,type,value,normalized_value,source) VALUES (?,?,?,?,?,?)",
                          (iid, actor_id, target_type, target, target.strip().lower(), source))
        self.conn.commit(); return iid, actor_id

    def get_crawler_investigation(self, crawler_investigation_id: int):
        r = self.conn.execute("SELECT * FROM investigations WHERE id=?", (crawler_investigation_id,)).fetchone()
        return dict(r) if r else None

    def ensure_actor_for_investigation(self, iid: str, display_name=None):
        r = self.conn.execute("SELECT id FROM actors WHERE investigation_id=? ORDER BY created_at LIMIT 1", (iid,)).fetchone()
        if r: return r[0]
        aid=f"actor-{uuid.uuid4().hex[:12]}"
        self.conn.execute("INSERT INTO actors (id,investigation_id,display_name,category,confidence_level) VALUES (?,? ,?,'unknown','insufficient')", (aid,iid,display_name)); self.conn.commit(); return aid

    def get_identifiers_from_crawler(self, iid: str):
        out=[]
        r=self.conn.execute("SELECT target_username FROM sessions WHERE session_id=?",(iid,)).fetchone()
        if r and r[0]: out.append(Identifier(type="username",value=r[0],source="crawler"))
        for r in self.conn.execute("SELECT username,source_url FROM usernames WHERE session_id=?",(iid,)):
            if r[0]: out.append(Identifier(type="username",value=r[0],source="crawler",source_url=r[1]))
        for r in self.conn.execute("SELECT currency,address,source_url FROM crypto_addresses WHERE session_id=?",(iid,)):
            if r[1]: out.append(Identifier(type="crypto",value=r[1],source="crawler",source_url=r[2]))
        for r in self.conn.execute("SELECT target_url,source_url FROM links WHERE session_id=?",(iid,)):
            if r[0]: out.append(Identifier(type="url" if "://" in r[0] else "domain",value=r[0],source="crawler",source_url=r[1]))
        seen=set(); result=[]
        for x in out:
            k=(x.type,x.value.strip().lower())
            if k not in seen: seen.add(k); result.append(x)
        return result

    def register_identifiers(self, iid: str, actor_id: str | None, identifiers):
        for item in identifiers:
            self.conn.execute(
                "INSERT INTO identifiers (investigation_id,actor_id,type,value,normalized_value,source,source_url,confidence) VALUES (?,?,?,?,?,?,?,?)",
                (iid, actor_id, item.type, item.value, item.value.strip().lower(), getattr(item, "source", "crawler"), getattr(item, "source_url", None), getattr(item, "confidence", 0.5)),
            )
        self.conn.commit()

    def save_investigation(self, result: InvestigationResult):
        iid=result.investigation_id; aid=result.actor_id or self.ensure_actor_for_investigation(iid)
        for f in result.findings:
            cur=self.conn.execute("""INSERT INTO findings
                (investigation_id,actor_id,finding_type,value,normalized_value,source,source_url,confidence,first_seen,last_seen,metadata)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""", (iid,aid,f.finding_type,f.value,f.value.strip().lower(),f.source,f.source_url,f.confidence,
                getattr(f,"first_seen",None),getattr(f,"last_seen",None),self._json(getattr(f,"metadata",None) or {})))
            fid=cur.lastrowid
            for e in getattr(f,"evidence",[]) or []:
                self.conn.execute("""INSERT INTO evidence
                (investigation_id,finding_id,source_url,title,excerpt,content_hash,collected_at,metadata)
                VALUES (?,?,?,?,?,?,?,?)""", (iid,fid,getattr(e,"source_url",None),getattr(e,"title",None),getattr(e,"excerpt",None),
                getattr(e,"hash_sha256",None),getattr(e,"collected_at",None),self._json(getattr(e,"metadata",None) or {})))
        self.conn.execute("UPDATE investigations SET status='completed',results=?,confidence_score=?,completed_at=? WHERE session_id=?",
                          (self._json({"errors":result.errors,"finding_count":len(result.findings)}),max((f.confidence for f in result.findings),default=0.0),
                           result.completed_at.isoformat() if result.completed_at else self._now(),iid))
        self.conn.execute("UPDATE sessions SET status='completed',completed_at=? WHERE session_id=?",(result.completed_at.isoformat() if result.completed_at else self._now(),iid)); self.conn.commit()

    def list_investigations(self,limit=50):
        return [dict(r) for r in self.conn.execute("SELECT session_id AS investigation_id,target_username AS target,status,started_at,completed_at,confidence_score FROM investigations ORDER BY started_at DESC LIMIT ?",(limit,)).fetchall()]

    def get_investigation(self,iid):
        r=self.conn.execute("SELECT * FROM investigations WHERE session_id=?",(iid,)).fetchone()
        if not r:return None
        d=dict(r); d["findings"]=[dict(x) for x in self.conn.execute("SELECT * FROM findings WHERE investigation_id=? ORDER BY created_at",(iid,)).fetchall()]
        d["identifiers"]=[dict(x) for x in self.conn.execute("SELECT * FROM identifiers WHERE investigation_id=? ORDER BY created_at",(iid,)).fetchall()]; return d

    def create_job(self,iid,job_type):
        jid=str(uuid.uuid4()); self.conn.execute("INSERT INTO jobs (id,investigation_id,job_type,status) VALUES (?,?,?,'queued')",(jid,iid,job_type)); self.conn.commit(); return jid
    def update_job(self,jid,status,progress=None,error=None):
        self.conn.execute("""UPDATE jobs SET status=?,progress=COALESCE(?,progress),error=?,
        started_at=CASE WHEN ?='running' AND started_at IS NULL THEN ? ELSE started_at END,
        completed_at=CASE WHEN ? IN ('completed','failed') THEN ? ELSE completed_at END WHERE id=?""",
        (status,progress,error,status,self._now(),status,self._now(),jid)); self.conn.commit()
    def add_job_event(self,jid,iid,event_type,message,level="info",metadata=None):
        self.conn.execute("INSERT INTO job_events (job_id,investigation_id,level,event_type,message,metadata) VALUES (?,?,?,?,?,?)",
                          (jid,iid,level,event_type,message,self._json(metadata or {}))); self.conn.commit()
    def get_job(self,jid):
        r=self.conn.execute("SELECT * FROM jobs WHERE id=?",(jid,)).fetchone(); return dict(r) if r else None
    def get_job_events(self,jid,after_id=0):
        return [dict(r) for r in self.conn.execute("SELECT * FROM job_events WHERE job_id=? AND id>? ORDER BY id",(jid,after_id)).fetchall()]
