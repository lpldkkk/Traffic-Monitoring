"""Revision-pinned investigation jobs. No networking or API credentials here."""
from contextlib import contextmanager
import json
import math
import os
import time
import uuid

import psutil

from .baseline import Baseline, similar_connections
from .incidents import encoded, identity
from .investigation import STEPS

STATUSES = ('queued', 'running', 'completed', 'partial', 'retry_wait', 'blocked_budget', 'failed', 'cancelled')
TERMINAL = {'completed', 'partial', 'failed', 'cancelled'}


def create_schema(db):
    sql = """
    CREATE TABLE IF NOT EXISTS investigation_jobs(
      job_id TEXT PRIMARY KEY,event_id TEXT NOT NULL REFERENCES incidents(event_id) ON DELETE CASCADE,
      event_revision INTEGER NOT NULL,status TEXT NOT NULL CHECK(status IN
        ('queued','running','completed','partial','retry_wait','blocked_budget','failed','cancelled')),
      priority INTEGER NOT NULL,created_at REAL NOT NULL,started_at REAL,updated_at REAL NOT NULL,
      completed_at REAL,current_step TEXT NOT NULL,attempt_count INTEGER NOT NULL DEFAULT 0,
      next_retry_at REAL,error_summary TEXT,budget_state TEXT NOT NULL,
      max_attempts INTEGER NOT NULL,max_steps INTEGER NOT NULL,max_tools INTEGER NOT NULL,
      max_seconds REAL NOT NULL,tool_calls INTEGER NOT NULL DEFAULT 0,
      snapshot TEXT NOT NULL,checkpoint TEXT NOT NULL,UNIQUE(event_id,event_revision));
    CREATE INDEX IF NOT EXISTS job_queue ON investigation_jobs(status,next_retry_at,created_at);
    CREATE TABLE IF NOT EXISTS investigation_steps(
      step_id TEXT PRIMARY KEY,job_id TEXT NOT NULL REFERENCES investigation_jobs(job_id) ON DELETE CASCADE,
      step_type TEXT NOT NULL,status TEXT NOT NULL,input_reference TEXT NOT NULL,output_reference TEXT,
      started_at REAL NOT NULL,completed_at REAL,error_summary TEXT,attempt INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS job_step ON investigation_steps(job_id,started_at,step_id);
    CREATE TABLE IF NOT EXISTS investigation_reports(
      report_id TEXT PRIMARY KEY,job_id TEXT NOT NULL REFERENCES investigation_jobs(job_id) ON DELETE CASCADE,
      attempt INTEGER NOT NULL,created_at REAL NOT NULL,report TEXT NOT NULL,UNIQUE(job_id,attempt));
    CREATE TABLE IF NOT EXISTS investigation_sources(
      job_id TEXT NOT NULL REFERENCES investigation_jobs(job_id) ON DELETE CASCADE,
      session_id TEXT NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,PRIMARY KEY(job_id,session_id));
    CREATE TABLE IF NOT EXISTS investigation_worker(
      id INTEGER PRIMARY KEY CHECK(id=1),owner TEXT NOT NULL,pid INTEGER NOT NULL,process_created REAL NOT NULL);
    """
    for statement in sql.split(';'):
        if statement.strip(): db.execute(statement)


class JobStopped(Exception):
    pass


class BudgetBlocked(Exception):
    pass


class LimitReached(Exception):
    pass


class JobStore:
    def __init__(self, store):
        self.store, self.db = store, store.db

    @contextmanager
    def transaction(self):
        with self.store.lock:
            if self.db.in_transaction:
                raise RuntimeError('调查任务需要独立事务')
            with self.db:
                self.db.execute('BEGIN IMMEDIATE')
                yield

    def _row(self, job_id):
        row = self.db.execute('SELECT * FROM investigation_jobs WHERE job_id=?',(job_id,)).fetchone()
        if row is None: raise JobStopped('任务或源数据已删除')
        return dict(row)

    def get(self, job_id, details=True):
        with self.store.lock:
            row = self._row(job_id)
            for field in ('budget_state','snapshot','checkpoint'):
                if field != 'budget_state' and not details: row.pop(field)
                else: row[field] = json.loads(row[field])
            return row

    def list(self, status=None, page=1, page_size=50):
        if status is not None and status not in STATUSES: raise ValueError('无效任务状态')
        if type(page) is not int or page<1 or not 1<=page_size<=100: raise ValueError('无效分页')
        where, args = (' WHERE status=?',[status]) if status else ('',[])
        with self.store.lock:
            total=self.db.execute('SELECT count(*) FROM investigation_jobs'+where,args).fetchone()[0]
            ids=[r[0] for r in self.db.execute('SELECT job_id FROM investigation_jobs'+where+
                ' ORDER BY created_at DESC,job_id LIMIT ? OFFSET ?',(*args,page_size,(page-1)*page_size))]
            return dict(items=[self.get(i,False) for i in ids],total=total,page=page,pages=max(1,math.ceil(total/page_size)))

    def _snapshot(self, event_id, max_tools):
        """Freeze bounded, redacted evidence in the enqueue transaction.

        Connection/application facts come from the incident revision's saved
        finding, NOT the changing live metric. History is frozen at enqueue.
        """
        event = self.store.incidents.get_event(event_id)
        members = self.store.incidents.members(event_id,page_size=50)
        timeline = self.store.incidents.timeline(event_id,page_size=50)
        total_connections = self.db.execute('''SELECT count(*) FROM (SELECT DISTINCT f.session_id,f.connection_id
            FROM incident_members m JOIN incident_findings f USING(finding_id) WHERE m.event_id=?)''',(event_id,)).fetchone()[0]
        limit = max(1,min(5,(max_tools-3)//6))
        selected=[]; seen=set()
        # Rank all members in SQL before bounding the evidence preparation work.
        rows=self.db.execute('''SELECT f.* FROM incident_members m JOIN incident_findings f USING(finding_id)
            WHERE m.event_id=? ORDER BY CASE f.state WHEN 'active' THEN 0 ELSE 1 END,
            f.original_score DESC,f.first_seen,f.finding_id''',(event_id,))
        for raw in rows:
            pair=(raw['session_id'],raw['connection_id'])
            if pair not in seen:
                seen.add(pair); selected.append(self.store.incidents._finding(raw))
            if len(selected)>=limit: break
        cutoff=time.time()
        snapshot=dict(event_id=event_id,event_revision=event['revision'],cutoff=cutoff,
            observation_range=dict(first_seen=event['first_seen'],last_seen=event['last_seen']),
            total_connections=total_connections,selected_connections=[],entries=[],omissions=[],sources=[])
        def add(name,args,data=None,error=None):
            key=identity('query_',name,args)
            if any(e['key']==key for e in snapshot['entries']): return
            result=dict(ok=error is None,evidence_id=identity('ev_',event_id,event['revision'],key)[:15],
                event_id=event_id,event_revision=event['revision'],data_cutoff=cutoff,source='frozen_incident_revision',
                **({'error':error} if error else {'data':data}))
            snapshot['entries'].append(dict(key=key,name=name,arguments=args,result=result))
        add('get_incident',{},event)
        add('query_incident_members',{},members)
        add('query_incident_timeline',{},timeline)
        if members['pages']>1: snapshot['omissions'].append('事件成员仅冻结前50条线索')
        if timeline['pages']>1: snapshot['omissions'].append('时间线仅冻结前50条，未穷尽全部时间线')
        if total_connections>len(selected): snapshot['omissions'].append(f'仅调查{len(selected)}/{total_connections}条连接')
        profiles={}
        sources={r[0] for r in self.db.execute('''SELECT DISTINCT f.session_id FROM incident_members m
            JOIN incident_findings f USING(finding_id) WHERE m.event_id=?''',(event_id,))}
        for f in selected:
            sid,cid=f['session_id'],f['connection_id']; args=dict(session_id=sid,connection_id=cid)
            source=dict(session_id=sid,source_kind=f['data']['source_kind'])
            if source not in snapshot['sources']: snapshot['sources'].append(source)
            snapshot['selected_connections'].append(args)
            connection=f['data']['connection']
            add('query_connection',args,{**args,**connection})
            app=f['data']['application']
            if len(app['observations'])>20:
                app={**app,'observations':app['observations'][:20]}
                snapshot['omissions'].append('应用身份仅冻结前20条：'+cid)
            add('query_application_identity',args,{**args,**app})
            add('query_anomaly_evidence',args,dict(**args,finding_id=f['finding_id'],state=f['state'],
                original_score=f['original_score'],risk_level=f['risk_level'],rule_code=f['rule_code'],
                detector_version=f['detector_version'],score_scope=f['data']['score_scope'],
                trigger=f['data']['trigger'],uncertainty_flags=f['data']['uncertainty_flags'],
                evidence_references=f['data']['evidence_references']))
            for name in ('query_connection_baseline','query_similar_sessions'):
                try:
                    if sid not in profiles:
                        profiles[sid]=self.store._historical_profiles(sid)
                        for profile in profiles[sid]:
                            source_id=self.db.execute('SELECT id FROM capture_sessions WHERE number=?',(profile['number'],)).fetchone()
                            if source_id: sources.add(source_id[0])
                    if name=='query_connection_baseline':
                        baseline=Baseline(profiles[sid])
                        value=dict(**args,baseline=baseline.summary(),connection_comparison=baseline.compare(connection),
                            scope='用事件revision冻结的连接指标比较入队时可用历史；不比较变化中的整次采集连接速率')
                    else:
                        value=similar_connections(connection,profiles[sid],5)
                        value.update(**args,historical_capture_count=len(profiles[sid]),
                                     status='available' if value['matches'] else 'insufficient_evidence')
                    add(name,args,value)
                except Exception as exc:
                    add(name,args,error='冻结历史证据失败：'+type(exc).__name__)
            for eid in f['data']['evidence_references'][:1]:
                value=self.store.incidents.evidence(event_id,eid,page_size=50)
                add('query_incident_evidence',dict(evidence_id=eid),value)
                if value['pages']>1: snapshot['omissions'].append('评分上下文仅冻结前50条：'+eid)
        snapshot['source_session_ids']=sorted(sources)
        from .agent import redact_text
        return json.loads(redact_text(encoded(snapshot),self.store))

    def enqueue(self, event_id, config, revision=None, max_attempts=3, max_seconds=180, cost_limit=.25):
        config.validate()
        if type(max_attempts) is not int or not 1<=max_attempts<=5: raise ValueError('最大尝试次数为1到5')
        if not math.isfinite(max_seconds) or not 1<=max_seconds<=600: raise ValueError('执行时间为1到600秒')
        if not math.isfinite(cost_limit) or cost_limit<=0: raise ValueError('任务预算必须为正数')
        with self.transaction():
            event=self.store.incidents._authorize(event_id,None)
            version=event['revision'] if revision is None else revision
            old=self.db.execute('SELECT job_id FROM investigation_jobs WHERE event_id=? AND event_revision=?',(event_id,version)).fetchone()
            if old: return self.get(old[0],False)
            if version != event['revision']: raise ValueError('旧revision尚未冻结，不能用当前证据伪造历史任务')
            snapshot=self._snapshot(event_id,config.max_tools)
            if len(encoded(snapshot).encode('utf-8'))>4*1024*1024:
                raise ValueError('事件冻结证据超过4MiB上限，未创建任务；需缩小调查范围')
            job_id=identity('job_',event_id,version); now=time.time()
            budget=dict(limit=min(cost_limit,config.max_cost),reserved=0.,reported=0.,unknown_requests=0)
            self.db.execute('''INSERT INTO investigation_jobs(job_id,event_id,event_revision,status,priority,created_at,
                updated_at,current_step,budget_state,max_attempts,max_steps,max_tools,max_seconds,snapshot,checkpoint)
                VALUES(?,?,?,'queued',?,?,?,'等待调查',?,?,?,?,?,?,'[]')''',
                (job_id,event_id,version,event['risk_score'],now,now,encoded(budget),max_attempts,
                 config.max_steps,config.max_tools,max_seconds,encoded(snapshot)))
            # Track actual incident/history dependencies; deleting an unrelated
            # capture must not erase this report. Delete derived copies of a
            # referenced capture when the user removes that source data.
            self.db.executemany('INSERT INTO investigation_sources VALUES(?,?)',
                                [(job_id,sid) for sid in snapshot['source_session_ids']])
            return self.get(job_id,False)

    def invalidate_source(self, session_id):
        """Caller owns the capture deletion/filter transaction."""
        self.db.execute('DELETE FROM investigation_jobs WHERE job_id IN (SELECT job_id FROM investigation_sources WHERE session_id=?)',(session_id,))

    def discovery_candidates(self):
        with self.store.lock:
            count=self.db.execute("SELECT count(*) FROM investigation_jobs WHERE status IN ('queued','running','retry_wait','blocked_budget')").fetchone()[0]
            return [dict(r) for r in self.db.execute("""SELECT event_id,revision FROM incidents e
                WHERE severity='high' AND status!='closed' AND NOT EXISTS(SELECT 1 FROM investigation_jobs j
                  WHERE j.event_id=e.event_id AND (j.event_revision=e.revision OR j.created_at>?))
                ORDER BY e.updated_at,e.event_id LIMIT ?""",(time.time()-60,min(20,max(0,200-count))))]

    def acquire_worker(self, owner):
        with self.transaction():
            row=self.db.execute('SELECT * FROM investigation_worker WHERE id=1').fetchone()
            if row and row['owner']!=owner:
                try:
                    if abs(psutil.Process(row['pid']).create_time()-row['process_created'])<.01:
                        return False
                except psutil.NoSuchProcess: pass
                except psutil.AccessDenied: return False
            self.db.execute('INSERT OR REPLACE INTO investigation_worker VALUES(1,?,?,?)',
                            (owner,os.getpid(),psutil.Process().create_time()))
            self._recover()
            return True

    def release_worker(self, owner):
        with self.transaction():
            self.db.execute('DELETE FROM investigation_worker WHERE owner=?',(owner,))

    def recover_worker(self,owner):
        with self.transaction():
            if not self.db.execute('SELECT 1 FROM investigation_worker WHERE owner=?',(owner,)).fetchone():
                raise RuntimeError('没有执行器恢复权限')
            self._recover()

    def _recover(self):
        for row in self.db.execute("SELECT * FROM investigation_jobs WHERE status='running'").fetchall():
            unknown=self.db.execute("SELECT 1 FROM investigation_steps WHERE job_id=? AND step_type='model' AND status IN ('running','unknown') AND attempt=?",(row['job_id'],row['attempt_count'])).fetchone()
            if unknown:
                self._finish(row['job_id'],'partial','模型请求结果未知，需人工确认后重试')
            else:
                self.db.execute("UPDATE investigation_steps SET status='retryable',error_summary='只读查询中断，可安全恢复' WHERE job_id=? AND status='running'",(row['job_id'],))
                exhausted=row['attempt_count']>=row['max_attempts']
                self._finish(row['job_id'],'failed' if exhausted else 'retry_wait','进程中断；已成功步骤保留',retry_at=time.time())

    def claim(self, owner, now=None):
        now=time.time() if now is None else now
        with self.transaction():
            if not self.db.execute('SELECT 1 FROM investigation_worker WHERE owner=?',(owner,)).fetchone():
                raise RuntimeError('没有调查执行器所有权')
            if self.db.execute("SELECT 1 FROM investigation_jobs WHERE status='running'").fetchone(): return None
            # Equivalent to unbounded aging by one priority point per minute.
            # Older low-priority work eventually beats any newly arriving job.
            row=self.db.execute("""SELECT job_id FROM investigation_jobs WHERE status IN ('queued','retry_wait')
                AND (next_retry_at IS NULL OR next_retry_at<=?) AND attempt_count<max_attempts
                ORDER BY priority+(?-created_at)/60.0 DESC,created_at,job_id LIMIT 1""",(now,now)).fetchone()
            if not row: return None
            self.db.execute("""UPDATE investigation_jobs SET status='running',started_at=?,updated_at=?,completed_at=NULL,
                current_step='恢复调查',attempt_count=attempt_count+1,next_retry_at=NULL,error_summary=NULL WHERE job_id=?""",(now,now,row[0]))
            return self.get(row[0])

    def ensure_running(self, job_id):
        with self.store.lock:
            if self._row(job_id)['status']!='running': raise JobStopped('任务已取消或暂停')

    def checkpoint(self, job_id, messages):
        with self.transaction():
            self.ensure_running(job_id)
            self.db.execute('UPDATE investigation_jobs SET checkpoint=?,updated_at=? WHERE job_id=?',
                            (encoded(messages),time.time(),job_id))

    def begin_query(self, job_id, entry, current_limit=None):
        with self.transaction():
            self.ensure_running(job_id); job=self._row(job_id)
            if job['tool_calls']>=min(job['max_tools'],current_limit or job['max_tools']): raise LimitReached('任务工具调用上限')
            sid=identity('step_',job_id,entry['key'])
            saved=self.db.execute('SELECT * FROM investigation_steps WHERE step_id=?',(sid,)).fetchone()
            self.db.execute('UPDATE investigation_jobs SET tool_calls=tool_calls+1,current_step=?,updated_at=? WHERE job_id=?',
                            (entry['name'],time.time(),job_id))
            if saved and saved['status']=='completed': return sid,json.loads(saved['output_reference'])
            self.db.execute('''INSERT INTO investigation_steps VALUES(?,?,'query','running',?,NULL,?,NULL,NULL,?)
                ON CONFLICT(step_id) DO UPDATE SET status='running',started_at=excluded.started_at,completed_at=NULL,error_summary=NULL,attempt=excluded.attempt''',
                (sid,job_id,encoded(dict(key=entry['key'],name=entry['name'],arguments=entry['arguments'])),time.time(),job['attempt_count']))
            return sid,None

    def finish_query(self, job_id, step_id, result, messages):
        with self.transaction():
            self.ensure_running(job_id)
            self.db.execute('UPDATE investigation_steps SET status=?,output_reference=?,completed_at=?,error_summary=? WHERE step_id=? AND job_id=?',
                ('completed' if result['ok'] else 'failed',encoded(result),time.time(),None if result['ok'] else result['error'],step_id,job_id))
            self.db.execute('UPDATE investigation_jobs SET checkpoint=?,updated_at=? WHERE job_id=?',(encoded(messages),time.time(),job_id))

    def begin_model(self, job_id, amount, config):
        with self.transaction():
            self.ensure_running(job_id); job=self._row(job_id); budget=json.loads(job['budget_state'])
            n=self.db.execute("SELECT count(*) FROM investigation_steps WHERE job_id=? AND step_type='model' AND attempt=?",(job_id,job['attempt_count'])).fetchone()[0]
            if n>=min(job['max_steps'],config.max_steps): raise LimitReached('本次尝试达到模型步数上限')
            if budget['reserved']+amount>budget['limit']: raise BudgetBlocked('任务费用预留上限')
            # Same SQL/meaning as Store.reserve, in the SAME transaction as the
            # durable request marker and per-job ledger; no nested commits.
            if not self.db.execute('UPDATE budget SET calls=calls+1,reserved=reserved+? WHERE id=1 AND reserved+?<=?',(amount,amount,config.max_cost)).rowcount:
                raise BudgetBlocked('共享费用预留上限')
            budget['reserved']+=amount
            sid='model_'+uuid.uuid4().hex
            self.db.execute("INSERT INTO investigation_steps VALUES(?,?,'model','running',?,NULL,?,NULL,NULL,?)",
                (sid,job_id,encoded(dict(reservation=amount,model=config.model,provider=config.base_url)),time.time(),job['attempt_count']))
            self.db.execute("UPDATE investigation_jobs SET budget_state=?,current_step='模型请求',updated_at=? WHERE job_id=?",(encoded(budget),time.time(),job_id))
            return sid

    def finish_model(self, job_id, step_id, response, messages, cost=None):
        with self.transaction():
            job=self._row(job_id); budget=json.loads(job['budget_state'])
            row=self.db.execute('SELECT * FROM investigation_steps WHERE step_id=? AND job_id=?',(step_id,job_id)).fetchone()
            if row['status']=='completed': return
            reserved=json.loads(row['input_reference'])['reservation']
            if cost is not None:
                extra=max(0,cost-reserved); budget['reserved']+=extra; budget['reported']+=cost
                self.db.execute('UPDATE budget SET reserved=reserved+?,reported=reported+? WHERE id=1',(extra,cost))
            self.db.execute("UPDATE investigation_steps SET status='completed',output_reference=?,completed_at=? WHERE step_id=?",(encoded(response),time.time(),step_id))
            self.db.execute('UPDATE investigation_jobs SET budget_state=?,checkpoint=?,updated_at=? WHERE job_id=?',
                            (encoded(budget),encoded(messages),time.time(),job_id))

    def model_error(self, job_id, step_id, summary, unknown):
        with self.transaction():
            self.db.execute('UPDATE investigation_steps SET status=?,error_summary=?,completed_at=? WHERE step_id=? AND job_id=?',
                ('unknown' if unknown else 'failed',summary,time.time(),step_id,job_id))
            if unknown:
                row=self._row(job_id); budget=json.loads(row['budget_state']); budget['unknown_requests']+=1
                self.db.execute('UPDATE investigation_jobs SET budget_state=? WHERE job_id=?',(encoded(budget),job_id))

    def steps(self, job_id):
        with self.store.lock:
            self._row(job_id)
            rows=[dict(r) for r in self.db.execute('SELECT * FROM investigation_steps WHERE job_id=? ORDER BY started_at,step_id',(job_id,))]
            for row in rows:
                for k in ('input_reference','output_reference'):
                    if row[k]: row[k]=json.loads(row[k])
            return rows

    def _finish(self, job_id, status, error=None, report=None, retry_at=None):
        from .investigation import event_report
        row=self.get(job_id)
        if row['status']=='cancelled': status='cancelled'
        if status=='cancelled':
            self.db.execute("UPDATE investigation_steps SET status='cancelled',completed_at=?,error_summary='用户取消只读步骤' WHERE job_id=? AND step_type='query' AND status='running'",(time.time(),job_id))
        else:
            self.db.execute("UPDATE investigation_steps SET status='retryable',completed_at=?,error_summary='只读步骤未完成，可安全重试' WHERE job_id=? AND step_type='query' AND status='running'",(time.time(),job_id))
        unresolved=self.db.execute("SELECT count(*) FROM investigation_steps WHERE job_id=? AND step_type='model' AND status='running'",(job_id,)).fetchone()[0]
        if unresolved:
            self.db.execute("UPDATE investigation_steps SET status='unknown',error_summary='请求已标记发出，但响应未持久化' WHERE job_id=? AND step_type='model' AND status='running'",(job_id,))
            row['budget_state']['unknown_requests']+=unresolved
            self.db.execute('UPDATE investigation_jobs SET budget_state=? WHERE job_id=?',(encoded(row['budget_state']),job_id))
        report=report or event_report(row,self.steps(job_id),None,error)
        if status=='completed' and report['调查完成状态']!='completed':
            raise ValueError('缺少通过校验的完整报告，不能标记completed')
        report['调查完成状态']=status
        self.db.execute('''INSERT OR IGNORE INTO investigation_reports VALUES(?,?,?,?,?)''',
            (identity('report_',job_id,row['attempt_count']),job_id,row['attempt_count'],time.time(),encoded(report)))
        self.db.execute('''UPDATE investigation_jobs SET status=?,current_step=?,updated_at=?,completed_at=?,
            next_retry_at=?,error_summary=? WHERE job_id=?''',(status,status,time.time(),time.time() if status in TERMINAL else None,retry_at,error,job_id))

    def finish(self, job_id, status, error=None, report=None, retry_at=None):
        if status not in STATUSES or status in {'queued','running'}: raise ValueError('无效完成状态')
        with self.transaction():
            self.ensure_running(job_id)
            self._finish(job_id,status,error,report,retry_at)

    def cancel(self, job_id):
        with self.transaction():
            row=self._row(job_id)
            if row['status'] in TERMINAL: return self.get(job_id,False)
            self._finish(job_id,'cancelled','用户取消；已发出的模型请求可能仍产生费用')
            return self.get(job_id,False)

    def retry(self, job_id, confirm_unknown=False, cost_limit=None):
        with self.transaction():
            row=self.get(job_id)
            if row['status'] not in {'partial','failed','blocked_budget','retry_wait'}: raise ValueError('此状态不能重试')
            if row['attempt_count']>=row['max_attempts']: raise ValueError('已达到最大尝试次数')
            if row['budget_state']['unknown_requests'] and not confirm_unknown:
                raise ValueError('存在结果未知的模型请求；重试可能重复计费，需要明确确认')
            if cost_limit is not None:
                if not math.isfinite(cost_limit) or cost_limit<=0: raise ValueError('任务预算必须为正数')
                row['budget_state']['limit']=cost_limit
            messages=row['checkpoint']
            # Pending tool calls are resumed before this user reminder is added.
            if messages and messages[-1].get('role')=='assistant' and not messages[-1].get('tool_calls'):
                messages.append({'role':'user','content':'继续此冻结范围的调查，复用已取得证据，补齐未完成步骤并输出结构化结果。'})
            self.db.execute("""UPDATE investigation_jobs SET status='queued',next_retry_at=NULL,completed_at=NULL,
                current_step='等待重试',updated_at=?,error_summary=NULL,budget_state=?,checkpoint=? WHERE job_id=?""",
                (time.time(),encoded(row['budget_state']),encoded(messages),job_id))
            return self.get(job_id,False)

    def reports(self, job_id):
        with self.store.lock:
            self._row(job_id)
            return [dict(report_id=r['report_id'],attempt=r['attempt'],created_at=r['created_at'],report=json.loads(r['report']))
                    for r in self.db.execute('SELECT * FROM investigation_reports WHERE job_id=? ORDER BY attempt',(job_id,))]
