"""Scripted Function Calling tests: no paid API or LLM quality claim."""
from contextlib import closing
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'.runtime'))
import test_jobs as fixtures
from traffic_agent.agent import Agent, ModelHTTPError
from traffic_agent.config import Config
from traffic_agent.investigation import SafeModelRetry
from traffic_agent.runtime import InvestigationRuntime
from traffic_agent.store import Store
from traffic_agent.tools import EventToolset


class ScriptModel:
    def __init__(self,hook=None,bad_fact=False):
        self.calls=0; self.hook=hook; self.bad_fact=bad_fact; self.bodies=[]
    def complete(self,config,key,body):
        self.calls+=1; self.bodies.append(json.loads(json.dumps(body)))
        if self.hook: self.hook(self.calls)
        request=json.loads(body['messages'][1]['content'])
        issued={(c['function']['name'],json.dumps(json.loads(c['function']['arguments']),sort_keys=True))
                for m in body['messages'] for c in m.get('tool_calls',[])}
        remaining=[q for q in request['required_queries'] if (q['name'],json.dumps(q['arguments'],sort_keys=True)) not in issued]
        if remaining:
            message={'role':'assistant','content':None,'tool_calls':[{'id':f'call_{self.calls}_{i}','type':'function',
                'function':dict(name=q['name'],arguments=json.dumps(q['arguments']))} for i,q in enumerate(remaining[:4])]}
        else:
            results=[json.loads(m['content']) for m in body['messages'] if m['role']=='tool']
            conn=next((r for r in results if r.get('ok') and 'packets' in r.get('data',{})),None)
            facts=[] if conn is None else [dict(evidence_id=conn['evidence_id'],path='/data/packets',value=conn['data']['packets']+(1 if self.bad_fact else 0))]
            message={'role':'assistant','content':json.dumps(dict(facts=facts,possible_explanations=['合成脚本：可能为正常业务'],manual_review=['核实业务']))}
        return {'choices':[dict(message=message,finish_reason='tool_calls' if remaining else 'stop')],
                'usage':dict(prompt_tokens=10,completion_tokens=10)}


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.JobFixture(); self.store=self.fixture.store; self.jobs=self.store.jobs
        self.model=ScriptModel(); self.agent=Agent(self.store,None,Config(),'test-key-secret',self.model)
        self.runtime=InvestigationRuntime(self.store,self.agent,start=False)
    def tearDown(self):
        self.runtime.close(); self.fixture.close()
    def enqueue(self,**kwargs): return self.fixture.enqueue(**kwargs)
    def execute(self,**kwargs):
        job=self.enqueue(**kwargs); self.assertTrue(self.runtime.run_once()); return self.jobs.get(job['job_id'])

    def test_successful_function_calling_persists_report_and_steps(self):
        job=self.execute(pid=41)
        self.assertEqual(job['status'],'completed')
        report=self.jobs.reports(job['job_id'])[-1]['report']
        self.assertEqual(report['事件 revision'],job['event_revision'])
        self.assertTrue(report['已验证事实'])
        self.assertTrue(report['缺失证据'])  # history unavailable != all steps incomplete
        self.assertFalse(report['model_interpretation_verified'])
        self.assertEqual(len([s for s in self.jobs.steps(job['job_id']) if s['step_type']=='query']),9)
        self.assertNotIn('test-key-secret','\n'.join(self.store.db.iterdump()))
        self.assertGreater(self.store.usage()['calls'],0)

    def test_partial_tool_failure_produces_partial_report(self):
        original=EventToolset.call
        def fail(tool,entry):
            if entry['name']=='query_similar_sessions': raise RuntimeError('synthetic query failure')
            return original(tool,entry)
        with patch.object(EventToolset,'call',fail): job=self.execute()
        self.assertEqual(job['status'],'partial')
        self.assertTrue(any(s['status']=='failed' for s in self.jobs.steps(job['job_id'])))
        self.assertTrue(self.jobs.reports(job['job_id'])[-1]['report']['未调查的范围'])

    def test_incorrect_fact_value_is_not_verified(self):
        self.agent.transport=ScriptModel(bad_fact=True)
        job=self.execute()
        self.assertEqual(job['status'],'partial')
        report=self.jobs.reports(job['job_id'])[-1]['report']
        self.assertFalse(report['fact_validation_passed'])
        self.assertTrue(any('数值不一致' in str(v) for v in report['缺失证据']))

    def test_large_event_reports_uninvestigated_connections(self):
        self.fixture.base.scan(); self.fixture.base.process()
        event=self.fixture.base.events()[0]['event_id']; job=self.jobs.enqueue(event,Config())
        self.runtime.run_once()
        self.assertEqual(self.jobs.get(job['job_id'])['status'],'partial')
        self.assertTrue(self.jobs.reports(job['job_id'])[-1]['report']['未调查的范围'])

    def test_safe_rejection_retries_with_backoff_and_max_attempts(self):
        def reject(n): raise SafeModelRetry('synthetic preflight rejection')
        self.agent.transport=ScriptModel(hook=reject)
        job=self.enqueue()
        for attempt in range(1,4):
            self.runtime.run_once(); saved=self.jobs.get(job['job_id'])
            self.assertEqual(saved['attempt_count'],attempt)
            self.assertEqual(saved['status'],'failed' if attempt==3 else 'retry_wait')
            if attempt<3:
                self.assertGreater(saved['next_retry_at'],time.time())
                with self.store.db: self.store.db.execute('UPDATE investigation_jobs SET next_retry_at=0 WHERE job_id=?',(job['job_id'],))
        with self.assertRaises(ValueError): self.jobs.retry(job['job_id'])
        self.assertEqual(self.store.usage()['calls'],3)

    def test_unknown_timeout_stops_retry_and_next_event_proceeds(self):
        def timeout_once(n):
            if n==1: raise TimeoutError('synthetic provider response lost')
        self.agent.transport=ScriptModel(hook=timeout_once)
        one=self.enqueue(pid=41); two=self.enqueue(pid=42,destination='198.51.100.3')
        self.runtime.run_once(); self.runtime.run_once()
        self.assertEqual(self.jobs.get(one['job_id'])['status'],'partial')
        self.assertEqual(self.jobs.get(one['job_id'])['budget_state']['unknown_requests'],1)
        self.assertEqual(self.jobs.get(two['job_id'])['status'],'completed')
        self.assertFalse(self.runtime.run_once())
        with self.assertRaises(ValueError): self.jobs.retry(one['job_id'])

    def test_auth_error_is_failed_not_unknown_and_can_retry_after_configuration(self):
        def auth(n): raise ModelHTTPError(401)
        self.agent.transport=ScriptModel(hook=auth)
        job=self.execute()
        self.assertEqual(job['status'],'failed')
        self.assertEqual(job['budget_state']['unknown_requests'],0)
        self.agent.transport=ScriptModel(); self.jobs.retry(job['job_id']); self.runtime.run_once()
        self.assertEqual(self.jobs.get(job['job_id'])['status'],'completed')
        self.assertEqual(len(self.jobs.reports(job['job_id'])),2)

    def test_budget_block_and_explicit_resume_preserve_accounting(self):
        self.agent.config=replace(Config(),max_cost=1e-9)
        job=self.enqueue(); self.runtime.run_once()
        self.assertEqual(self.jobs.get(job['job_id'])['status'],'blocked_budget')
        self.assertEqual(self.store.usage()['calls'],0)
        self.agent.config=Config(); self.jobs.retry(job['job_id'],cost_limit=.25); self.runtime.run_once()
        self.assertEqual(self.jobs.get(job['job_id'])['status'],'completed')

    def test_cancel_in_flight_stops_subsequent_tool_calls(self):
        job=self.enqueue()
        self.agent.transport=ScriptModel(hook=lambda n:self.jobs.cancel(job['job_id']))
        self.runtime.run_once()
        self.assertEqual(self.jobs.get(job['job_id'])['status'],'cancelled')
        self.assertEqual(self.jobs.get(job['job_id'])['tool_calls'],0)
        self.assertEqual(len(self.jobs.steps(job['job_id'])),1)

    def test_cancel_during_query_stops_next_tool(self):
        job=self.enqueue(); original=EventToolset.call; calls=[]
        def cancel(tool,entry):
            calls.append(entry['name']); self.jobs.cancel(job['job_id']); return original(tool,entry)
        with patch.object(EventToolset,'call',cancel): self.runtime.run_once()
        self.assertEqual(len(calls),1)
        self.assertEqual(self.jobs.get(job['job_id'])['status'],'cancelled')
        self.assertFalse(any(s['status']=='running' for s in self.jobs.steps(job['job_id'])))

    def test_existing_agent_lock_defers_claim_without_attempt(self):
        job=self.enqueue()
        with self.agent.lock: self.assertFalse(self.runtime.run_once())
        self.assertEqual(self.jobs.get(job['job_id'])['attempt_count'],0)

    def test_tool_limit_is_enforced(self):
        self.fixture.config=replace(Config(),max_tools=2)
        job=self.execute()
        self.assertEqual(job['status'],'partial'); self.assertEqual(job['tool_calls'],2)

    def test_model_step_limit_is_enforced(self):
        self.fixture.config=replace(Config(),max_steps=1)
        job=self.execute()
        self.assertEqual(job['status'],'partial'); self.assertEqual(self.model.calls,1)

    def test_revision_update_during_investigation_keeps_frozen_scope(self):
        job=self.enqueue(pid=41); old_revision=job['event_revision']
        def update(n):
            if n==1:
                self.fixture.base.add(start=1020,pid=41); self.fixture.base.process()
                self.jobs.enqueue(job['event_id'],Config())
        self.agent.transport=ScriptModel(hook=update)
        self.runtime.run_once()
        report=self.jobs.reports(job['job_id'])[-1]['report']
        self.assertEqual(report['事件 revision'],old_revision)
        self.assertEqual(report['关联连接与应用']['total_connections'],1)
        self.assertEqual(self.jobs.list()['total'],2)

    def test_restart_resumes_saved_queries_without_reexecuting(self):
        job=self.enqueue(); original=EventToolset.call; calls=[]
        def interrupt_after_query(tool,entry):
            calls.append(entry['name']); result=original(tool,entry)
            self.runtime.stop_event.set()
            return result
        with patch.object(EventToolset,'call',interrupt_after_query): self.runtime.run_once()
        self.assertEqual(self.jobs.get(job['job_id'])['status'],'retry_wait')
        self.assertEqual(calls,['get_incident'])
        self.runtime.close()
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'resume.db'
            with closing(sqlite3.connect(path)) as target: self.store.db.backup(target)
            with closing(Store(path)) as reopened:
                agent=Agent(reopened,None,Config(),'scripted-key',ScriptModel())
                runtime=InvestigationRuntime(reopened,agent,start=False)
                actual=[]
                def observe(tool,entry): actual.append(entry['name']); return original(tool,entry)
                try:
                    with patch.object(EventToolset,'call',observe): runtime.run_once()
                    self.assertEqual(reopened.jobs.get(job['job_id'])['status'],'completed')
                    self.assertNotIn('get_incident',actual)
                finally: runtime.close()

    def test_missing_key_does_not_block_other_tasks_or_collection(self):
        one=self.enqueue(); two=self.enqueue(destination='198.51.100.3')
        self.agent.api_key=''; self.runtime.run_once()
        self.assertEqual(self.jobs.get(one['job_id'])['status'],'failed')
        self.fixture.base.add(destination='198.51.100.4'); self.fixture.base.process()
        self.agent.api_key='scripted'; self.runtime.run_once()
        self.assertEqual(self.jobs.get(two['job_id'])['status'],'completed')
        self.assertGreater(self.store.session_summary(self.fixture.base.sid)['packets'],0)

    def test_automatic_discovery_is_opt_in_idempotent_and_throttled(self):
        self.fixture.base.scan(); self.fixture.base.process()
        self.assertEqual(self.runtime.discover(),[])
        self.runtime.automatic=True
        self.assertEqual(len(self.runtime.discover()),1)
        self.assertEqual(self.runtime.discover(),[])

    def test_normal_thread_shutdown_releases_worker(self):
        self.runtime.close()
        self.runtime=InvestigationRuntime(self.store,self.agent)
        self.runtime.close()
        self.assertFalse(self.runtime.thread.is_alive())
        self.assertIsNone(self.store.db.execute('SELECT * FROM investigation_worker').fetchone())

    def test_database_finish_failure_recovers_without_new_model_call(self):
        job=self.enqueue()
        with patch.object(self.jobs,'finish',side_effect=sqlite3.OperationalError('synthetic commit failure')):
            with self.assertRaises(sqlite3.OperationalError): self.runtime.run_once()
        calls=self.model.calls
        self.assertEqual(self.jobs.get(job['job_id'])['status'],'running')
        self.runtime.run_once()
        self.assertEqual(self.jobs.get(job['job_id'])['status'],'completed')
        self.assertEqual(self.model.calls,calls)

    def test_execution_deadline_stops_before_next_tool_or_request(self):
        job=self.enqueue()
        # Simulate elapsed time without sleeping or sending a real API request.
        original=EventToolset.call
        elapsed=[0]
        def query(tool,entry):
            result=original(tool,entry); elapsed[0]=1000; return result
        with patch('time.monotonic',side_effect=lambda:elapsed[0]),patch.object(EventToolset,'call',query):
            self.runtime.run_once()
        self.assertEqual(self.jobs.get(job['job_id'])['status'],'partial')
        self.assertEqual(self.jobs.get(job['job_id'])['tool_calls'],1)

    def test_query_cache_reuses_saved_result_if_model_requests_it_again(self):
        job=self.enqueue(); self.jobs.acquire_worker('test'); running=self.jobs.claim('test')
        entry=running['snapshot']['entries'][0]
        sid,old=self.jobs.begin_query(job['job_id'],entry)
        self.assertIsNone(old)
        result=EventToolset(running['snapshot']).call(entry)
        self.jobs.finish_query(job['job_id'],sid,result,[])
        same,cached=self.jobs.begin_query(job['job_id'],entry)
        self.assertEqual(same,sid); self.assertEqual(cached,result)
        self.jobs.finish_query(job['job_id'],sid,cached,[])
        self.assertEqual(len(self.jobs.steps(job['job_id'])),1)
        self.jobs.release_worker('test')

    def test_received_malformed_response_is_failed_not_unknown(self):
        class Malformed:
            def complete(self,*args): return {'choices':[None]}
        self.agent.transport=Malformed()
        job=self.execute()
        self.assertEqual(job['status'],'failed')
        self.assertEqual(job['budget_state']['unknown_requests'],0)
        self.assertEqual(self.jobs.steps(job['job_id'])[0]['status'],'completed')

    def test_tool_commit_failure_leaves_no_running_step_in_partial_job(self):
        job=self.enqueue()
        with patch.object(self.jobs,'finish_query',side_effect=sqlite3.OperationalError('synthetic commit failure')):
            self.runtime.run_once()
        self.assertEqual(self.jobs.get(job['job_id'])['status'],'partial')
        self.assertFalse(any(s['status']=='running' for s in self.jobs.steps(job['job_id'])))

    def test_separate_budget_database_cannot_bypass_shared_accounting(self):
        with closing(Store(':memory:')) as other:
            agent=Agent(self.store,None,Config(),'scripted',self.model,budget_store=other)
            with self.assertRaises(ValueError): InvestigationRuntime(self.store,agent,start=False)

    def test_cancel_between_query_marker_and_execution_does_not_start_tool(self):
        job=self.enqueue(); original=self.jobs.begin_query
        def cancel(*args):
            result=original(*args); self.jobs.cancel(job['job_id']); return result
        with patch.object(self.jobs,'begin_query',side_effect=cancel),patch.object(EventToolset,'call') as tool:
            self.runtime.run_once()
            tool.assert_not_called()
        self.assertEqual(self.jobs.get(job['job_id'])['status'],'cancelled')
