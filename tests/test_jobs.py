"""SYNTHETIC incident metadata; tests persistence, not real attack accuracy."""
from contextlib import closing
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'.runtime'))
import test_incidents as fixtures
from traffic_agent.config import Config
from traffic_agent.store import Store
from traffic_agent.jobs import create_schema, BudgetBlocked
from traffic_agent.tools import EventToolset
from traffic_agent.migrations import SCHEMA_VERSION


class JobFixture:
    def __init__(self):
        self.base=fixtures.IncidentTests(); self.base.setUp()
        self.store=self.base.store; self.jobs=self.store.jobs; self.config=Config()
    def event(self,**kwargs):
        cid=self.base.add(**kwargs); self.base.process()
        return self.store.db.execute('''SELECT m.event_id FROM incident_members m JOIN incident_findings f USING(finding_id)
            WHERE f.session_id=? AND f.connection_id=?''',(self.base.sid,cid)).fetchone()[0]
    def enqueue(self,**kwargs):
        event=self.event(**kwargs)
        return self.jobs.enqueue(event,self.config)
    def close(self): self.base.tearDown()


class JobsTests(unittest.TestCase):
    def setUp(self):
        self.fixture=JobFixture(); self.store=self.fixture.store; self.jobs=self.fixture.jobs
    def tearDown(self): self.fixture.close()

    def test_same_event_revision_enqueue_is_idempotent(self):
        j=self.fixture.enqueue(pid=41)
        before=list(self.store.db.iterdump())
        other=self.jobs.enqueue(j['event_id'],Config())
        self.assertEqual(j,other)
        self.assertEqual(list(self.store.db.iterdump()),before)

    def test_new_revision_has_distinct_job_and_fixed_old_evidence(self):
        old=self.fixture.enqueue(pid=41)
        frozen=self.jobs.get(old['job_id'])['snapshot']
        self.fixture.base.add(start=1020,pid=41); self.fixture.base.process()
        new=self.jobs.enqueue(old['event_id'],Config())
        self.assertNotEqual(old['job_id'],new['job_id'])
        self.assertGreater(new['event_revision'],old['event_revision'])
        self.assertEqual(self.jobs.get(old['job_id'])['snapshot'],frozen)
        self.assertEqual(frozen['total_connections'],1)
        self.assertEqual(self.jobs.get(new['job_id'])['snapshot']['total_connections'],2)

    def test_old_unfrozen_revision_is_rejected(self):
        event=self.fixture.event(pid=41)
        with self.assertRaises(ValueError): self.jobs.enqueue(event,Config(),revision=0)

    def test_priority_and_aging_prevent_permanent_starvation(self):
        low=self.fixture.enqueue(pid=41)
        high=self.fixture.enqueue(pid=42,destination='198.51.100.3',bulk=True)
        self.assertTrue(self.jobs.acquire_worker('owner'))
        self.assertEqual(self.jobs.claim('owner')['job_id'],high['job_id'])
        self.jobs.finish(high['job_id'],'failed','synthetic')
        with self.store.db:
            self.store.db.execute('UPDATE investigation_jobs SET created_at=created_at-10000 WHERE job_id=?',(low['job_id'],))
        newest=self.fixture.enqueue(pid=43,destination='198.51.100.4',bulk=True)
        self.assertEqual(self.jobs.claim('owner')['job_id'],low['job_id'])
        self.assertEqual(self.jobs.get(newest['job_id'])['status'],'queued')

    def test_worker_ownership_and_single_running_task(self):
        self.fixture.enqueue(); self.fixture.enqueue(destination='198.51.100.3')
        self.assertTrue(self.jobs.acquire_worker('one'))
        self.assertFalse(self.jobs.acquire_worker('two'))
        self.assertIsNotNone(self.jobs.claim('one'))
        self.assertIsNone(self.jobs.claim('one'))
        with self.assertRaises(RuntimeError): self.jobs.claim('two')

    def test_budget_and_request_marker_are_one_transaction(self):
        j=self.fixture.enqueue(); self.jobs.acquire_worker('owner'); self.jobs.claim('owner')
        before=list(self.store.db.iterdump())
        self.store.db.execute("CREATE TRIGGER reject_model BEFORE INSERT ON investigation_steps BEGIN SELECT RAISE(ABORT,'injected'); END")
        try:
            with self.assertRaises(sqlite3.IntegrityError): self.jobs.begin_model(j['job_id'],.1,Config())
        finally: self.store.db.execute('DROP TRIGGER reject_model')
        self.assertEqual(list(self.store.db.iterdump()),before)
        self.assertEqual(self.store.usage()['calls'],0)

    def test_enqueue_failure_rolls_back_all_rows(self):
        event=self.fixture.event()
        self.store.db.execute("CREATE TRIGGER fail_sources BEFORE INSERT ON investigation_sources BEGIN SELECT RAISE(ABORT,'injected'); END")
        before=list(self.store.db.iterdump())
        with self.assertRaises(sqlite3.IntegrityError): self.jobs.enqueue(event,Config())
        self.assertEqual(list(self.store.db.iterdump()),before)

    def test_recovery_distinguishes_query_from_unknown_model(self):
        j=self.fixture.enqueue(); self.jobs.acquire_worker('one'); job=self.jobs.claim('one')
        entry=job['snapshot']['entries'][0]
        step,_=self.jobs.begin_query(j['job_id'],entry)
        self.jobs.release_worker('one'); self.jobs.acquire_worker('two')
        self.assertEqual(self.jobs.get(j['job_id'])['status'],'retry_wait')
        self.assertEqual(self.jobs.steps(j['job_id'])[0]['status'],'retryable')
        self.jobs.claim('two'); self.jobs.begin_model(j['job_id'],.01,Config())
        self.jobs.release_worker('two'); self.jobs.acquire_worker('three')
        recovered=self.jobs.get(j['job_id'])
        self.assertEqual(recovered['status'],'partial')
        self.assertEqual(recovered['budget_state']['unknown_requests'],1)
        with self.assertRaises(ValueError): self.jobs.retry(j['job_id'])
        self.jobs.retry(j['job_id'],confirm_unknown=True)
        self.assertEqual(self.jobs.get(j['job_id'])['status'],'queued')

    def test_already_marked_unknown_is_never_automatically_retried(self):
        j=self.fixture.enqueue(); self.jobs.acquire_worker('one'); self.jobs.claim('one')
        sid=self.jobs.begin_model(j['job_id'],.01,Config())
        self.jobs.model_error(j['job_id'],sid,'synthetic timeout',True)
        self.jobs.release_worker('one'); self.jobs.acquire_worker('two')
        self.assertEqual(self.jobs.get(j['job_id'])['status'],'partial')
        self.assertIsNone(self.jobs.claim('two'))

    def test_cancelled_and_completed_jobs_cannot_be_retried(self):
        j=self.fixture.enqueue(); self.jobs.cancel(j['job_id'])
        self.assertEqual(self.jobs.get(j['job_id'])['status'],'cancelled')
        with self.assertRaises(ValueError): self.jobs.retry(j['job_id'])

    def test_frozen_tools_reject_foreign_references_and_writes(self):
        j=self.fixture.enqueue(); snapshot=self.jobs.get(j['job_id'])['snapshot']; tools=EventToolset(snapshot)
        for name,args in [('capture_traffic',{}),('get_incident',{'event_id':'wrong'}),
                          ('query_connection',{'session_id':'other','connection_id':snapshot['selected_connections'][0]['connection_id']})]:
            with self.assertRaises(ValueError): tools.resolve(name,json.dumps(args))
        before=list(self.store.db.iterdump())
        for entry in snapshot['entries']: tools.call(entry)
        self.assertEqual(list(self.store.db.iterdump()),before)
        self.assertNotIn('192.0.2.1',json.dumps(snapshot))

    def test_capture_delete_removes_derived_job_snapshots(self):
        self.fixture.enqueue()
        self.store.end_session(self.fixture.base.sid)
        self.store.delete_session(self.fixture.base.sid)
        self.assertEqual(self.jobs.list()['total'],0)
        self.assertEqual(self.store.db.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_budget_rejection_does_not_increment_calls(self):
        j=self.fixture.enqueue(); self.jobs.acquire_worker('one'); self.jobs.claim('one')
        with self.assertRaises(BudgetBlocked): self.jobs.begin_model(j['job_id'],2,Config())
        self.assertEqual(self.store.usage()['calls'],0)

    def test_invalid_completion_transition_is_rejected(self):
        from traffic_agent.jobs import JobStopped
        j=self.fixture.enqueue()
        with self.assertRaises(JobStopped): self.jobs.finish(j['job_id'],'completed')
        self.jobs.acquire_worker('one'); self.jobs.claim('one')
        with self.assertRaises(ValueError): self.jobs.finish(j['job_id'],'completed')
        self.assertEqual(self.jobs.get(j['job_id'])['status'],'running')

    def test_unrelated_capture_deletion_does_not_erase_job(self):
        sid=self.store.start_session('unrelated-interface'); self.store.end_session(sid)
        j=self.fixture.enqueue()
        self.store.delete_session(sid)
        self.assertEqual(self.jobs.get(j['job_id'])['status'],'queued')


class JobMigrationTests(unittest.TestCase):
    def old_database(self,path):
        with closing(Store(path)) as store:
            base=fixtures.IncidentTests(); base.store=store; base.serial=0
            base.sid=store.start_session('synthetic v3 preservation')
            base.add(pid=41); base.process(); store.end_session(base.sid)
            store.save_session_report(base.sid,'existing report must survive',True)
            for table in ('investigation_sources','investigation_reports','investigation_steps','investigation_jobs','investigation_worker'):
                store.db.execute('DROP TABLE '+table)
            store.db.execute('PRAGMA user_version=3'); store.db.commit()

    def test_v3_upgrade_preserves_all_source_tables_and_backup(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'v3.db'; self.old_database(path)
            with closing(sqlite3.connect(path)) as db:
                tables=[r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
                before={t:db.execute('SELECT * FROM '+t).fetchall() for t in tables}
            with closing(Store(path)) as store:
                self.assertEqual(store.db.execute('PRAGMA user_version').fetchone()[0],4)
                self.assertTrue(Path(store.migration_backup).exists())
                for t,rows in before.items(): self.assertEqual([tuple(r) for r in store.db.execute('SELECT * FROM '+t)],rows)
                self.assertEqual(store.db.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_v3_upgrade_failure_rolls_back_schema_and_version(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'v3.db'; self.old_database(path)
            with closing(sqlite3.connect(path)) as db: before=list(db.iterdump())
            def fail(db): create_schema(db); raise RuntimeError('injected')
            with patch('traffic_agent.jobs.create_schema',side_effect=fail),self.assertRaises(RuntimeError): Store(path)
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(list(db.iterdump()),before)
                self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],3)
