"""Explicitly SYNTHETIC metadata for correlation, not attack-accuracy evidence."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'.runtime'))
from traffic_agent.anomaly import assess_session_records
from traffic_agent.incidents import identity, CORRELATION_VERSION
from traffic_agent.incident_store import create_schema
from traffic_agent.store import Store
from traffic_agent.tools import Toolset
from traffic_agent.replay import Replay
from traffic_agent.capture import Collector
from traffic_agent.migrations import SCHEMA_VERSION


class IncidentTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')
        self.sid = self.store.start_session('explicit-synthetic-correlation-fixture')
        self.serial = 0

    def tearDown(self):
        self.store.close()

    def add(self, start=1000, port=443, source_port=40000, pid=None, created=900,
            destination='198.51.100.2', syn_only=False, bulk=False, kind='tcp_observed', proxy=False):
        self.serial += 1
        cid = identity('conn_',self.sid,self.serial)
        applications=[]
        if pid is not None:
            applications.append(dict(endpoint_ip='192.0.2.1',endpoint_port=source_port,
                role='socket_owner',pid=pid,process_created=created,app='same-name.exe',
                sampled_at=start,basis='SYNTHETIC test snapshot',confidence='snapshot_match'))
        if proxy:
            applications += [dict(endpoint_ip='192.0.2.1',endpoint_port=source_port,
                role='proxy_original',pid=pid,process_created=created if pid is not None else None,
                app='same-name.exe',sampled_at=start,basis='SYNTHETIC proxy inbound evidence',confidence='inferred'),
                dict(endpoint_ip=destination,endpoint_port=port,role='socket_owner',pid=99,
                process_created=800,app='mihomo.exe',sampled_at=start,basis='SYNTHETIC peer snapshot',confidence='snapshot_match')]
        row=dict(source='live',session_id=self.sid,connection_id=cid,instance_kind=kind,
            boundary_reason='synthetic_fixture',uncertainty_flags=0 if kind=='tcp_observed' else 256,
            handshake_basis='sequence_checked',timestamp=start,src='192.0.2.1',dst=destination,
            protocol='TCP',sport=source_port,dport=port,syn=1,syn_ack=0 if syn_only else 1,
            fin=0 if syn_only else 1,client_is_a=1,handshake_status='SYN_ONLY' if syn_only else 'CONFIRMED',
            connection_state='UNKNOWN' if syn_only else 'CLOSED',
            bytes=60 if syn_only else 60000000 if bulk else 600000,
            packets=1 if syn_only else 600000 if bulk else 6000,application_observations=applications)
        self.store.add([row])
        if not syn_only:
            self.store.add([{**row,'timestamp':start+10,'bytes':0,'packets':0,'syn':0,'application_observations':[]}])
        return cid

    def scan(self,start=1000,pids=None):
        return [self.add(start+i*.1,port=1000+i,syn_only=True,pid=pids[i] if pids else None) for i in range(20)]

    def process(self):
        return self.store.process_incidents(self.sid)

    def events(self):
        return self.store.incidents.list_events(page_size=50)['items']

    def test_related_scan_findings_form_one_traceable_event(self):
        ids=self.scan()
        result=self.process()
        event,=self.events()
        self.assertFalse(result['llm_called'])
        self.assertEqual(event['risk_score'],80)
        self.assertEqual(event['severity'],'high')
        members=self.store.incidents.members(event['event_id'],page_size=50)
        self.assertEqual(members['total'],40)
        self.assertEqual({r['connection_id'] for r in members['items']},set(ids))
        self.assertEqual({r['session_id'] for r in members['items']},{self.sid})
        self.assertTrue(all(r['data']['trigger']['thresholds'] for r in members['items']))
        self.assertTrue(any(r['correlation_reason']['rule']=='SAME_INITIATOR_DETECTED_PATTERN' for r in members['items']))

    def test_same_connection_different_rules_share_event_without_score_sum(self):
        self.add(bulk=True)
        self.process()
        event,=self.events()
        members=self.store.incidents.members(event['event_id'])['items']
        self.assertEqual(len(members),2)
        self.assertEqual(event['risk_score'],55)
        self.assertEqual(sum(f['original_score'] for f in members),110)
        self.assertEqual({r['correlation_reason']['rule'] for r in members},{'SINGLE_CONNECTION_SEED','SAME_CONNECTION_INSTANCE'})

    def test_same_process_related_behavior_correlates(self):
        self.add(pid=41)
        self.add(start=1020,source_port=40001,pid=41)
        self.process()
        event,=self.events()
        members=self.store.incidents.members(event['event_id'])['items']
        self.assertEqual(len(members),2)
        relation=next(r for r in members if r['anchor_finding_id'])['correlation_reason']
        self.assertEqual(relation['rule'],'SAME_LOCAL_PROCESS_BEHAVIOR')
        self.assertEqual(relation['fields']['process_instances'],[[41,900.0]])
        self.assertEqual(event['risk_score'],30)
        self.assertEqual(event['correlation_confidence'],'medium')

    def test_different_target_does_not_merge_just_because_same_process(self):
        self.add(pid=41)
        self.add(start=1020,pid=41,destination='198.51.100.3')
        self.process()
        self.assertEqual(len(self.events()),2)

    def test_same_ip_and_name_different_pid_or_lifetime_do_not_merge(self):
        for pid,created in ((41,900),(42,900),(41,901)):
            self.add(start=1000+self.serial,pid=pid,created=created)
        self.process()
        self.assertEqual(len(self.events()),3)

    def test_group_behavior_respects_conflicting_processes(self):
        self.scan(pids=[41]*10+[42]*10)
        self.process()
        self.assertEqual(len(self.events()),2)
        for e in self.events():
            members=self.store.incidents.members(e['event_id'],page_size=50)['items']
            self.assertEqual(len({p[0] for f in members for p in f['data']['subject_processes']}),1)

    def test_late_process_evidence_splits_conflicting_members(self):
        ids=self.scan()
        self.process()
        self.assertEqual(len(self.events()),1)
        for i,cid in enumerate(ids):
            # Add saved source evidence, not a current-process historical guess.
            self.store.db.execute('''INSERT INTO session_applications VALUES(
                ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (self.sid,'192.0.2.1',40000,'198.51.100.2',1000+i,'TCP',960,'192.0.2.1',40000,
                 'socket_owner',41 if i<10 else 42,900,'same-name.exe','SYNTHETIC added evidence',
                 'snapshot_match',60,1,1000+i*.1,1000+i*.1,1000+i*.1,1000+i*.1,cid))
        self.store.db.commit()
        self.process()
        self.assertEqual(len(self.events()),2)
        timeline=[]
        for e in self.events():
            first=self.store.incidents.timeline(e['event_id'],page_size=50)
            timeline.extend(first['items'])
            for page in range(2,first['pages']+1):
                timeline.extend(self.store.incidents.timeline(e['event_id'],page=page,page_size=50)['items'])
        self.assertTrue(any(t['action']=='member_detached' for t in timeline))

    def test_proxy_requires_original_owner_and_proxy_peer_evidence(self):
        self.add(proxy=True)
        self.add(start=1020,source_port=40001,proxy=True)
        self.process()
        self.assertEqual(len(self.events()),2)
        for e in self.events():
            self.assertFalse(self.store.incidents.members(e['event_id'])['items'][0]['data']['verified_proxy_processes'])

    def test_verified_proxy_inbound_can_correlate(self):
        self.add(proxy=True,pid=41)
        self.add(start=1020,source_port=40001,proxy=True,pid=41)
        self.process()
        event,=self.events()
        reasons=[r['correlation_reason']['rule'] for r in self.store.incidents.members(event['event_id'])['items']]
        self.assertIn('VERIFIED_PROXY_INBOUND_PROCESS',reasons)

    def test_process_evidence_snapshot_survives_later_identity_change(self):
        self.add(pid=41); self.add(start=1020,pid=41)
        self.process()
        event,=self.events()
        eid=event['event_id']
        reference=self.store.incidents.get_event(eid)['evidence_references'][0]
        original=self.store.incidents.evidence(eid,reference)
        owner=original['context_connections'][0]['application_identity']['observations'][0]
        self.assertEqual(owner['pid'],41)
        self.assertEqual(owner['process_created'],900)
        self.assertGreater(owner['matched_packets'],0)
        with self.store.db:
            self.store.db.execute('UPDATE session_applications SET pid=42')
        self.process()
        self.assertEqual(self.store.incidents.evidence(eid,reference),original)

    def test_repeat_is_idempotent_including_timestamps_and_timeline(self):
        self.scan()
        self.process()
        before=list(self.store.db.iterdump())
        result=self.process()
        self.assertEqual(result['changed_findings'],0)
        self.assertEqual(list(self.store.db.iterdump()),before)

    def test_larger_new_window_does_not_withdraw_still_valid_old_trigger(self):
        for i in range(10): self.add(start=850+i*.1,syn_only=True)
        for i in range(10): self.add(start=1100+i*.1,syn_only=True)
        self.process()
        for i in range(20): self.add(start=1190+i*.1,syn_only=True)
        self.process()
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM incident_findings WHERE state='active'").fetchone()[0],40)
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM incident_findings WHERE state='withdrawn'").fetchone()[0],0)

    def test_caller_transaction_is_not_rolled_back_on_rejection(self):
        self.store.db.execute('UPDATE budget SET calls=123')
        with self.assertRaises(RuntimeError): self.process()
        self.assertTrue(self.store.db.in_transaction)
        self.assertEqual(self.store.db.execute('SELECT calls FROM budget').fetchone()[0],123)
        self.store.db.rollback()

    def test_reused_tuple_retains_distinct_references(self):
        ids=[self.add(pid=41),self.add(start=1020,pid=41)]
        self.process()
        event,=self.events()
        members=self.store.incidents.members(event['event_id'])['items']
        self.assertEqual({m['connection_id'] for m in members},set(ids))
        self.assertEqual(len(members),2)

    def test_new_related_connection_updates_existing_event_not_risk_by_count(self):
        self.add(pid=41)
        self.process()
        before,=self.events()
        for i in range(20):
            self.add(start=1020+i,source_port=41000+i,pid=41)
        self.process()
        after,=self.events()
        self.assertEqual(before['event_id'],after['event_id'])
        self.assertEqual(after['risk_score'],30)
        self.assertGreater(after['updated_at'],before['updated_at'])
        self.assertEqual(self.store.incidents.members(after['event_id'])['total'],21)

    def test_fixed_window_boundary_does_not_chain_forever(self):
        for start in (1000,1300,1300.001,1600.002):
            self.add(start=start,pid=41)
        self.process()
        events=self.events()
        self.assertEqual(len(events),3)
        self.assertEqual(self.store.incidents.members(events[0]['event_id'])['total'],2)

    def test_distant_group_behavior_creates_separate_events(self):
        self.scan(1000)
        self.scan(1700)
        self.process()
        self.assertEqual(len(self.events()),2)

    def test_cross_capture_requires_same_process_and_capture_scope(self):
        self.add(pid=41); self.process()
        original=self.sid
        self.sid=self.store.start_session('explicit-synthetic-correlation-fixture')
        self.add(start=1050,pid=41); self.process()
        event,=self.events()
        self.assertEqual({m['session_id'] for m in self.store.incidents.members(event['event_id'])['items']},{original,self.sid})
        self.sid=self.store.start_session('different-interface')
        self.add(start=1070,pid=41); self.process()
        self.assertEqual(len(self.events()),2)

    def test_ip_group_does_not_merge_across_captures(self):
        self.scan(); self.process()
        self.sid=self.store.start_session('explicit-synthetic-correlation-fixture')
        self.scan(1050); self.process()
        self.assertEqual(len(self.events()),2)

    def test_closed_repeat_stays_closed_and_new_activity_reopens(self):
        self.add(pid=41); self.process()
        event,=self.events(); eid=event['event_id']
        self.store.incidents.set_status(eid,'acknowledged')
        closed=self.store.incidents.set_status(eid,'closed')
        self.assertEqual(self.store.incidents.set_status(eid,'closed'),closed)
        self.process()
        self.assertEqual(self.store.incidents.get_event(eid)['status'],'closed')
        self.add(start=1020,pid=41); self.process()
        self.assertEqual(self.store.incidents.get_event(eid)['status'],'open')
        self.assertIn('reopened',[r['action'] for r in self.store.incidents.timeline(eid,page_size=50)['items']])

    def test_withdrawn_trigger_remains_auditable_without_current_risk(self):
        self.scan(); self.process()
        eid=self.events()[0]['event_id']
        with self.store.db:
            self.store.db.execute("UPDATE session_connection_metrics SET handshake_status='CONFIRMED',connection_state='ESTABLISHED' WHERE session_id=?",(self.sid,))
        self.process()
        event=self.store.incidents.get_event(eid)
        self.assertEqual(event['risk_score'],0)
        self.assertIn('no_current_trigger',event['uncertainty_flags'])
        self.assertTrue(all(r['state']=='withdrawn' for r in self.store.incidents.members(eid,page_size=50)['items']))
        self.assertTrue(event['evidence_references'])

    def test_legacy_aggregates_stay_unassociated(self):
        self.add(kind='legacy_aggregate'); self.process()
        self.assertEqual(self.events(),[])
        pending=self.store.incidents.unassociated(self.sid)
        self.assertEqual(pending['total'],1)
        self.assertEqual(pending['items'][0]['data']['connection']['instance_kind'],'legacy_aggregate')

    def test_all_queries_pagination_filters_scope_and_redaction(self):
        self.scan(); self.process()
        eid=self.events()[0]['event_id']; tool=Toolset(self.store,None,session_id=self.sid)
        summary=tool.call('get_incident',json.dumps({'event_id':eid}))
        self.assertTrue(summary['ok'],summary)
        self.assertEqual(summary['data']['members_pages'],2)
        members=[]
        for page in (1,2,3,4):
            result=tool.call('query_incident_members',json.dumps(dict(event_id=eid,page=page,page_size=10)))
            self.assertTrue(result['ok'],result)
            members += result['data']['items']
        self.assertEqual(len({m['finding_id'] for m in members}),40)
        self.assertNotIn('192.0.2.1',json.dumps(members))
        reference=summary['data']['evidence_references'][0]
        evidence=tool.call('query_incident_evidence',json.dumps(dict(event_id=eid,evidence_id=reference)))
        self.assertTrue(evidence['ok'],evidence)
        self.assertEqual(evidence['data']['total'],20)
        self.assertEqual(self.store.incidents.list_events(status='open',severity='high',since=1000,until=1002)['total'],1)
        self.assertEqual(self.store.incidents.list_events(since=2000)['total'],0)
        self.assertFalse(tool.call('set_incident_status',json.dumps(dict(event_id=eid,status='closed')))['ok'])
        other=self.store.start_session('unrelated')
        self.assertFalse(Toolset(self.store,None,session_id=other).call('get_incident',json.dumps({'event_id':eid}))['ok'])
        self.assertFalse(tool.call('list_incidents','{"session_id":"foreign"}')['ok'])

    def test_evidence_and_relation_references_exist_and_are_event_bound(self):
        self.scan(); self.process()
        eid=self.events()[0]['event_id']
        for f in self.store.incidents.members(eid,page_size=50)['items']:
            for reference in f['correlation_reason']['evidence_references']:
                self.assertTrue(self.store.incidents.evidence(eid,reference))
        self.assertEqual(self.store.db.execute('PRAGMA foreign_key_check').fetchall(),[])
        for item in self.store.incidents.timeline(eid,page_size=50)['items']:
            for ref in item['data'].get('evidence_references',[]):
                self.assertTrue(self.store.incidents.evidence(eid,ref))
        with self.assertRaises(ValueError):
            self.store.incidents.evidence(eid,'ie_'+'0'*32)

    def test_source_delete_cleans_snapshots_and_keeps_other_capture(self):
        self.add(pid=41); self.process(); old=self.sid
        self.store.end_session(old)
        self.sid=self.store.start_session('explicit-synthetic-correlation-fixture')
        self.add(start=1050,pid=41); self.process()
        eid=self.events()[0]['event_id']
        self.store.delete_session(old)
        event=self.store.incidents.get_event(eid)
        self.assertIn('source_data_removed',event['uncertainty_flags'])
        self.assertEqual({r['session_id'] for r in event['related_connections']},{self.sid})
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM incident_evidence WHERE session_id=?',(old,)).fetchone()[0],0)
        self.assertEqual(self.store.db.execute('PRAGMA foreign_key_check').fetchall(),[])
        for item in self.store.incidents.timeline(eid,page_size=50)['items']:
            for ref in item['data'].get('evidence_references',[]):
                self.assertTrue(self.store.incidents.evidence(eid,ref))

    def test_filter_invalidates_affected_capture_and_can_recompute(self):
        self.add(pid=41); self.add(start=1020,pid=41); self.process()
        self.store.end_session(self.sid)
        key=self.store.session_connections(self.sid)['connections'][0]['key']
        self.store.retain_session_connections(self.sid,[key])
        self.assertEqual(self.events(),[])
        self.process()
        event,=self.events()
        self.assertEqual(self.store.incidents.members(event['event_id'])['total'],1)
        self.assertIn('incomplete_capture_scope',event['uncertainty_flags'])

    def test_transaction_failure_leaves_no_partial_update(self):
        self.scan()
        before=list(self.store.db.iterdump())
        with patch.object(self.store.incidents,'_assign',side_effect=RuntimeError('injected')):
            with self.assertRaises(RuntimeError): self.process()
        self.assertEqual(list(self.store.db.iterdump()),before)
        self.process()
        self.assertEqual(len(self.events()),1)

    def test_deferred_commit_failure_rolls_back_evidence_members_and_timeline(self):
        self.scan()
        self.store.db.execute('''CREATE TRIGGER fail_incident_commit AFTER INSERT ON incidents BEGIN
            INSERT INTO incident_members VALUES(NEW.event_id,'missing_finding',NULL,'{}',0); END''')
        before=list(self.store.db.iterdump())
        with self.assertRaises(sqlite3.IntegrityError): self.process()
        self.assertEqual(list(self.store.db.iterdump()),before)

    def test_capture_incident_failure_does_not_drop_saved_flow(self):
        self.add(pid=41)
        collector=Collector(self.store)
        try:
            count=self.store.session_summary(self.sid)['packets']
            with patch.object(self.store,'process_incidents',side_effect=RuntimeError('test failure')):
                collector._update_incidents(self.sid)
            self.assertTrue(collector.status()['incident_error'])
            self.assertEqual(collector.dropped,0)
            self.assertEqual(self.store.session_summary(self.sid)['packets'],count)
        finally:
            collector.close()

    def test_capture_writer_and_stop_generate_events_without_llm(self):
        # Synthetic packet metadata through the real writer/tracker/store path.
        collector=Collector(self.store)
        collector.session_id=self.sid
        try:
            for i in range(20):
                collector.queue.put(dict(source='live',session_id=self.sid,timestamp=1000+i*.1,
                    src='192.0.2.1',dst='198.51.100.2',sport=40000+i,dport=1000+i,protocol='TCP',
                    bytes=60,packets=1,syn=1,syn_ack=0,ack=0,fin=0,rst=0,tcp_seq=100+i,tcp_ack=0))
            collector.queue.join()
            collector.stop()
            self.assertIsNone(collector.incident_error)
            self.assertEqual(collector.dropped,0)
            event,=self.events()
            self.assertEqual(event['severity'],'high')
            self.assertEqual(self.store.session_summary(self.sid)['packets'],20)
            self.assertEqual(self.store.db.execute('SELECT calls FROM budget').fetchone()[0],0)
        finally:
            collector.close()

    def test_detector_optional_window_export_does_not_change_scores(self):
        self.scan()
        records=[dict(r) for r in self.store.db.execute('SELECT * FROM session_connection_metrics')]
        a=assess_session_records(records,True)
        seen=[]
        b=assess_session_records(records,True,on_window=lambda *v:seen.append(v))
        self.assertEqual(a,b)
        self.assertTrue(seen)


class IncidentMigrationTests(unittest.TestCase):
    def v2(self,path):
        with closing(Store(path)) as store:
            sid=store.start_session('synthetic migration')
            store.end_session(sid)
            store.save_session_report(sid,'keep me',True)
            # Recreate schema version 2 without incident tables; preserve source tables.
            for table in ('incident_timeline','incident_members','incident_finding_evidence','incident_findings','incident_evidence','incidents'):
                store.db.execute('DROP TABLE '+table)
            store.db.execute('PRAGMA user_version=2')
            store.db.commit()
        return sid

    def test_v2_migration_backup_preserves_original_tables(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'v2.db'; sid=self.v2(path)
            with closing(sqlite3.connect(path)) as db:
                before={t:[tuple(r) for r in db.execute('SELECT * FROM '+t)] for t in ('capture_sessions','capture_reports','budget','meta')}
            with closing(Store(path)) as store:
                self.assertEqual(store.db.execute('PRAGMA user_version').fetchone()[0],SCHEMA_VERSION)
                self.assertEqual(store.db.execute('PRAGMA foreign_keys').fetchone()[0],1)
                self.assertTrue(Path(store.migration_backup).exists())
                for table,rows in before.items(): self.assertEqual([tuple(r) for r in store.db.execute('SELECT * FROM '+table)],rows)
                self.assertEqual(store.session_report(sid)['answer'],'keep me')
            with closing(Store(path)) as reopened:
                self.assertIsNone(reopened.migration_backup)

    def test_v2_migration_failure_rolls_back_schema_and_version(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'v2.db'; self.v2(path)
            with closing(sqlite3.connect(path)) as db: before=list(db.iterdump())
            def fail(db):
                create_schema(db)
                raise RuntimeError('injected DDL failure')
            with patch('traffic_agent.incident_store.create_schema',side_effect=fail),self.assertRaises(RuntimeError): Store(path)
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(list(db.iterdump()),before)
                self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0],2)

    def test_reopen_and_replay_keep_stable_logical_events(self):
        from sample_data import port_scan_pcap
        path=port_scan_pcap(self)
        with Replay(path) as first, Replay(path) as second:
            a,b=first.store.incidents.list_events(),second.store.incidents.list_events()
            self.assertGreater(a['total'],0)
            self.assertFalse(first.incident_result['llm_called'])
            self.assertEqual([r['event_id'] for r in a['items']],[r['event_id'] for r in b['items']])
            self.assertEqual(first.detection,second.detection)
            with tempfile.TemporaryDirectory() as folder:
                dbpath=Path(folder)/'events.db'
                with closing(sqlite3.connect(dbpath)) as dest: first.store.db.backup(dest)
                with closing(Store(dbpath)) as reopened:
                    self.assertEqual(reopened.incidents.list_events(),a)
                    self.assertEqual(reopened.process_incidents(first.session_id)['changed_findings'],0)


if __name__=='__main__':
    unittest.main()
