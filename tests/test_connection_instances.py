"""Instance boundaries and migrations; packets here are explicitly synthetic."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / '.runtime'))
from scapy.all import IP, TCP, Raw, wrpcap
from traffic_agent.capture import TCPStateTracker, packet_metadata
from traffic_agent.connection_instances import FLAGS
from traffic_agent.store import Store
from traffic_agent.tools import Toolset
from traffic_agent.replay import Replay
from traffic_agent.evaluation import validate_record, legacy_feature_view
from traffic_agent.migrations import restore_copy, migrate, SCHEMA_VERSION
from traffic_agent.connections import ConnectionTracker


def packet(t, flags, seq, ack=0, reverse=False, payload=b'', port=40000):
    a, b = ('192.0.2.1', port), ('198.51.100.2', 443)
    src, dst = (b, a) if reverse else (a, b)
    p = IP(src=src[0], dst=dst[0])/TCP(sport=src[1], dport=dst[1], flags=flags, seq=seq, ack=ack)
    if payload:
        p = p/Raw(payload)
    p.time = t
    return p


def conversation(t=1000, seq=100000, peer=900000, port=40000):
    return [packet(t, 'S', seq, port=port),
            packet(t+.1, 'SA', peer, seq+1, True, port=port),
            packet(t+.2, 'A', seq+1, peer+1, port=port),
            packet(t+.3, 'PA', seq+1, peer+1, payload=b'test', port=port),
            packet(t+.4, 'FA', seq+5, peer+1, port=port),
            packet(t+.5, 'FA', peer+1, seq+6, True, port=port),
            packet(t+.6, 'A', seq+6, peer+2, port=port)]


def legacy_database(path):
    """Actual pre-instance schemas, including the historical application table."""
    with closing(sqlite3.connect(path)) as db:
        db.executescript('''
        CREATE TABLE capture_sessions(id TEXT PRIMARY KEY,interface TEXT NOT NULL,started REAL NOT NULL,stopped REAL,state TEXT NOT NULL);
        INSERT INTO capture_sessions VALUES('old','fixture',1000,1300,'stopped');
        CREATE TABLE session_flows(id INTEGER PRIMARY KEY,session_id TEXT NOT NULL,bucket INTEGER NOT NULL,
          src TEXT NOT NULL,dst TEXT NOT NULL,protocol TEXT NOT NULL,sport INTEGER NOT NULL,dport INTEGER NOT NULL,
          bytes INTEGER NOT NULL,packets INTEGER NOT NULL,records INTEGER NOT NULL,syn INTEGER NOT NULL,rst INTEGER NOT NULL,
          first REAL NOT NULL,last REAL NOT NULL,UNIQUE(session_id,bucket,src,dst,protocol,sport,dport));
        INSERT INTO session_flows VALUES(11,'old',960,'192.0.2.1','198.51.100.2','TCP',40000,443,300,5,5,2,0,1000,1005);
        CREATE TABLE session_connection_metrics(session_id TEXT NOT NULL,a TEXT NOT NULL,ap INTEGER NOT NULL,b TEXT NOT NULL,bp INTEGER NOT NULL,protocol TEXT NOT NULL,
          a_to_b_packets INTEGER NOT NULL,b_to_a_packets INTEGER NOT NULL,a_to_b_bytes INTEGER NOT NULL,b_to_a_bytes INTEGER NOT NULL,
          syn_seen INTEGER NOT NULL,syn_ack_seen INTEGER NOT NULL,fin_seen INTEGER NOT NULL,rst_seen INTEGER NOT NULL,
          client_is_a INTEGER,handshake_status TEXT NOT NULL,connection_state TEXT NOT NULL,first_seen REAL NOT NULL,last_seen REAL NOT NULL,
          PRIMARY KEY(session_id,a,ap,b,bp,protocol));
        INSERT INTO session_connection_metrics VALUES('old','192.0.2.1',40000,'198.51.100.2',443,'TCP',5,0,300,0,1,1,1,0,1,'CONFIRMED','CLOSED',1000,1005);
        CREATE TABLE session_applications(session_id TEXT NOT NULL,a TEXT NOT NULL,ap INTEGER NOT NULL,b TEXT NOT NULL,bp INTEGER NOT NULL,
          protocol TEXT NOT NULL,bucket INTEGER NOT NULL,endpoint_ip TEXT NOT NULL,endpoint_port INTEGER NOT NULL,role TEXT NOT NULL,pid INTEGER NOT NULL,
          process_created REAL NOT NULL,app TEXT NOT NULL,basis TEXT NOT NULL,confidence TEXT NOT NULL,matched_bytes INTEGER NOT NULL,matched_packets INTEGER NOT NULL,
          first_seen REAL NOT NULL,last_seen REAL NOT NULL,first_sampled REAL NOT NULL,last_sampled REAL NOT NULL,
          PRIMARY KEY(session_id,a,ap,b,bp,protocol,bucket,endpoint_ip,endpoint_port,role,pid,process_created,app,basis,confidence));
        INSERT INTO session_applications VALUES('old','192.0.2.1',40000,'198.51.100.2',443,'TCP',960,'192.0.2.1',40000,'socket_owner',9,999,'old.exe','snapshot','snapshot_match',300,5,1000,1005,1000,1005);
        CREATE TABLE capture_reports(session_id TEXT PRIMARY KEY,created REAL NOT NULL,answer TEXT NOT NULL,citation_valid INTEGER NOT NULL);
        INSERT INTO capture_reports VALUES('old',1301,'saved report',1);
        CREATE TABLE budget(id INTEGER PRIMARY KEY,calls INTEGER,reserved REAL,reported REAL);
        INSERT INTO budget VALUES(1,99,1.5,1.2);
        ''')


class InstanceTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')
        self.sid = self.store.start_session('synthetic')
        self.tracker = TCPStateTracker()

    def tearDown(self):
        self.store.close()

    def feed(self, packets, owner=None):
        rows = []
        for p in packets:
            row = packet_metadata(p, self.sid)
            self.tracker._annotate_tcp(row)
            if owner:
                row['application_observations'] = [dict(endpoint_ip='192.0.2.1', endpoint_port=40000,
                    role='socket_owner', pid=owner, process_created=900+owner, app=f'app{owner}.exe',
                    sampled_at=row['timestamp'], basis='test snapshot', confidence='snapshot_match')]
            rows.append(row)
        self.store.add(rows)
        return rows

    def metrics(self):
        return [r['metrics'] for r in self.store.session_connections(self.sid)['connections']]

    def args(self, metric):
        return dict(src=metric['source_ip'], dst=metric['destination_ip'], protocol='TCP',
                    sport=metric['source_port'], dport=metric['destination_port'], connection_id=metric['connection_id'])

    def test_closed_tuple_reuse_has_separate_counts_times_and_apps(self):
        first = self.feed(conversation(), owner=1)
        second = self.feed(conversation(1002, 200000, 1900000), owner=2)
        self.assertNotEqual(first[0]['connection_id'], second[0]['connection_id'])
        metrics = self.metrics()
        self.assertEqual(len(metrics), 2)
        self.assertEqual(sum(m['packets'] for m in metrics), 14)
        self.assertEqual(sum(m['bytes'] for m in metrics), sum(len(p) for p in conversation()+conversation(1002, 200000, 1900000)))
        for m in metrics:
            self.assertEqual(m['connection_state'], 'CLOSED')
            self.assertEqual(m['handshake_basis'], 'sequence_checked')
            self.assertAlmostEqual(m['duration'], .6)
            app = self.store.query_application_identity(self.sid, **self.args(m))
            self.assertEqual(len(app['observations']), 1)
            self.assertEqual(app['observations'][0]['matched_packets'], 7)
        history = self.store.session_connection_history(self.sid, **self.args(metrics[0]))
        self.assertEqual(history['packets'], 7)
        self.assertTrue(all(r['connection_id'] == metrics[0]['connection_id'] for r in history['timeline']))

    def test_syn_retransmissions_stay_one_instance(self):
        self.feed([packet(1000, 'S', 123), packet(1001, 'S', 123), packet(1002, 'S', 123)])
        m, = self.metrics()
        self.assertEqual(m['packets'], 3)
        self.assertEqual((m['handshake_status'], m['connection_state']), ('SYN_ONLY', 'UNKNOWN'))

    def test_identical_sequence_reuse_is_not_silently_attributed_to_old_instance(self):
        old = self.feed(conversation())
        repeated = self.feed(conversation(1002))
        self.assertNotEqual(old[0]['connection_id'], repeated[0]['connection_id'])
        self.assertTrue(repeated[0]['uncertainty_flags'] & FLAGS['ambiguous_packet'])
        self.assertTrue(all(r['connection_id'] != old[0]['connection_id'] for r in repeated))
        self.assertTrue(all(r['handshake_status'] != 'CONFIRMED' for r in repeated))
        self.assertEqual(sum(m['packets'] for m in self.metrics()), 14)

    def test_missing_new_handshake_after_close_does_not_inherit_success(self):
        old = self.feed(conversation())
        new = self.feed([packet(1002, 'PA', 8000000, 9000000, payload=b'new'),
                         packet(1003, 'PA', 8000003, 9000000, payload=b'bytes')])
        self.assertNotEqual(old[0]['connection_id'], new[0]['connection_id'])
        self.assertEqual(new[0]['connection_id'], new[1]['connection_id'])
        m = next(m for m in self.metrics() if m['connection_id'] == new[0]['connection_id'])
        self.assertEqual((m['packets'], m['connection_state']), (2, 'UNKNOWN'))
        self.assertIn('midstream', m['uncertainties'])

    def test_reset_ack_is_not_third_handshake_ack(self):
        self.feed([packet(1000, 'S', 10), packet(1001, 'SA', 20, 11, True), packet(1002, 'RA', 11, 21)])
        m, = self.metrics()
        self.assertEqual(m['connection_state'], 'UNKNOWN')
        self.assertNotEqual(m['handshake_status'], 'CONFIRMED')

    def test_new_isn_without_close_starts_new_uncertain_instance(self):
        self.feed(conversation()[:4])
        self.feed([packet(1001, 'S', 200000)])
        m = next(m for m in self.metrics() if m['first_seen'] == 1001)
        self.assertEqual(m['connection_state'], 'UNKNOWN')
        self.assertIn('replaced_without_close', m['uncertainties'])

    def test_rst_then_reopen_does_not_inherit_handshake(self):
        self.feed(conversation()[:3]+[packet(1000.3, 'R', 100001, 900001)])
        self.feed([packet(1001, 'S', 200000)])
        self.assertEqual({m['connection_state'] for m in self.metrics()}, {'CLOSED', 'UNKNOWN'})

    def test_midstream_and_idle_split_are_explicitly_unknown(self):
        self.feed([packet(1000, 'PA', 10, 20, payload=b'x'), packet(1400, 'PA', 11, 20, payload=b'y')])
        self.assertEqual(len(self.metrics()), 2)
        self.assertTrue(all(m['connection_state'] == 'UNKNOWN' and m['client_to_server_bytes'] is None for m in self.metrics()))
        self.assertTrue(any('idle_boundary' in m['uncertainties'] for m in self.metrics()))

    def test_missing_and_invalid_handshake_ack_never_confirm(self):
        self.feed([packet(1000, 'S', 10), packet(1001, 'SA', 20, 999, True), packet(1002, 'A', 11, 21)])
        m, = self.metrics()
        self.assertEqual(m['connection_state'], 'UNKNOWN')
        self.assertIn('sequence_mismatch', m['uncertainties'])

    def test_invalid_third_ack_never_confirms(self):
        self.feed([packet(1000, 'S', 10), packet(1001, 'SA', 20, 11, True), packet(1002, 'A', 11, 999)])
        m, = self.metrics()
        self.assertEqual(m['handshake_status'], 'SYN_ACK_SEEN')
        self.assertEqual(m['connection_state'], 'UNKNOWN')

    def test_sequence_number_wrap(self):
        self.feed([packet(1000, 'S', 2**32-1), packet(1001, 'SA', 2**32-1, 0, True), packet(1002, 'A', 0, 0)])
        self.assertEqual(self.metrics()[0]['handshake_status'], 'CONFIRMED')

    def test_reordered_handshake_does_not_retroactively_succeed(self):
        self.feed([packet(1001, 'SA', 20, 11, True), packet(1000, 'S', 10), packet(1002, 'A', 11, 21)])
        self.assertTrue(all(m['connection_state'] == 'UNKNOWN' for m in self.metrics()))
        self.assertTrue(any('out_of_order' in m['uncertainties'] for m in self.metrics()))

    def test_late_old_packet_does_not_change_new_instance_or_owner(self):
        first = self.feed(conversation())
        second = self.feed(conversation(1002, 200000, 1900000))
        late = conversation()[3]
        late.time = 1003
        row, = self.feed([late])
        self.assertEqual(row['connection_id'], first[0]['connection_id'])
        self.assertFalse(row['identity_match_allowed'])
        newer = next(m for m in self.metrics() if m['connection_id'] == second[0]['connection_id'])
        self.assertEqual(newer['packets'], 7)

    def test_unresolvable_generation_is_separate_and_not_attributed(self):
        self.feed(conversation())
        self.feed(conversation(1002, 200000, 1900000))
        row, = self.feed([packet(1003, 'PA', 77777777, 88888888, payload=b'?')])
        self.assertEqual(row['instance_kind'], 'ambiguous_fragment')
        self.assertIsNone(row['client_is_a'])
        self.assertFalse(row['identity_match_allowed'])
        self.assertEqual(len(self.metrics()), 3)

    def test_store_and_tools_reject_ambiguous_tuple_and_foreign_id(self):
        self.feed(conversation()+conversation(1002, 200000, 1900000))
        args = self.args(self.metrics()[0])
        toolset = Toolset(self.store, None, session_id=self.sid)
        self.assertTrue(toolset.call('query_connection', json.dumps(args))['ok'])
        history = toolset.call('session_connection_history', json.dumps(args))
        self.assertTrue(history['ok'], history)
        self.assertEqual(history['data']['connection_metrics_total'], 1)
        self.assertEqual(history['data']['packets'], 7)
        self.assertFalse(toolset.call('query_connection', json.dumps({k:v for k,v in args.items() if k != 'connection_id'}))['ok'])
        for name in ('query_connection', 'session_connection_history', 'query_application_identity', 'query_connection_baseline', 'query_similar_sessions', 'query_anomaly_evidence'):
            with self.subTest(tool=name):
                self.assertFalse(toolset.call(name, json.dumps({**args, 'connection_id': 'conn_'+'0'*32}))['ok'])

    def test_retaining_one_generation_preserves_only_its_identity_and_totals(self):
        self.feed(conversation(), owner=1)
        self.feed(conversation(1002, 200000, 1900000), owner=2)
        self.store.end_session(self.sid)
        rows = self.store.session_connections(self.sid)['connections']
        chosen = next(r for r in rows if r['metrics']['first_seen'] == 1000)
        result = self.store.retain_session_connections(self.sid, [chosen['key']])
        self.assertEqual((result['kept'], result['deleted']), (1, 1))
        self.assertEqual(self.store.session_summary(self.sid)['packets'], 7)
        self.assertEqual(self.store.db.execute('SELECT sum(packets) FROM flows').fetchone()[0], 7)
        identity = self.store.query_application_identity(self.sid, **self.args(chosen['metrics']))
        self.assertEqual([r['app'] for r in identity['observations']], ['app1.exe'])

    def test_short_connection_rule_counts_instances_without_changing_threshold(self):
        for i in range(20):
            self.feed(conversation(1000+i, 100000+i*100000, 900000+i*100000))
        result = self.store.session_anomaly_assessment(self.sid)
        self.assertEqual(result['total_connections'], 20)
        candidate, = result['candidate_pairs_first_20']
        self.assertEqual(candidate['anomaly_score'], 40)
        self.assertEqual(candidate['signals'][0]['observed']['short_closed_connections_same_port'], 20)

    def test_live_ranking_does_not_merge_generations(self):
        with patch('traffic_agent.connections.time.time', return_value=1004):
            tracker = ConnectionTracker(start=False)
            tracker.resolver.local_ips.add('192.0.2.1')
            rows = self.feed(conversation()+conversation(1002, 200000, 1900000))
            tracker.ingest(rows)
            self.assertEqual(tracker.snapshot()['count'], 2)
            tracker.close()

    def test_state_reset_never_reuses_identity(self):
        first = self.feed([packet(1000, 'S', 10)])[0]
        self.tracker.reset_tracking(lost=True)
        second = self.feed([packet(1001, 'A', 11, 20)])[0]
        self.assertNotEqual(first['connection_id'], second['connection_id'])
        self.assertTrue(second['uncertainty_flags'] & FLAGS['state_loss_possible'])

    def test_baseline_and_similar_history_keep_generation_references(self):
        history_ids = set()
        for index in range(4):
            if index:
                self.sid = self.store.start_session('synthetic')
                self.tracker = TCPStateTracker()
            start = 1000 * (index+1)
            self.feed(conversation(start)+conversation(start+2, 200000, 1900000))
            self.store.end_session(self.sid)
            with self.store.db:
                self.store.db.execute('UPDATE capture_sessions SET started=?,stopped=? WHERE id=?', (start, start+300, self.sid))
            if index < 3:
                self.store.set_session_normal(self.sid)
                history_ids.update(m['connection_id'] for m in self.metrics())
        args = self.args(self.metrics()[0])
        result = self.store.query_connection_baseline(self.sid, **args)
        self.assertEqual(result['baseline']['average_connection_count']['mean'], 2)
        self.assertEqual(result['baseline']['packets_per_connection']['mean'], 7)
        self.assertEqual(result['connection_comparison']['status'], 'available')
        similar = self.store.query_similar_sessions(self.sid, **args)
        self.assertEqual(similar['matching_connections'], 6)
        self.assertTrue(all(r['connection']['connection_id'] in history_ids for r in similar['matches']))
        # Historical aggregates cannot become an instance-count baseline.
        with self.store.db:
            self.store.db.execute("UPDATE session_connection_metrics SET instance_kind='legacy_aggregate' WHERE session_id<>?", (self.sid,))
        self.assertEqual(self.store.query_connection_baseline(self.sid, **args)['baseline']['capture_count'], 0)

    def test_native_investigation_is_bound_to_one_generation(self):
        from traffic_agent.agent import Agent
        from traffic_agent.config import Config
        from traffic_agent.investigation import Investigation, STEPS
        from test_investigation import FunctionCallingFixture
        self.feed(conversation()+conversation(1002, 200000, 1900000))
        first, second = self.metrics()
        target = self.args(first)
        investigation = Investigation(target)
        self.assertFalse(investigation.accepts('query_connection', json.dumps(self.args(second))))
        self.assertFalse(investigation.accepts('query_connection', json.dumps({k:v for k,v in target.items() if k != 'connection_id'})))
        result = Agent(self.store, None, Config(), 'scripted-key', FunctionCallingFixture()).run(
            '调查选定连接实例', session_id=self.sid, investigation_target=target)
        self.assertTrue(result['ok'], result)
        self.assertEqual([r['name'] for r in result['trace']], ['session_summary', *STEPS])
        self.assertEqual(result['investigation_report']['investigated_connection'], target)

    def test_late_packet_identity_cannot_be_saved_as_current_owner(self):
        self.feed(conversation(), owner=1)
        self.feed(conversation(1002, 200000, 1900000), owner=2)
        late = conversation()[3]
        late.time = 1003
        row, = self.feed([late], owner=2)
        metric = next(m for m in self.metrics() if m['connection_id'] == row['connection_id'])
        result = self.store.query_application_identity(self.sid, **self.args(metric))
        self.assertEqual([r['app'] for r in result['observations']], ['app1.exe'])

    def test_pre_generation_process_and_proxy_snapshots_are_not_reused(self):
        self.feed(conversation(), owner=1)
        with patch('traffic_agent.connections.time.time', return_value=1002.5):
            live = ConnectionTracker(start=False)
            try:
                live.resolver.local_ips.add('192.0.2.1')
                live.resolver.sampled_at = 1001.9  # Fresh by age, but belongs before the new SYN.
                key = ('192.0.2.1', 40000, '198.51.100.2', 443)
                live.resolver.tcp = {key: {1: dict(pid=1, created=901, app='old.exe')}}
                proxy = dict(endpoint_ip='192.0.2.1', endpoint_port=40000, role='proxy_original',
                    app='old-proxy-app.exe', sampled_at=1002.5, connection_started=1000,
                    basis='test', confidence='inferred')
                rows = []
                for p in conversation(1002, 200000, 1900000)[:3]:
                    row = packet_metadata(p, self.sid)
                    self.tracker._annotate_tcp(row)
                    rows.append(row)
                with patch.object(live.proxy, 'identify_wire', return_value=[proxy]):
                    live.annotate(rows)
                self.assertTrue(all(not r['application_observations'] and r['owner'] is None for r in rows))
                self.store.add(rows)
                live.resolver.sampled_at = 1002.3
                live.resolver.tcp = {key: {2: dict(pid=2, created=902, app='new.exe')}}
                row = packet_metadata(conversation(1002, 200000, 1900000)[3], self.sid)
                self.tracker._annotate_tcp(row)
                live.annotate([row])
                self.store.add([row])
                current = next(m for m in self.metrics() if m['connection_id'] == row['connection_id'])
                identity = self.store.query_application_identity(self.sid, **self.args(current))
                self.assertEqual([o['app'] for o in identity['observations']], ['new.exe'])
                self.assertEqual(identity['observations'][0]['matched_packets'], 1)
            finally:
                live.close()

    def test_replay_logical_instances_and_v2_export_are_deterministic(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'reused.pcap'
            wrpcap(str(path), conversation()+conversation(1002, 200000, 1900000))
            with Replay(path) as a, Replay(path) as b:
                self.assertEqual(a.record, b.record)
                self.assertEqual(a.detection, b.detection)
                self.assertEqual(len(a.record['features']['connections']), 2)
                validate_record({**a.record, 'label': 0})
                with self.assertRaisesRegex(ValueError, '五元组复用'):
                    legacy_feature_view(a.record['features'])
                data = json.loads(json.dumps(a.record))
                data['features']['connections'][1]['connection_id'] = data['features']['connections'][0]['connection_id']
                with self.assertRaises(ValueError):
                    validate_record({**data, 'label': 0})


class MigrationTests(unittest.TestCase):
    def test_backup_includes_committed_wal_rows(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'wal.db'
            legacy_database(path)
            with closing(sqlite3.connect(path)) as writer:
                writer.execute('PRAGMA journal_mode=WAL')
                writer.execute('PRAGMA wal_autocheckpoint=0')
                writer.execute('UPDATE budget SET calls=101')
                writer.commit()
                self.assertTrue(Path(str(path)+'-wal').exists())
                with closing(Store(path)) as store:
                    with closing(sqlite3.connect(store.migration_backup)) as backup:
                        self.assertEqual(backup.execute('SELECT calls FROM budget').fetchone()[0], 101)

    def test_old_rows_apps_reports_budget_backup_and_restore(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'old.db'
            legacy_database(path)
            with closing(Store(path)) as store:
                self.assertEqual(store.db.execute('PRAGMA user_version').fetchone()[0], SCHEMA_VERSION)
                row, = store.session_connections('old')['connections']
                self.assertEqual(row['bytes'], 300)
                self.assertEqual(row['metrics']['instance_kind'], 'legacy_aggregate')
                self.assertEqual(row['metrics']['uncertainties'], ['legacy_aggregate'])
                self.assertIn('不能恢复为精确连接实例', row['metrics']['observation_notice'])
                self.assertEqual(row['application_identity']['observations'][0]['app'], 'old.exe')
                self.assertEqual(store.session_report('old')['answer'], 'saved report')
                self.assertEqual(store.usage()['calls'], 99)
                backup = store.migration_backup
                self.assertIsNotNone(backup)
                original_id = row['connection_id']
            with closing(Store(path)) as reopened:
                self.assertIsNone(reopened.migration_backup)
                self.assertEqual(reopened.session_connections('old')['connections'][0]['connection_id'], original_id)
            restored = Path(folder)/'restored.db'
            restore_copy(backup, restored)
            with closing(sqlite3.connect(restored)) as db:
                self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 0)
                self.assertEqual(db.execute('SELECT bytes FROM session_flows').fetchone()[0], 300)
            with self.assertRaises(ValueError):
                restore_copy(backup, path)

    def test_ddl_failure_rolls_back_all_tables_and_keeps_backup(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'old.db'
            legacy_database(path)
            with closing(sqlite3.connect(path)) as db:
                before = list(db.iterdump())
            def fail_after_migration(db):
                migrate(db)
                raise RuntimeError('injected migration failure')
            with patch('traffic_agent.store.migrate', side_effect=fail_after_migration), self.assertRaises(RuntimeError):
                Store(path)
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(list(db.iterdump()), before)
                self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            self.assertEqual(len(list((Path(folder)/'backups').glob('*.sqlite'))), 1)
            with closing(Store(path)) as store:
                self.assertEqual(store.session_connections('old')['total'], 1)

    def test_backup_failure_prevents_any_schema_change(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'old.db'
            legacy_database(path)
            with patch('traffic_agent.store.prepare_backup', side_effect=OSError('disk full')), self.assertRaises(OSError):
                Store(path)
            with closing(sqlite3.connect(path)) as db:
                self.assertNotIn('connection_id', [r[1] for r in db.execute('PRAGMA table_info(session_flows)')])
                self.assertEqual(db.execute('SELECT bytes FROM session_flows').fetchone()[0], 300)

    def test_future_schema_is_rejected_without_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'future.db'
            with closing(sqlite3.connect(path)) as db:
                db.execute('PRAGMA user_version=999')
            before = path.read_bytes()
            with self.assertRaises(RuntimeError):
                Store(path)
            self.assertEqual(path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
