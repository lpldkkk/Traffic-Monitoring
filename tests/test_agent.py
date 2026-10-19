"""Deterministic simulated model tests; these do not prove real LLM quality."""
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / ".runtime"))

from traffic_agent.agent import Agent, Monitor, HTTPTransport, redact_text, CONTEXT_LIMIT_BYTES, model_tool_view
from traffic_agent.capture import Collector, seed_simulation
from traffic_agent.config import Config
from traffic_agent.store import Store
from traffic_agent.tools import Toolset


def response(content=None, calls=None):
    return {"choices": [{"message": {"role": "assistant", "content": content, "tool_calls": calls},
                         "finish_reason": "tool_calls" if calls else "stop"}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50}}


def call(name, args, ident="call_1"):
    return {"id": ident, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


class ModelFixture:
    """Next tool arguments depend on the previous actual tool result."""
    def __init__(self):
        self.bodies = []

    def complete(self, config, key, body):
        self.bodies.append(json.loads(json.dumps(body)))
        results = [json.loads(m["content"]) for m in body["messages"] if m["role"] == "tool"]
        if not results:
            return response(calls=[call("protocol_stats", {})])
        if len(results) == 1:
            # Pick the lower-volume scanner host using actual returned counters.
            host = min(results[-1]["data"]["top_hosts"], key=lambda n: n["out_bytes"] if n["out_bytes"] else float("inf"))["host"]
            return response(calls=[call("analyze_ip", {"host": host}, "call_2")])
        if len(results) == 2:
            return response(calls=[call("query_history", {"host": results[-1]["data"]["host"]}, "call_3")])
        return response("[模拟模型] 来源 simulation；观察到端口分散，需要进一步验证。证据 " + results[1]["evidence_id"])


class Base(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.collector = Collector(self.store)
        self.config = Config(input_price=1.0, output_price=2.0)

    def tearDown(self):
        self.collector.close()
        self.store.close()

    def row(self, **kw):
        return dict(dict(source="live", src="192.0.2.1", dst="198.51.100.2", protocol="TCP", sport=12345, dport=443, bytes=100), **kw)


class StoreTests(Base):
    def test_existing_capture_gets_stable_number_and_incomplete_label(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'legacy.db'
            db = sqlite3.connect(path)
            db.execute('CREATE TABLE capture_sessions(id TEXT PRIMARY KEY,interface TEXT NOT NULL,started REAL NOT NULL,stopped REAL,state TEXT NOT NULL)')
            db.execute("INSERT INTO capture_sessions VALUES('old','adapter',100,200,'stopped')")
            db.commit()
            db.close()
            migrated = Store(path)
            self.assertEqual(migrated._session('old')['number'], 1)
            self.assertTrue(migrated.session_summary('old')['legacy_incomplete'])
            migrated.close()
            reopened = Store(path)
            try:
                self.assertEqual(reopened._session('old')['number'], 1)
                sid = reopened.start_session('adapter')
                self.assertEqual(reopened._session(sid)['number'], 2)
                self.assertFalse(reopened.session_summary(sid)['legacy_incomplete'])
            finally:
                reopened.close()

    def test_legacy_session_flow_has_unknown_connection_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'legacy-with-flow.db'
            old = Store(path)
            sid = old.start_session('adapter')
            old.add([self.row(session_id=sid, timestamp=time.time(), syn=1)])
            old.end_session(sid)
            old.db.execute('DROP TABLE session_connection_metrics')
            old.db.commit()
            old.close()
            migrated = Store(path)
            try:
                metric = migrated.session_connections(sid)['connections'][0]['metrics']
                self.assertEqual(metric['packets'], 1)
                self.assertEqual(metric['connection_state'], 'UNKNOWN')
                self.assertEqual(metric['handshake_status'], 'NOT_OBSERVED')
                self.assertIsNone(metric['syn_seen'])
                self.assertIsNone(metric['client_to_server_bytes'])
                assessment = migrated.session_anomaly_assessment(sid)
                self.assertEqual(assessment['status'], 'insufficient_evidence')
                self.assertEqual(assessment['unassessed_legacy_connections'], 1)
            finally:
                migrated.close()

    def test_ten_numbered_capture_slots_and_explicit_deletion(self):
        sessions = []
        for number in range(1, 11):
            sid = self.store.start_session('adapter-A')
            self.store.end_session(sid)
            self.assertEqual(self.store._session(sid)['number'], number)
            sessions.append(sid)
        self.assertEqual(len(self.store.list_sessions()), 10)
        with self.assertRaisesRegex(ValueError, '10 次采集'):
            self.store.start_session('adapter-A')
        self.store.delete_session(sessions[0])
        next_sid = self.store.start_session('adapter-A')
        self.assertEqual(self.store._session(next_sid)['number'], 11)
        self.assertEqual(len(self.store.list_sessions()), 10)

    def test_saved_capture_survives_global_seven_day_prune(self):
        sid = self.store.start_session('adapter-A')
        self.store.add([self.row(session_id=sid, timestamp=time.time()-8*86400, bytes=77)])
        self.store.end_session(sid)
        self.store.prune()
        self.assertEqual(self.store.session_summary(sid)['bytes'], 77)
        self.assertEqual(self.store.session_summary(sid)['flow_buckets'], 1)

    def test_keep_selected_bidirectional_connection_and_invalidate_report(self):
        start = int(time.time() // 60) * 60
        first = self.store.start_session('adapter-A')
        second = self.store.start_session('adapter-A')
        a = self.row(session_id=first, timestamp=start, sport=12345, dport=443, bytes=100)
        reverse = self.row(session_id=first, timestamp=start+1, src='198.51.100.2', dst='192.0.2.1',
                           sport=443, dport=12345, bytes=30)
        unwanted = self.row(session_id=first, timestamp=start+2, sport=12345, dport=80, bytes=50)
        also_other_session = self.row(session_id=second, timestamp=start+3, sport=12345, dport=80, bytes=20)
        self.store.add([a, reverse, unwanted, also_other_session])
        self.store.end_session(first)
        self.store.end_session(second)
        self.store.save_session_report(first, '旧报告', True)
        revision = self.store._session(first)['revision']
        all_keys = [row['key'] for row in self.store.session_connections(first)['connections']]
        self.assertFalse(self.store.retain_session_connections(first, all_keys)['changed'])
        self.assertEqual(self.store.session_report(first)['answer'], '旧报告')
        listing = self.store.session_connections(first, page_size=1)
        self.assertEqual((listing['total'], listing['pages']), (2, 2))
        self.assertEqual(self.store.session_connections(first, search='443')['total'], 1)
        kept = listing['connections'][0]['key']
        result = self.store.retain_session_connections(first, [kept])
        self.assertEqual((result['kept'], result['deleted']), (1, 1))
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM session_connection_metrics WHERE session_id=?',
                                               (first,)).fetchone()[0], 1)
        self.assertEqual(self.store.session_summary(first)['bytes'], 130)
        self.assertTrue(self.store.session_summary(first)['filtered'])
        self.assertEqual(self.store.session_summary(second)['bytes'], 20)
        self.assertEqual(self.store.summary('live')['bytes'], 150)
        remaining_port_80 = next(row for row in self.store.read('live') if row['dport'] == 80)
        self.assertEqual(remaining_port_80['first'], start+3)
        self.assertIsNone(self.store.session_report(first))
        self.assertFalse(self.store.save_session_report(first, '过期报告', True, revision))
        self.assertIsNone(self.store.session_report(first))
        self.store.delete_session(first)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM session_connection_metrics WHERE session_id=?',
                                               (first,)).fetchone()[0], 0)
        self.assertEqual(self.store.summary('live')['bytes'], 20)

    def test_capture_sessions_isolate_same_minute_and_persist_reports(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'session.db'
            store = Store(p)
            try:
                first = store.start_session('adapter-A')
                store.add([self.row(session_id=first, bytes=100, syn=1)])
                store.end_session(first)
                second = store.start_session('adapter-A')
                store.add([self.row(session_id=second, bytes=300, rst=1)])
                store.end_session(second)
                self.assertEqual(store.session_summary(first)['bytes'], 100)
                self.assertEqual(store.session_summary(second)['bytes'], 300)
                self.assertEqual(store.summary()['bytes'], 400)
                store.save_session_report(second, '有证据的结论', True)
            finally:
                store.close()
            reopened = Store(p)
            try:
                self.assertEqual(reopened.latest_session()['id'], second)
                self.assertEqual(reopened.session_summary(first)['syn'], 1)
                self.assertEqual(reopened.session_summary(second)['rst'], 1)
                self.assertEqual(reopened.session_report(second)['answer'], '有证据的结论')
            finally:
                reopened.close()

    def test_session_pair_and_five_tuple_timeline_pagination(self):
        sid = self.store.start_session('test-interface')
        now = time.time()-3600
        rows = []
        for i in range(55):
            rows.append(self.row(session_id=sid, timestamp=now+i*60, sport=12345, dport=443, bytes=100, syn=1))
        rows.append(self.row(session_id=sid, timestamp=now+60, src='198.51.100.2', dst='192.0.2.1',
                             sport=443, dport=12345, bytes=50))
        rows.append(self.row(session_id=sid, timestamp=now+60, sport=12345, dport=80, bytes=20))
        self.store.add(rows)
        self.store.end_session(sid)
        a, b = self.store.alias('192.0.2.1'), self.store.alias('198.51.100.2')
        first = self.store.session_connection_history(sid, a, b, 'TCP', 12345, 443)
        second = self.store.session_connection_history(sid, a, b, 'TCP', 12345, 443, page=2)
        self.assertEqual((first['flow_buckets'], first['pages'], len(first['timeline']), len(second['timeline'])), (56, 2, 50, 6))
        self.assertEqual(first['bytes'], 5550)
        self.assertEqual(self.store.session_connection_history(sid, a, b, 'TCP')['flow_buckets'], 57)
        self.assertEqual(self.store.session_summary(sid)['flow_buckets'], 57)
        self.assertNotIn('192.0.2.1', json.dumps(first))

    def test_aggregation_source_isolation_and_https_both_directions(self):
        self.store.add([self.row(), self.row(), self.row(source="csv", packets=0),
                        self.row(src="198.51.100.2", dst="192.0.2.1", sport=443, dport=12345, bytes=200)])
        live = self.store.summary()
        self.assertEqual(live["bytes"], 400)
        self.assertEqual(live["packets"], 3)
        self.assertEqual(live["flow_buckets"], 2)
        self.assertEqual(live["top_hosts"][0]["https_bytes"], 400)
        self.assertEqual(self.store.summary("csv")["packets"], 0)

    def test_existing_csv(self):
        from sample_data import course_csv
        result = self.store.import_csv(course_csv(self))
        self.assertGreater(result["imported"], 0)
        self.assertEqual(self.store.summary("csv")["packets"], 0)
        self.assertEqual(self.store.summary("live")["bytes"], 0)

    def test_csv_empty_ports_and_bad_rows(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "test.csv"
            p.write_text("Source,Destination,Protocol,SrcPort,DstPort,DataSize,Duration\n192.0.2.1,198.51.100.2,1,,,90,0.1\nbad,198.51.100.2,6,1,2,90,1\n192.0.2.1,198.51.100.2,6,1,2,90,NaN\n", encoding="utf-8")
            result = self.store.import_csv(p)
            self.assertEqual((result["imported"], result["rejected"]), (1, 2))
            flow = self.store.flow_query("csv")["flows"][0]
            self.assertEqual((flow["sport"], flow["dport"]), (0, 0))

    def test_historical_buckets_and_retention(self):
        now = time.time()
        self.store.add([self.row(timestamp=now-600), self.row(timestamp=now-10), self.row(timestamp=now-8*86400)])
        self.assertEqual(self.store.summary(seconds=60)["packets"], 1)
        self.assertEqual(len(self.store.history(seconds=3600)["bins"]), 2)
        self.store.prune()
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM flows").fetchone()[0], 2)

    def test_graph_is_observed_directed_path(self):
        self.store.add([self.row(), self.row(src="198.51.100.2", dst="203.0.113.3")])
        result = self.store.graph(host="192.0.2.1", target="203.0.113.3")
        self.assertEqual(len(result["directed_path"]), 3)
        self.assertIn("不代表", result["meaning"])

    def test_persistent_alias_and_budget(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "db"
            a = Store(p)
            alias = a.alias("192.0.2.1")
            a.reserve(.1, self.config)
            a.close()
            b = Store(p)
            self.assertEqual(b.alias("192.0.2.1"), alias)
            self.assertEqual(b.usage()["calls"], 1)
            b.close()

    def test_cap_rows(self):
        self.store.max_rows = 2
        self.store.add([self.row(dport=i) for i in range(5)])
        self.store.prune()
        self.assertEqual(len(self.store.read()), 2)


class ToolTests(Base):
    def test_tcp_handshake_directional_metrics_and_close(self):
        from scapy.all import IP, TCP, Raw
        sid = self.store.start_session('synthetic-test-interface')
        self.collector.session_id = sid
        stamp = time.time()
        packets = [
            IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=50101, dport=8080, flags='S', seq=100),
            IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=8080, dport=50101, flags='SA', seq=500, ack=101),
            IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=50101, dport=8080, flags='A', seq=101, ack=501),
            IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=50101, dport=8080, flags='PA', seq=101, ack=501)/Raw(b'GET / HTTP/1.0\r\n\r\n'),
            IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=8080, dport=50101, flags='FA', seq=501, ack=119),
            IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=50101, dport=8080, flags='FA', seq=119, ack=502),
        ]
        for index, packet in enumerate(packets[:5]):
            packet.time = stamp + index * .25
            self.collector._packet(packet)
        self.collector.queue.join()
        self.assertEqual(self.store.session_connections(sid)['connections'][0]['metrics']['connection_state'], 'ESTABLISHED')
        packets[5].time = stamp + 1.25
        self.collector._packet(packets[5])
        self.collector.queue.join()
        self.store.end_session(sid)
        flow = self.store.session_summary(sid)['top_flows_first_20'][0]
        args = {k: flow[k] for k in ('src', 'dst', 'protocol')}
        args.update(sport=50101, dport=8080)
        result = Toolset(self.store, self.collector, 'live', sid).call('session_connection_history', json.dumps(args))
        self.assertTrue(result['ok'], result)
        metric = result['data']['connection_metrics'][0]
        self.assertEqual(metric['connection_state'], 'CLOSED')
        self.assertEqual(metric['handshake_status'], 'CONFIRMED')
        self.assertEqual((metric['syn_seen'], metric['syn_ack_seen'], metric['fin_seen'], metric['rst_seen']), (1, 1, 1, 0))
        self.assertEqual((metric['client_to_server_packets'], metric['server_to_client_packets']), (4, 2))
        self.assertEqual(metric['client_to_server_bytes'], sum(len(p) for p in (packets[0], packets[2], packets[3], packets[5])))
        self.assertEqual(metric['server_to_client_bytes'], sum(len(p) for p in (packets[1], packets[4])))
        self.assertAlmostEqual(metric['duration'], 1.25)
        self.assertTrue(metric['short_connection_flag'])
        self.assertGreater(metric['packets_per_second'], 0)
        self.assertNotIn('127.0.0.1', json.dumps(result))

    def test_syn_only_and_midstream_stay_unknown(self):
        from scapy.all import IP, TCP
        sid = self.store.start_session('synthetic-test-interface')
        self.collector.session_id = sid
        packets = [IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=50102, dport=8080, flags='S'),
                   IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=50103, dport=8080, flags='A'),
                   IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=8080, dport=50103, flags='FA'),
                   IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=8080, dport=50104, flags='SA'),
                   IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=50104, dport=8080, flags='R')]
        for packet in packets:
            self.collector._packet(packet)
        self.collector.queue.join()
        metrics = {max(row['ap'], row['bp']): row['metrics'] for row in self.store.session_connections(sid)['connections']}
        self.assertEqual(metrics[50102]['connection_state'], 'UNKNOWN')
        self.assertEqual(metrics[50102]['handshake_status'], 'SYN_ONLY')
        self.assertEqual(metrics[50103]['connection_state'], 'UNKNOWN')
        self.assertEqual(metrics[50103]['handshake_status'], 'UNKNOWN')
        self.assertIsNone(metrics[50103]['client_to_server_packets'])
        self.assertIsNone(metrics[50103]['short_connection_flag'])
        self.assertEqual(metrics[50103]['fin_seen'], 1)
        self.assertEqual(metrics[50104]['connection_state'], 'UNKNOWN')
        self.assertEqual((metrics[50104]['syn_ack_seen'], metrics[50104]['rst_seen']), (1, 1))

    def test_port_sweep_is_ranked_but_one_syn_is_not_failure(self):
        sid = self.store.start_session('synthetic-test-interface')
        stamp = time.time()
        self.store.add([self.row(session_id=sid, timestamp=stamp+i, sport=40000+i,
                                 dport=2000+i, bytes=60, syn=1, client_is_a=1,
                                 handshake_status='SYN_ONLY', connection_state='UNKNOWN')
                        for i in range(22)])
        assessment = self.store.session_anomaly_assessment(sid)
        self.assertEqual(assessment['status'], 'assessed')
        self.assertEqual(assessment['candidate_pairs_total'], 1)
        candidate = assessment['candidate_pairs_first_20'][0]
        self.assertGreaterEqual(candidate['score'], 70)
        self.assertIn('PORT_SWEEP', [signal['code'] for signal in candidate['signals']])
        self.assertNotIn('192.0.2.1', json.dumps(assessment))
        tool = Toolset(self.store, self.collector, 'live', sid)
        summary = tool.call('session_summary', '{}')
        self.assertTrue(summary['ok'])
        self.assertEqual(summary['data']['anomaly_assessment']['candidate_pairs_total'], 1)
        history = tool.call('session_connection_history', json.dumps({
            'src': candidate['src'], 'dst': candidate['dst'], 'protocol': 'TCP',
            'sport': 40000, 'dport': 2000}))
        self.assertTrue(history['ok'], history)
        self.assertEqual(history['data']['connection_metrics'][0]['assessment']['status'], 'insufficient_evidence')
        self.assertEqual(history['data']['pair_assessment']['candidate_pairs_total'], 1)
        self.store.end_session(sid)
        keep = self.store.session_connections(sid, page_size=1)['connections'][0]['key']
        self.store.retain_session_connections(sid, [keep])
        self.assertEqual(self.store.session_anomaly_assessment(sid)['candidate_pairs_total'], 0)

    def test_few_normal_connections_and_midstream_are_not_candidates(self):
        sid = self.store.start_session('synthetic-test-interface')
        stamp = time.time()
        rows = []
        for i in range(3):
            rows.extend([self.row(session_id=sid, timestamp=stamp+i, sport=45000+i,
                                  dport=443, bytes=100, client_is_a=1,
                                  handshake_status='CONFIRMED', connection_state='HANDSHAKE_CONFIRMED'),
                         self.row(session_id=sid, timestamp=stamp+i+.5, sport=45000+i,
                                  dport=443, bytes=50, fin=1, client_is_a=1,
                                  handshake_status='CONFIRMED', connection_state='CLOSED')])
        rows.append(self.row(session_id=sid, timestamp=stamp+4, sport=46000, dport=80,
                             bytes=50, handshake_status='UNKNOWN', connection_state='UNKNOWN'))
        self.store.add(rows)
        assessment = self.store.session_anomaly_assessment(sid)
        self.assertEqual(assessment['candidate_pairs_total'], 0)
        self.assertEqual(assessment['watch_connections_total'], 0)
        self.assertEqual(assessment['unknown_direction_connections'], 1)
        self.assertEqual(assessment['evaluated_connections'], 3)

    def test_behavior_windows_do_not_combine_scattered_resets(self):
        for spacing, expected in ((1, 1), (301, 0)):
            sid = self.store.start_session('synthetic-reset-fixture')
            stamp = time.time() - 10000
            rows = []
            for i in range(15):
                for offset, state, rst in ((0, 'HANDSHAKE_CONFIRMED', 0), (1, 'CLOSED', 1)):
                    rows.append(self.row(session_id=sid, timestamp=stamp+i*spacing+offset,
                        sport=48000+i, dport=443, bytes=60, rst=rst, client_is_a=1,
                        handshake_status='CONFIRMED', connection_state=state))
            self.store.add(rows)
            assessment = self.store.session_anomaly_assessment(sid)
            self.assertEqual(assessment['candidate_pairs_total'], expected)
            if expected:
                signal = assessment['candidate_pairs_first_20'][0]['signals'][0]
                self.assertEqual(signal['code'], 'RESET_BURST')
                self.assertEqual(signal['observed']['rst_connections'], 15)
                self.assertEqual(signal['thresholds']['window_seconds'], 300)

    def test_non_tcp_is_not_assessed_and_pair_query_is_protocol_scoped(self):
        sid = self.store.start_session('synthetic-mixed-protocol-fixture')
        stamp = time.time()
        self.store.add([self.row(session_id=sid, timestamp=stamp+i, sport=40000+i,
                                 dport=2000+i, bytes=60, syn=1, client_is_a=1,
                                 handshake_status='SYN_ONLY', connection_state='UNKNOWN')
                        for i in range(22)])
        self.store.add([self.row(session_id=sid, protocol='UDP', sport=50000, dport=53)])
        assessment = self.store.session_anomaly_assessment(sid)
        self.assertEqual(assessment['non_tcp_connections'], 1)
        self.assertEqual(assessment['status'], 'partial')
        history = self.store.session_connection_history(sid, self.store.alias('192.0.2.1'),
                                                       self.store.alias('198.51.100.2'), 'UDP')
        self.assertEqual(history['pair_assessment']['candidate_pairs_total'], 0)
        self.assertEqual(history['connection_metrics'][0]['assessment']['status'], 'not_applicable')

    def test_all_candidates_available_locally_but_model_summary_is_bounded(self):
        sid = self.store.start_session('synthetic-many-pairs-fixture')
        stamp = time.time()
        self.store.add([self.row(session_id=sid, timestamp=stamp+i, dst=f'198.51.100.{host}',
            sport=40000+i, dport=2000+i, bytes=60, syn=1, client_is_a=1,
            handshake_status='SYN_ONLY', connection_state='UNKNOWN')
            for host in range(1, 22) for i in range(20)])
        local = self.store.session_anomaly_assessment(sid, include_all=True)
        self.assertEqual(len(local['candidate_pairs_all']), 21)
        self.assertNotIn('198.51.100.', json.dumps(local))
        summary = self.store.session_summary(sid)['anomaly_assessment']
        self.assertEqual(summary['candidate_pairs_total'], 21)
        self.assertEqual(len(summary['candidate_pairs_first_20']), 20)
        self.assertNotIn('candidate_pairs_all', summary)

    def test_bulk_transfer_is_only_a_watch_signal_and_unknown_stays_uncertain(self):
        from traffic_agent.anomaly import assess_connection
        metric = dict(protocol='TCP', handshake_status='CONFIRMED',
            client_to_server_bytes=59*1024*1024, bytes=60*1024*1024,
            bytes_per_second=1024*1024, packets=50000, packets_per_second=833, duration=60)
        result = assess_connection(metric)
        self.assertEqual(result['status'], 'watch')
        self.assertFalse(result['review_required'])
        self.assertEqual(result['signals'][0]['code'], 'BULK_OUTBOUND')
        result = assess_connection({**metric, 'handshake_status': 'UNKNOWN'})
        self.assertEqual(result['status'], 'insufficient_evidence')
        self.assertEqual(result['score'], 0)

    def test_session_tools_are_bound_and_model_receives_only_aliases(self):
        sid = self.store.start_session('test-interface')
        self.store.add([self.row(session_id=sid, syn=1)])
        tool = Toolset(self.store, self.collector, 'live', sid)
        self.assertEqual({d['function']['name'] for d in tool.definitions}, {'session_summary', 'session_connection_history', 'query_connection',
                         'query_connection_baseline', 'query_anomaly_evidence', 'query_similar_sessions', 'query_application_identity',
                         'list_incidents', 'get_incident', 'query_incident_members', 'query_incident_timeline',
                         'query_incident_evidence', 'query_unassociated_findings'})
        summary = tool.call('session_summary', '{}')
        self.assertTrue(summary['ok'])
        self.assertNotIn('192.0.2.1', json.dumps(summary))
        flow = summary['data']['top_flows_first_20'][0]
        args = {k: flow[k] for k in ('src', 'dst', 'protocol', 'sport', 'dport')}
        history = tool.call('session_connection_history', json.dumps(args))
        self.assertTrue(history['ok'])
        self.assertEqual(history['data']['bytes'], 100)
        self.assertFalse(tool.call('query_flows', '{}')['ok'])
        self.assertFalse(tool.call('session_connection_history', json.dumps({**args, 'src': 'host_0000000000000000'}))['ok'])

    def test_unknown_and_invalid_tools_cannot_execute(self):
        tools = Toolset(self.store, self.collector)
        for name, arg in [("exec", '{"cmd":"whoami"}'), ("capture_traffic", '{"seconds":999}'),
                          ("query_flows", '{"limit":true}'), ("protocol_stats", '{"sql":"SELECT 1"}'),
                          ("protocol_stats", "not json"), ("analyze_ip", '{"host":"192.0.2.1"}')]:
            self.assertFalse(tools.call(name, arg)["ok"])

    def test_no_packet_payload_or_raw_address_in_egress(self):
        from scapy.all import Ether, IP, TCP, Raw
        packet = Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:66")/IP(src="192.0.2.1", dst="198.51.100.2")/TCP(dport=443, flags="S")/Raw(b"PASSWORD=secret-content")
        self.collector._packet(packet)
        self.collector.queue.join()
        tool = Toolset(self.store, self.collector)
        result = json.dumps(tool.call("query_flows", "{}"))
        self.assertNotIn("192.0.2.1", result)
        self.assertNotIn("secret-content", result)
        self.assertEqual(self.store.summary()["packets"], 1)
        self.assertEqual(self.store.read()[0]["syn"], 1)

    def test_no_implicit_live_interface(self):
        result = Toolset(self.store, self.collector).call("capture_traffic", '{"seconds":1}')
        self.assertFalse(result["ok"])
        self.assertIn("网卡", result["error"])

    def test_ipv6_metadata_and_tunnel_not_misattributed(self):
        from scapy.all import IPv6, IP, TCP, UDP
        self.collector._packet(IPv6(src="2001:db8::1", dst="2001:db8::2")/UDP(sport=1234, dport=53))
        self.collector._packet(IP(src="192.0.2.1", dst="198.51.100.2")/IP(src="192.0.2.3", dst="198.51.100.4")/TCP(dport=80))
        self.collector.queue.join()
        rows = self.store.read()
        self.assertEqual({r["protocol"] for r in rows}, {"UDP", "OTHER"})
        self.assertEqual(next(r for r in rows if r["protocol"] == "OTHER")["dport"], 0)

    def test_local_ip_mapping_is_not_a_model_tool(self):
        self.store.add([self.row()])
        self.assertIn("192.0.2.1", json.dumps(self.store.local_hosts()))
        self.assertFalse(Toolset(self.store, self.collector).call("local_hosts", "{}")["ok"])

    def test_offline_cannot_claim_capture(self):
        self.assertFalse(Toolset(self.store, self.collector, "csv").call("capture_traffic", '{"seconds":1}')["ok"])


class AgentTests(Base):
    def test_long_output_is_not_capped_and_actual_cost_blocks_later_calls(self):
        seed_simulation(self.store)
        long_answer = '这是一份较长的模拟调查报告。' * 1000 + '完整结尾'
        class LongModel:
            def __init__(self):
                self.bodies = []

            def complete(self, config, key, body):
                self.bodies.append(json.loads(json.dumps(body)))
                results = [json.loads(m['content']) for m in body['messages'] if m['role'] == 'tool']
                if not results:
                    return response(calls=[call('protocol_stats', {})])
                result = response(long_answer + results[-1]['evidence_id'])
                result['usage']['completion_tokens'] = 5000
                return result

        model = LongModel()
        config = replace(self.config, input_price=.001, output_price=100, max_cost=.4)
        agent = Agent(self.store, self.collector, config, 'scripted-key', model)
        result = agent.run('分析', 'simulation')
        self.assertTrue(result['ok'], result)
        self.assertIn(long_answer, result['answer'])
        self.assertTrue(result['citation_valid'])
        for body in model.bodies:
            self.assertFalse({'max_tokens', 'max_completion_tokens', 'max_output_tokens'} & body.keys())
        usage = self.store.usage()
        self.assertGreater(usage['reserved'], config.max_cost)
        self.assertGreater(usage['reported'], config.max_cost)
        self.assertGreaterEqual(usage['reserved'], usage['reported'])
        calls = len(model.bodies)
        following = agent.run('再分析', 'simulation')
        self.assertFalse(following['ok'])
        self.assertIn('费用预留', following['answer'])
        self.assertEqual(len(model.bodies), calls)

    def test_provider_truncation_is_still_disclosed_without_local_token_cap(self):
        seed_simulation(self.store)
        class LimitedProvider:
            def complete(self, config, key, body):
                results = [json.loads(m['content']) for m in body['messages'] if m['role'] == 'tool']
                if not results:
                    return response(calls=[call('protocol_stats', {})])
                result = response('模拟服务端截断 ' + results[-1]['evidence_id'])
                result['choices'][0]['finish_reason'] = 'length'
                return result
        result = Agent(self.store, self.collector, self.config, 'scripted-key', LimitedProvider()).run('分析', 'simulation')
        self.assertTrue(result['ok'])
        self.assertIn('本程序未设置输出 token 上限', result['answer'])

    def test_day_long_capture_paged_analysis_bounds_context_without_losing_data(self):
        sid = self.store.start_session('simulated-day-long-capture')
        start = 1700000000.0
        self.store.db.execute('UPDATE capture_sessions SET started=?, stopped=?, state=? WHERE id=?',
                              (start, start+86400, 'stopped', sid))
        self.store.add([self.row(session_id=sid, timestamp=start+i*720,
                                 sport=40000+i, dport=443) for i in range(120)])
        store = self.store

        class PagedModel:
            def __init__(self):
                self.bodies = []

            def complete(self, config, key, body):
                self.bodies.append(json.loads(json.dumps(body)))
                results = [json.loads(m['content']) for m in body['messages'] if m['role'] == 'tool']
                if not results:
                    return response(calls=[call('session_summary', {})])
                if len(results) <= 6:
                    return response(calls=[call('session_connection_history',
                        {'src': store.alias('192.0.2.1'), 'dst': store.alias('198.51.100.2'),
                         'protocol': 'TCP', 'page': len(results), 'page_size': 20}, 'page_'+str(len(results)))])
                return response('[模拟模型] 已按页查询；无法仅凭元数据判断恶意。' + results[-1]['evidence_id'])

        model = PagedModel()
        result = Agent(self.store, self.collector, self.config, 'scripted-key', model).run('分析全天采集', session_id=sid)
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['citation_valid'])
        self.assertIn('上下文范围', result['answer'])
        self.assertTrue(any('context_archived' in json.dumps(b) for b in model.bodies))
        for body in model.bodies:
            self.assertLessEqual(len(json.dumps(body, ensure_ascii=False).encode())+4096, CONTEXT_LIMIT_BYTES)
            calls = {c['id'] for m in body['messages'] for c in (m.get('tool_calls') or [])}
            self.assertTrue(all(m['tool_call_id'] in calls for m in body['messages'] if m['role'] == 'tool'))
        history = [e['result']['data'] for e in result['trace'] if e['name'] == 'session_connection_history']
        self.assertEqual(sum(len(d['connection_metrics']) for d in history), 120)
        summary = result['trace'][0]['result']['data']
        self.assertEqual(summary['duration_seconds'], 86400)
        self.assertEqual(summary['started'], start)
        self.assertEqual(summary['stopped'], start+86400)
        self.assertEqual(summary['last_observed'], start+119*720)
        self.assertEqual(self.store.session_summary(sid)['packets'], 120)

    def test_time_fields_and_default_model_page_are_explicit(self):
        from unittest.mock import patch
        from traffic_agent.ui import capture_times
        sid = self.store.start_session('simulated-interface')
        self.store.db.execute('UPDATE capture_sessions SET started=1000 WHERE id=?', (sid,))
        self.store.add([self.row(session_id=sid, timestamp=1010+i, sport=40000+i) for i in range(23)])
        with patch('traffic_agent.store.time.time', return_value=1600):
            summary = Toolset(self.store, self.collector, session_id=sid).call('session_summary', '{}')['data']
        self.assertEqual(summary['duration_seconds'], 600)
        self.assertEqual(summary['as_of'], 1600)
        self.assertIsNone(summary['stopped'])
        self.assertEqual(summary['first_observed'], 1010)
        self.assertEqual(capture_times(self.store._session(sid), now=1600)[1:], ('进行中', '00:10:00'))
        args = {'src': self.store.alias('192.0.2.1'), 'dst': self.store.alias('198.51.100.2'), 'protocol': 'TCP'}
        tool = Toolset(self.store, self.collector, session_id=sid)
        pages = [tool.call('session_connection_history', json.dumps({**args, 'page': p}))['data'] for p in (1, 2, 3)]
        self.assertEqual([len(d['connection_metrics']) for d in pages], [10, 10, 3])
        self.assertTrue(all(d['page_size'] == 10 and d['connection_metrics_pages'] == 3 for d in pages))
        self.store.db.execute('UPDATE capture_sessions SET stopped=4630, state=? WHERE id=?', ('stopped', sid))
        self.assertEqual(capture_times(self.store._session(sid))[2], '01:00:30')

    def test_overview_compaction_keeps_evidence_locally(self):
        result = {'ok': True, 'data': {'anomaly_assessment': {'candidate_pairs_total': 1,
            'candidate_pairs_first_20': [{'src': 'host_a', 'dst': 'host_b', 'anomaly_score': 70,
                'signals': [{'code': 'PORT_SWEEP'}], 'evidence': [{'feature': 'ports', 'value': 20}],
                'score_components': [{'contribution': 70}]}]}}}
        view = model_tool_view(result, 'session_summary')
        self.assertEqual(view['data']['anomaly_assessment']['candidate_pairs_first_20'][0]['triggered_rules'], ['PORT_SWEEP'])
        self.assertIn('evidence', result['data']['anomaly_assessment']['candidate_pairs_first_20'][0])
        self.assertEqual(model_tool_view(result, 'query_anomaly_evidence'), result)

    def test_monitor_evaluates_behavior_at_most_once_per_minute(self):
        from unittest.mock import patch
        sid = self.store.start_session('synthetic-monitor-fixture')
        self.store.add([self.row(session_id=sid)])
        class Capture:
            def status(self):
                return {'running': True, 'accepted_packets': 1, 'session_id': sid}
        class FakeAgent:
            lock = threading.Lock()
            cancel = threading.Event()
            config = Config(monitor_seconds=3600)
        monitor = Monitor(self.store, Capture(), FakeAgent(), lambda event: None)
        try:
            monitor.enabled = True
            monitor.last_attempt = 100
            with patch.object(self.store, 'session_anomaly_assessment', wraps=self.store.session_anomaly_assessment) as assess:
                for stamp in (120, 125, 140, 179):
                    self.assertIsNone(monitor.tick(stamp))
                self.assertEqual(assess.call_count, 1)
                self.assertIsNone(monitor.tick(181))
                self.assertEqual(assess.call_count, 2)
        finally:
            monitor.close()

    def test_scored_short_connection_burst_requires_agent_history(self):
        sid = self.store.start_session('synthetic-test-interface')
        stamp = time.time()
        rows = []
        for i in range(20):
            rows.extend([self.row(session_id=sid, timestamp=stamp+i, sport=47000+i,
                                  dport=443, bytes=100, client_is_a=1,
                                  handshake_status='CONFIRMED', connection_state='HANDSHAKE_CONFIRMED'),
                         self.row(session_id=sid, timestamp=stamp+i+.3, sport=47000+i,
                                  dport=443, bytes=70, fin=1, client_is_a=1,
                                  handshake_status='CONFIRMED', connection_state='CLOSED')])
        self.store.add(rows)
        self.store.end_session(sid)
        summary = self.store.session_summary(sid)
        self.assertFalse(summary['candidate_pairs_first_20'], '旧SYN/RST规则不应触发此样本')
        self.assertEqual(summary['anomaly_assessment']['candidate_pairs_total'], 1)
        self.assertIn('SHORT_CONNECTION_BURST', [signal['code'] for signal in
            summary['anomaly_assessment']['candidate_pairs_first_20'][0]['signals']])

        class Model:
            def complete(self, config, key, body):
                results = [json.loads(m['content']) for m in body['messages'] if m['role'] == 'tool']
                if not results:
                    return response(calls=[call('session_summary', {})])
                if len(results) == 1 and '候选异常连接对' in body['messages'][-1]['content']:
                    pair = results[0]['data']['anomaly_assessment']['candidate_pairs_first_20'][0]
                    return response(calls=[call('session_connection_history',
                        {'src': pair['src'], 'dst': pair['dst'], 'protocol': 'TCP'}, 'history')])
                return response('需要核实是否为正常轮询。证据 ' + results[-1]['evidence_id'])

        result = Agent(self.store, self.collector, self.config, 'scripted-key', Model()).run(
            '分析本次采集', session_id=sid)
        self.assertTrue(result['ok'], result)
        self.assertEqual([item['name'] for item in result['trace']],
                         ['session_summary', 'session_connection_history'])
        self.assertTrue(result['citation_valid'])

    def test_session_candidate_requires_history_and_flags_unread_pages(self):
        sid = self.store.start_session('test-interface')
        start = time.time()-3600
        self.store.add([self.row(session_id=sid, timestamp=start+i*60, dport=1000+i, syn=1)
                        for i in range(60)])
        class PrematureModel:
            def complete(self, config, key, body):
                results = [json.loads(m['content']) for m in body['messages'] if m['role'] == 'tool']
                if not results:
                    return response(calls=[call('session_summary', {})])
                if len(results) == 1 and '候选异常连接对' in body['messages'][-1]['content']:
                    pair = results[0]['data']['candidate_pairs_first_20'][0]
                    return response(calls=[call('session_connection_history',
                        {'src':pair['src'], 'dst':pair['dst'], 'protocol':'TCP'}, 'history')])
                evidence = results[-1]['evidence_id']
                return response('需要继续核实。证据 ' + evidence)
        result = Agent(self.store, self.collector, self.config, 'scripted-key', PrematureModel()).run(
            '分析本次采集', session_id=sid)
        self.assertTrue(result['ok'], result)
        self.assertEqual([r['name'] for r in result['trace']], ['session_summary', 'session_connection_history'])
        self.assertIn('未查询页', result['answer'])
        self.assertTrue(result['citation_valid'])

    def test_session_agent_follows_full_session_then_connection_history(self):
        sid = self.store.start_session('test-interface')
        self.store.add([self.row(session_id=sid, syn=1), self.row(session_id=sid,
                             src='198.51.100.2', dst='192.0.2.1', sport=443, dport=12345, bytes=75)])
        self.store.end_session(sid)
        class SessionModel:
            def __init__(self):
                self.bodies = []
            def complete(self, config, key, body):
                self.bodies.append(body)
                results = [json.loads(m['content']) for m in body['messages'] if m['role'] == 'tool']
                if not results:
                    return response(calls=[call('session_summary', {})])
                if len(results) == 1:
                    flow = results[0]['data']['top_flows_first_20'][0]
                    return response(calls=[call('session_connection_history',
                        {k: flow[k] for k in ('src', 'dst', 'sport', 'dport', 'protocol')}, 'history')])
                return response('本次会话双向连接需要核实；证据 ' + results[-1]['evidence_id'])
        model = SessionModel()
        result = Agent(self.store, self.collector, self.config, 'scripted-key', model).run(
            '分析本次采集', session_id=sid)
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['citation_valid'])
        self.assertEqual([x['name'] for x in result['trace']], ['session_summary', 'session_connection_history'])
        self.assertEqual(result['trace'][-1]['result']['data']['bytes'], 175)
        self.assertEqual({t['function']['name'] for t in model.bodies[0]['tools']},
                         {'session_summary', 'session_connection_history', 'query_connection', 'query_connection_baseline',
                          'query_anomaly_evidence', 'query_similar_sessions', 'query_application_identity',
                          'list_incidents', 'get_incident', 'query_incident_members', 'query_incident_timeline',
                          'query_incident_evidence', 'query_unassociated_findings'})
        self.assertIn('采集会话', model.bodies[0]['messages'][0]['content'])
        self.assertNotIn('192.0.2.1', json.dumps(model.bodies))

    def test_multiple_dependent_tools_and_evidence(self):
        seed_simulation(self.store)
        model = ModelFixture()
        agent = Agent(self.store, self.collector, self.config, "test-key-12345", model)
        result = agent.run("分析当前流量", "simulation")
        self.assertTrue(result["ok"], result)
        self.assertEqual([x["name"] for x in result["trace"]], ["protocol_stats", "analyze_ip", "query_history"])
        self.assertEqual(len(model.bodies), 4)
        self.assertEqual(self.store.usage()["calls"], 4)
        self.assertNotIn("192.0.2.", json.dumps(model.bodies))
        self.assertIn(result["evidence"][1], result["answer"])

    def test_high_lifetime_call_count_does_not_block_analysis(self):
        seed_simulation(self.store)
        self.store.db.execute('UPDATE budget SET calls=10000 WHERE id=1')
        self.store.db.commit()
        model = ModelFixture()
        agent = Agent(self.store, self.collector, self.config, "test-key", model)
        result = agent.run("分析", "simulation")
        self.assertTrue(result["ok"], result)
        self.assertEqual(len(model.bodies), 4)
        self.assertEqual(self.store.usage()['calls'], 10004)

    def test_cost_limit_prevents_request(self):
        model = ModelFixture()
        agent = Agent(self.store, self.collector, replace(self.config, max_cost=.000001), "test-key", model)
        self.assertFalse(agent.run("分析")["ok"])
        self.assertEqual(len(model.bodies), 0)

    def test_failure_does_not_stop_writer_or_refund(self):
        class Failure:
            def complete(self, *args):
                raise OSError("test-key-should-never-leak")
        agent = Agent(self.store, self.collector, self.config, "test-key", Failure())
        result = agent.run("分析")
        self.assertFalse(result["ok"])
        self.assertNotIn("should-never-leak", result["answer"])
        self.collector.queue.put(self.row())
        self.collector.queue.join()
        self.assertEqual(self.store.summary()["packets"], 1)
        self.assertEqual(self.store.usage()["calls"], 1)
        self.assertGreater(self.store.usage()["reserved"], 0)

    def test_no_evidence_means_no_successful_verdict(self):
        class ChatOnly:
            def complete(self, *args):
                return response("你的网络非常安全")
        agent = Agent(self.store, self.collector, replace(self.config, max_steps=2), "test-key", ChatOnly())
        self.assertFalse(agent.run("分析")["ok"])
        self.assertEqual(self.store.usage()["calls"], 2)

    def test_infinite_tool_loop_stops(self):
        class Loop:
            def complete(self, *args):
                return response(calls=[call("capture_status", {})])
        agent = Agent(self.store, self.collector, replace(self.config, max_tools=2), "test-key", Loop())
        self.assertFalse(agent.run("分析")["ok"])
        self.assertEqual(self.store.usage()["calls"], 3)

    def test_user_ip_redaction(self):
        text = redact_text("分析 192.0.2.1 和 2001:db8::1，https://private.test/x?a=secret，sk-secret123", self.store)
        self.assertNotIn("192.0.2.1", text)
        self.assertNotIn("2001:db8::1", text)
        self.assertNotIn("private.test", text)
        self.assertNotIn("sk-secret", text)

    def test_budget_parallel_reservations_are_atomic(self):
        outcomes = []
        def reserve():
            try:
                self.store.reserve(.6, self.config)
                outcomes.append(True)
            except ValueError:
                outcomes.append(False)
        threads = [threading.Thread(target=reserve) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sum(outcomes), 1)

    def test_monitor_cooldown_and_unchanged_no_repeat(self):
        self.store.add([self.row()])
        class Capture:
            def status(self):
                return {"running": True, "accepted_packets": 1}
        class FakeAgent:
            lock = threading.Lock()
            cancel = threading.Event()
            config = Config(monitor_seconds=60)
            def run(self, *args, **kwargs):
                return {"ok": True}
        monitor = Monitor(self.store, Capture(), FakeAgent(), lambda e: None)
        try:
            monitor.enabled = True
            monitor.last_attempt = 100
            self.assertIsNone(monitor.tick(120))
            self.assertTrue(monitor.tick(161)["ok"])
            self.assertIsNone(monitor.tick(400))
        finally:
            monitor.close()

    def test_config_rejects_bad_prices_and_remote_http(self):
        for cfg in [replace(self.config, input_price=0), replace(self.config, max_cost=float("nan")),
                    replace(self.config, base_url="http://example.com/v1"), replace(self.config, base_url="https://user:pass@example.com")]:
            with self.assertRaises(ValueError):
                cfg.validate()


if __name__ == "__main__":
    unittest.main()
