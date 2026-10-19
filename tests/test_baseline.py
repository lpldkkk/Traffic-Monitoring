"""Labeled synthetic metadata only: no attack traffic or real LLM calls."""
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / '.runtime'))

from traffic_agent.agent import Agent
from traffic_agent.capture import Collector
from traffic_agent.config import Config
from traffic_agent.store import Store
from traffic_agent.tools import Toolset


class CredibilityTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')

    def tearDown(self):
        self.store.close()

    def capture(self, kind='web', count=3, interface='synthetic-interface', normal=False):
        sid = self.store.start_session(interface)
        start = self.store._session(sid)['number'] * 1000.0
        for i in range(count):
            protocol = 'UDP' if kind == 'dns' else 'TCP'
            port = 53 if kind == 'dns' else 22 if kind == 'ssh' else 100+i if kind == 'scan' else 443
            duration = 120 if kind == 'ssh' else 1 if kind in ('short', 'dns') else 10
            syn_only = kind in ('syn', 'scan')
            row = dict(source='live', session_id=sid, timestamp=start+i, src='192.0.2.1', dst='198.51.100.2',
                       protocol=protocol, sport=40000+i, dport=port, bytes=600, packets=5,
                       syn=int(protocol == 'TCP'), client_is_a=1 if protocol == 'TCP' and kind != 'midstream' else None,
                       handshake_status='SYN_ONLY' if syn_only else 'NOT_OBSERVED' if kind in ('midstream', 'dns') else 'CONFIRMED',
                       connection_state='UNKNOWN' if syn_only or kind in ('midstream', 'dns') else 'CLOSED',
                       fin=int(not syn_only and protocol == 'TCP' and kind != 'midstream'))
            self.store.add([row])
            if not syn_only:
                self.store.add([{**row, 'timestamp': start+i+duration, 'src': row['dst'], 'dst': row['src'],
                                 'sport': port, 'dport': row['sport'], 'syn': 0, 'syn_ack': int(protocol == 'TCP')}])
        self.store.end_session(sid)
        with self.store.lock, self.store.db:
            self.store.db.execute('UPDATE capture_sessions SET started=?,stopped=? WHERE id=?', (start, start+300, sid))
        if normal:
            self.store.set_session_normal(sid)
        return sid

    def args(self, sid):
        c = self.store.session_connections(sid)['connections'][0]['metrics']
        return dict(src=c['source_ip'], dst=c['destination_ip'], protocol=c['protocol'],
                    sport=c['source_port'], dport=c['destination_port'])

    def seed_baseline(self):
        return [self.capture(normal=True) for _ in range(3)]

    def test_labeled_scenarios_and_explanations(self):
        expectations = [('web', 3, None, 'none'), ('dns', 3, None, 'none'), ('ssh', 3, None, 'none'),
                        ('syn', 30, 'SYN_ONLY_BURST', 'medium'), ('scan', 30, 'PORT_SWEEP', 'high'),
                        ('short', 25, 'SHORT_CONNECTION_BURST', 'medium')]
        report = []
        for kind, count, rule, risk in expectations:
            with self.subTest(scenario=kind):
                sid = self.capture(kind, count)
                result = self.store.session_anomaly_assessment(sid)
                candidates = result['candidate_pairs_first_20']
                self.assertEqual(bool(candidates), rule is not None)
                if rule:
                    result = candidates[0]
                    self.assertEqual(result['risk_level'], risk)
                    self.assertIn(rule, [s['code'] for s in result['signals']])
                    self.assertEqual(result['anomaly_score'], sum(c['contribution'] for c in result['score_components']))
                    self.assertTrue(all(set(('feature', 'value', 'baseline', 'reason')) <= e.keys() for e in result['evidence']))
                    for e in result['evidence']:
                        self.assertEqual(e['baseline_kind'], 'rule_threshold')
                        self.assertTrue(e['reason'])
                        self.assertTrue(e['value'] >= e['baseline'] if e['operator'] == '>=' else e['value'] <= e['baseline'])
                    if kind == 'scan':
                        self.assertEqual(next(e['value'] for e in result['evidence'] if e['feature'] == 'distinct_server_ports'), 30)
                        self.assertEqual(result['anomaly_score'], 80)
                    if kind == 'short':
                        self.assertIn('正常轮询', result['signals'][0]['reason'])
                else:
                    metric = self.store.session_connections(sid)['connections'][0]['metrics']
                    self.assertEqual(metric['assessment']['anomaly_score'], 0)
                    self.assertEqual(metric['assessment']['status'], 'not_applicable' if kind == 'dns' else 'no_signal')
                report.append({'synthetic_scenario': kind, 'detected': bool(candidates), 'risk': risk,
                               'explanation_checked': True, 'assessment_status': 'not_applicable' if kind == 'dns' else 'metadata_only'})
        print('\n合成场景评估（不是实网准确率）：' + json.dumps(report, ensure_ascii=False))

    def test_no_implicit_normal_label_or_self_reference(self):
        self.capture()
        sid = self.capture(normal=True)
        result = self.store.query_connection_baseline(sid, **self.args(sid))
        self.assertEqual(result['baseline']['capture_count'], 0)
        self.assertEqual(result['connection_comparison']['status'], 'insufficient_evidence')
        self.assertIsNone(result['connection_comparison']['comparisons'][0]['deviation'])

    def test_numeric_baseline_and_capture_rate_are_reproducible(self):
        self.seed_baseline()
        sid = self.capture()
        result = self.store.query_connection_baseline(sid, **self.args(sid))
        self.assertEqual(result['baseline']['average_connection_count']['mean'], 3)
        self.assertEqual(result['baseline']['packets_per_connection']['mean'], 10)
        self.assertEqual(result['baseline']['observed_duration']['mean'], 10)
        self.assertEqual(result['connection_comparison']['status'], 'available')
        self.assertEqual(result['connection_comparison']['comparisons'][0]['deviation'], 0)
        self.assertEqual(result['capture_comparison']['current_value'], 3)
        self.assertEqual(result['baseline']['common_ports'], [{'port': 443, 'connections': 9}])
        self.assertNotIn('192.0.2.1', json.dumps(result))

    def test_deviation_and_unseen_port_do_not_fabricate_anomaly_score(self):
        self.seed_baseline()
        sid = self.capture('short', 25)
        result = self.store.query_connection_baseline(sid, **self.args(sid))
        duration = next(c for c in result['connection_comparison']['comparisons'] if c['feature'] == 'duration')
        self.assertEqual(duration['deviation'], -9)
        self.assertEqual(result['capture_comparison']['deviation'], 22)
        self.assertNotIn('anomaly_score', result)
        ssh = self.capture('ssh')
        comparison = self.store.query_connection_baseline(ssh, **self.args(ssh))['connection_comparison']
        self.assertEqual(comparison['status'], 'insufficient_evidence')
        self.assertEqual(next(c for c in comparison['comparisons'] if c['feature'] == 'service_port')['status'], 'unseen_in_history')

    def test_filter_interface_chronology_and_label_revocation(self):
        history = self.seed_baseline()
        self.capture(interface='other-interface', normal=True)
        sid = self.capture()
        self.capture(normal=True)  # Later capture must not leak into earlier analysis.
        self.assertEqual(self.store.query_connection_baseline(sid, **self.args(sid))['baseline']['capture_count'], 3)
        self.store.set_session_normal(history[0], False)
        key = self.store.session_connections(history[1])['connections'][0]['key']
        self.store.retain_session_connections(history[1], [key])
        self.assertEqual(self.store._session(history[1])['normal_label'], 'unreviewed')
        result = self.store.query_connection_baseline(sid, **self.args(sid))
        self.assertEqual(result['baseline']['capture_count'], 1)
        self.store.delete_session(history[2])
        self.assertEqual(self.store.query_connection_baseline(sid, **self.args(sid))['baseline']['capture_count'], 0)

    def test_modified_metadata_invalidates_normal_label(self):
        sid = self.capture(normal=True)
        self.store.add([dict(source='live', session_id=sid, src='192.0.2.1', dst='198.51.100.2',
                             protocol='TCP', sport=40000, dport=443, bytes=10, timestamp=1010)])
        self.assertEqual(self.store._session(sid)['normal_label'], 'unreviewed')

    def test_small_cohort_not_usable_even_with_three_capture_labels(self):
        for _ in range(3):
            self.capture(count=1, normal=True)
        sid = self.capture()
        result = self.store.query_connection_baseline(sid, **self.args(sid))['connection_comparison']
        self.assertEqual(result['matched_capture_count'], 3)
        self.assertEqual(result['matched_connection_count'], 3)
        self.assertEqual(result['status'], 'insufficient_evidence')
        self.assertIsNone(result['comparisons'][0]['deviation'])

    def test_connection_count_comparison_normalizes_capture_exposure(self):
        self.seed_baseline()
        sid = self.capture(count=6)
        with self.store.db:
            self.store.db.execute('UPDATE capture_sessions SET stopped=started+600 WHERE id=?', (sid,))
        result = self.store.query_connection_baseline(sid, **self.args(sid))['capture_comparison']
        self.assertEqual(result['current_value'], 3)
        self.assertEqual(result['deviation'], 0)

    def test_overlap_and_partial_target_are_explicitly_incomparable(self):
        history = self.seed_baseline()
        sid = self.capture()
        with self.store.db:
            self.store.db.execute('UPDATE capture_sessions SET stopped=5000 WHERE id=?', (history[0],))
        self.assertEqual(self.store.query_connection_baseline(sid, **self.args(sid))['baseline']['capture_count'], 2)
        key = self.store.session_connections(sid)['connections'][0]['key']
        self.store.retain_session_connections(sid, [key])
        self.assertEqual(self.store.query_connection_baseline(sid, **self.args(sid))['capture_comparison']['status'], 'insufficient_evidence')

    def test_invalid_normal_samples_rejected(self):
        running = self.store.start_session('test')
        with self.assertRaises(ValueError):
            self.store.set_session_normal(running)
        self.store.end_session(running)
        with self.assertRaises(ValueError):
            self.store.set_session_normal(running)
        sid = self.capture()
        with self.store.db:
            self.store.db.execute('UPDATE capture_sessions SET legacy_incomplete=1 WHERE id=?', (sid,))
        with self.assertRaises(ValueError):
            self.store.set_session_normal(sid)

    def test_similarity_includes_unreviewed_and_never_future_or_current(self):
        first = self.capture()
        self.capture('ssh', normal=True)
        sid = self.capture()
        self.capture(normal=True)
        result = self.store.query_similar_sessions(sid, **self.args(sid), limit=2)
        self.assertEqual(result['matches'][0]['capture_number'], self.store._session(first)['number'])
        self.assertEqual(result['matches'][0]['similarity'], 1)
        self.assertEqual(result['matches'][0]['normal_label'], 'unreviewed')
        self.assertEqual(result['matching_connections'], 6)
        self.assertTrue(result['truncated'])
        self.assertNotIn('198.51.100.2', json.dumps(result))

    def test_unknown_handshake_stays_uncertain_with_matching_history(self):
        self.seed_baseline()
        sid = self.capture('midstream')
        result = self.store.query_anomaly_evidence(sid, **self.args(sid))
        assessment = result['connection_assessments'][0]['assessment']
        self.assertEqual(assessment['status'], 'insufficient_evidence')
        self.assertEqual(assessment['anomaly_score'], 0)
        self.assertEqual(assessment['evidence'], [])
        self.assertEqual(self.store.query_similar_sessions(sid, **self.args(sid))['status'], 'available')

    def test_new_tools_validate_and_hide_raw_endpoints(self):
        self.seed_baseline()
        sid = self.capture('scan', 30)
        tools = Toolset(self.store, None, 'live', sid)
        args = self.args(sid)
        for name in ('query_connection_baseline', 'query_anomaly_evidence', 'query_similar_sessions'):
            result = tools.call(name, json.dumps(args))
            self.assertTrue(result['ok'], result)
            self.assertNotIn('192.0.2.1', json.dumps(result))
            self.assertFalse(tools.call(name, json.dumps({**args, 'session_id': 'foreign'}))['ok'])
            self.assertFalse(tools.call(name, json.dumps({**args, 'src': '192.0.2.1'}))['ok'])
            self.assertFalse(tools.call(name, json.dumps({**args, 'sport': 1}))['ok'])
        self.assertFalse(tools.call('query_similar_sessions', json.dumps({**args, 'limit': 100}))['ok'])
        self.assertFalse(tools.call('set_session_normal', '{}')['ok'])

    def test_legacy_database_migration_and_label_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'legacy.db'
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE capture_sessions(id TEXT PRIMARY KEY,interface TEXT,started REAL,stopped REAL,state TEXT)')
                db.execute("INSERT INTO capture_sessions VALUES('old','test',100,400,'stopped')")
            db.close()
            store = Store(path)
            self.assertEqual(store._session('old')['normal_label'], 'unreviewed')
            self.assertIsNone(store._session('old')['normal_label_at'])
            store.close()
            store = Store(path)
            self.assertEqual(store._session('old')['normal_label'], 'unreviewed')
            store.close()

    def test_agent_executes_dependent_evidence_baseline_similarity_workflow(self):
        self.seed_baseline()
        sid = self.capture('short', 25)
        class ScriptedModel:
            def complete(self, config, key, body):
                results = [json.loads(m['content']) for m in body['messages'] if m['role'] == 'tool']
                sequence = ['session_summary', 'session_connection_history', 'query_anomaly_evidence',
                            'query_connection_baseline', 'query_similar_sessions']
                if len(results) < len(sequence):
                    args = {} if not results else {k: results[0]['data']['top_flows_first_20'][0][k]
                                                  for k in ('src', 'dst', 'protocol', 'sport', 'dport')}
                    message = {'role': 'assistant', 'content': None, 'tool_calls': [
                        {'id': 'call_' + str(len(results)), 'type': 'function', 'function':
                         {'name': sequence[len(results)], 'arguments': json.dumps(args)}}]}
                else:
                    message = {'role': 'assistant', 'content': '[模拟模型] 高频短连接需核实轮询，历史有3次人工正常参考；非攻击定论。' + ' '.join(r['evidence_id'] for r in results)}
                return {'choices': [{'message': message, 'finish_reason': 'stop'}], 'usage': {}}
        collector = Collector(self.store)
        try:
            result = Agent(self.store, collector, Config(), 'scripted-only', ScriptedModel()).run('分析', session_id=sid)
            self.assertTrue(result['ok'], result)
            self.assertTrue(result['citation_valid'])
            self.assertEqual(len(result['trace']), 5)
            self.assertEqual(result['trace'][3]['result']['data']['baseline']['capture_count'], 3)
            self.assertNotIn('198.51.100.2', json.dumps(result))
        finally:
            collector.close()


if __name__ == '__main__':
    unittest.main()
