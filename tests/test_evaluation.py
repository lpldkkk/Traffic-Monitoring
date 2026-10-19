"""Arithmetic, import integrity and real saved loopback corpus evaluation."""
import copy
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / '.runtime'))
from traffic_agent.evaluation import evaluate, load_dataset, metrics, validate_record
from traffic_agent.replay import Replay, replay_to_directory
from scapy.all import IP, TCP, Raw, wrpcap
from sample_data import port_scan_pcap


def small_pcap(path):
    """Synthetic decoder fixture; not part of the real detection benchmark."""
    payload = b'payload-must-stay-local'
    packets = [IP(src='192.0.2.1', dst='198.51.100.2') / TCP(sport=40000, dport=443, flags='S', seq=100),
               IP(src='198.51.100.2', dst='192.0.2.1') / TCP(sport=443, dport=40000, flags='SA', seq=500, ack=101),
               IP(src='192.0.2.1', dst='198.51.100.2') / TCP(sport=40000, dport=443, flags='A', seq=101, ack=501) / Raw(payload),
               IP(src='192.0.2.1', dst='198.51.100.2') / TCP(sport=40000, dport=443, flags='FA', seq=101+len(payload), ack=501),
               IP(src='198.51.100.2', dst='192.0.2.1') / TCP(sport=443, dport=40000, flags='FA', seq=501, ack=102+len(payload))]
    for i, packet in enumerate(packets):
        packet.time = 1000 + i * .5
    wrpcap(str(path), packets)


class EvaluationTests(unittest.TestCase):
    def test_fresh_cli_process_loads_npcap_loopback_link_layer(self):
        with tempfile.TemporaryDirectory() as folder:
            result = subprocess.run([sys.executable, str(ROOT / 'app.py'), '--replay',
                str(port_scan_pcap(self)), '--output', folder],
                cwd=ROOT, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            detection = json.loads((Path(folder) / 'detection.json').read_text(encoding='utf-8'))
            self.assertEqual(detection['prediction'], 1)
            self.assertEqual(detection['anomaly_score'], 90)

    def test_confusion_matrix_and_all_five_rates(self):
        report = metrics([1, 1, 1, 0, 0, 0], [1, 1, 0, 1, 0, 0])
        self.assertEqual((report['true_positive'], report['false_positive'], report['false_negative'], report['true_negative']), (2, 1, 1, 2))
        for name in ('precision', 'recall', 'f1'):
            self.assertAlmostEqual(report[name], 2/3)
        for name in ('false_positive_rate', 'false_negative_rate'):
            self.assertAlmostEqual(report[name], 1/3)

    def test_zero_denominators_not_invented_perfect_scores(self):
        report = metrics([0, 0], [0, 0])
        self.assertIsNone(report['precision'])
        self.assertIsNone(report['recall'])
        self.assertIsNone(report['f1'])
        self.assertEqual(report['false_positive_rate'], 0)
        with self.assertRaises(ValueError):
            evaluate([])

    def test_replay_is_deterministic_and_uses_real_handshake_state(self):
        with tempfile.TemporaryDirectory() as folder:
            pcap = Path(folder) / 'fixture.pcap'
            small_pcap(pcap)
            with Replay(pcap) as first, Replay(pcap) as second:
                self.assertEqual(first.record, second.record)
                self.assertEqual(first.detection, second.detection)
                self.assertEqual(first.local_report(), second.local_report())
                c = first.record['features']['connections'][0]
                self.assertEqual(c['handshake_status'], 'CONFIRMED')
                self.assertEqual(c['connection_state'], 'CLOSED')
                self.assertEqual(c['a_to_b_packets'] + c['b_to_a_packets'], 5)
                self.assertEqual(c['last_seen'] - c['first_seen'], 2)
                self.assertNotIn('payload-must-stay-local', json.dumps(first.record))
                self.assertEqual(first.store._session(first.session_id)['source_kind'], 'replay')

    def test_label_does_not_change_prediction_and_duplicates_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            pcap = Path(folder) / 'fixture.pcap'
            small_pcap(pcap)
            with Replay(pcap) as replay:
                normal = {**replay.record, 'label': 0}
                attack = {**replay.record, 'label': 1}
                a, b = evaluate([normal]), evaluate([attack])
                self.assertEqual(a['sessions'][0]['prediction'], b['sessions'][0]['prediction'])
                self.assertEqual(b['false_negative'], 1)
                with self.assertRaises(ValueError):
                    evaluate([normal, attack])

    def test_import_validation_and_unsupported_protocols_stay_in_denominator(self):
        row = {'session_id': 'empty-unknown', 'timestamp': 0,
               'features': {'schema_version': 1, 'connections': []}, 'label': 1}
        report = evaluate([row])
        self.assertEqual(report['false_negative'], 1)
        self.assertEqual(report['unassessed_sessions'], 1)
        self.assertEqual(report['recall'], 0)
        for changed in ({'label': True}, {'timestamp': float('nan')}, {'features': {'prediction': 1}}):
            with self.assertRaises(ValueError):
                validate_record({**row, **changed})
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'dataset.jsonl'
            path.write_text(json.dumps(row) + '\n', encoding='utf-8')
            self.assertEqual(load_dataset(path), [row])

    def test_saved_metadata_cannot_disagree_with_pcap(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            small_pcap(path / 'traffic.pcap')
            with Replay(path / 'traffic.pcap') as replay:
                record = copy.deepcopy(replay.record)
                record['features']['connections'][0]['a_to_b_packets'] += 100
                (path / 'session.json').write_text(json.dumps(record), encoding='utf-8')
                (path / 'label.json').write_text(json.dumps({'session_id': replay.session_id,
                    'pcap_sha256': replay.record['pcap_sha256'], 'label': 0}), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, '不一致'):
                load_dataset(path)

    def test_replay_exports_stable_artifacts_and_preserves_existing_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            pcap = Path(folder) / 'fixture.pcap'
            output = Path(folder) / 'output'
            small_pcap(pcap)
            replay_to_directory(pcap, output)
            before = {p.name: p.read_bytes() for p in output.iterdir()}
            replay_to_directory(pcap, output)
            self.assertEqual(before, {p.name: p.read_bytes() for p in output.iterdir()})
            self.assertFalse(json.loads((output / 'local_report.json').read_text(encoding='utf-8'))['investigation_complete'])
            with self.assertRaises(ValueError):
                replay_to_directory(pcap, Path(folder))

    @unittest.skipUnless((ROOT / 'datasets/dataset.jsonl').is_file(),
                         '可选私有回环实验数据未提供；合成夹具不替代真实检测效果评估')
    def test_real_saved_corpus_rates_and_provenance(self):
        # Private real PCAPs are never committed; offline replay sends no traffic.
        records = load_dataset(ROOT / 'datasets')
        self.assertGreaterEqual(len(records), 24)
        scenarios = {r['scenario'] for r in records}
        self.assertTrue({'web', 'dns', 'ssh', 'file_transfer', 'syn_flood', 'port_scan',
                         'frequent_connections', 'abnormal_outbound'} <= scenarios)
        report = evaluate(records)
        self.assertEqual(report['total_sessions'], len(records))
        self.assertTrue(all(r['provenance']['traffic_source'] == 'real_loopback_capture' for r in records))
        self.assertGreater(report['true_positive'], 0)
        self.assertGreater(report['false_negative'], 0, '外联语义代理样本应暴露当前检测盲区')
        self.assertGreater(report['false_positive'], 0, '合法高频轮询应暴露短连接规则误报')
        self.assertGreater(report['unassessed_sessions'], 0, 'DNS不适用TCP规则，必须披露')
        self.assertEqual(report['human_reviewed_sessions'], 0)
        print('\n真实本机实验指标：' + json.dumps({k: report[k] for k in ('total_sessions', 'precision', 'recall', 'f1', 'false_positive_rate', 'false_negative_rate')}, ensure_ascii=False))


if __name__ == '__main__':
    unittest.main()
