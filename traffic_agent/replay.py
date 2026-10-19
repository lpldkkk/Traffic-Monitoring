"""Offline PCAP -> the same metadata/state/store pipeline. Never sends packets."""
import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from .capture import packet_metadata, TCPStateTracker
from .evaluation import FEATURE_VERSION, detect, detector_fingerprint
from .evaluation import fingerprint
from .store import Store
from .connection_instances import TRACKING_VERSION, IDLE_SECONDS


class Replay:
    def __init__(self, path):
        path = Path(path)
        if path.stat().st_size > 128 * 1024 * 1024:
            raise ValueError('PCAP超过128MiB回放上限')
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        self.store = Store(':memory:')
        self.session_id = 'pcap_' + digest
        try:
            sid = self.store.start_session('offline-pcap')
            with self.store.db:
                self.store.db.execute("UPDATE capture_sessions SET id=?,source_kind='replay' WHERE id=?", (self.session_id, sid))
            tracker = TCPStateTracker()
            count = ignored = backwards = 0
            first = last = previous = None
            batch = []
            # Register link-layer decoders in a fresh CLI process too (Npcap DLT_NULL).
            from scapy.all import PcapReader
            # Own the handle even if Scapy rejects the header during construction.
            with path.open('rb') as stream, PcapReader(stream) as reader:
                for packet in reader:
                    count += 1
                    if count > 1000000:
                        raise ValueError('PCAP超过100万包上限')
                    row = packet_metadata(packet, self.session_id)
                    if row is None:
                        ignored += 1
                        continue
                    stamp = row['timestamp']
                    first = stamp if first is None else min(first, stamp)
                    last = stamp if last is None else max(last, stamp)
                    backwards += int(previous is not None and stamp < previous)
                    previous = stamp
                    tracker._annotate_tcp(row)
                    batch.append(row)
                    if len(batch) == 256:
                        self.store.add(batch)
                        batch.clear()
                self.store.add(batch)
            if first is None:
                raise ValueError('PCAP没有可解析IP流量')
            with self.store.db:
                self.store.db.execute("UPDATE capture_sessions SET started=?,stopped=?,state='stopped' WHERE id=?",
                                      (first, last, self.session_id))
            connections = []
            for row in self.store.db.execute('SELECT * FROM session_connection_metrics WHERE session_id=? ORDER BY a,ap,b,bp,protocol,first_seen,connection_id', (self.session_id,)):
                connection = dict(row)
                connection.pop('session_id')
                connections.append(connection)
            self.record = {'session_id': self.session_id, 'timestamp': first, 'pcap_sha256': digest,
                'features': {'schema_version': FEATURE_VERSION, 'connections': connections,
                             'tracking': {'version': TRACKING_VERSION, 'idle_seconds': IDLE_SECONDS},
                             'capture': {'first_seen': first, 'last_seen': last, 'pcap_packets': count,
                                         'ignored_non_ip_packets': ignored, 'out_of_order_timestamps': backwards}},
                'source': 'pcap_replay', 'detector_sha256': detector_fingerprint()}
            self.detection = detect(self.record['features'])
            self.incident_result = self.store.process_incidents(self.session_id)
        except BaseException:
            self.store.close()
            raise

    def local_report(self):
        result = self.detection
        assessment = result['assessment']
        candidates = assessment['candidate_pairs_all'] + assessment['watch_connections_first_20']
        return {'事件': '离线PCAP规则检测', '时间': self.record['features']['capture'],
                '涉及IP': sorted({c[k] for c in candidates for k in ('src', 'dst')}),
                '风险': {'level': result['risk_level'], 'score': result['anomaly_score']},
                '触发规则': sorted({s['code'] for c in candidates for s in c['signals']}),
                '异常证据': [e for c in candidates for e in c['evidence']],
                '历史比较': {'status': 'not_queried', 'reason': '独立回放数据库；未导入历史正常采集'},
                '建议行动': ['按触发规则核实业务、采集完整性及目标授权；未命中不代表安全'],
                'report_kind': 'deterministic_local_detection', 'investigation_complete': False,
                'notice': '本报告由本地规则生成，尚未执行LLM调查；原始IP仅在此本地文件中'}

    def close(self):
        self.store.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def replay_to_directory(path, output=None, use_agent=False, settings_home=None):
    """Persist deterministic local artifacts; cache a completed model investigation."""
    with Replay(path) as replay:
        output = Path(output) if output else Path('data/replays') / replay.record['pcap_sha256'][:24]
        manifest_path = output / 'manifest.json'
        if output.exists() and any(output.iterdir()):
            if not manifest_path.exists() or json.loads(manifest_path.read_text(encoding='utf-8')).get('pcap_sha256') != replay.record['pcap_sha256']:
                raise ValueError('输出目录已有其他数据；请为本PCAP使用独立目录')
        output.mkdir(parents=True, exist_ok=True)
        def save(name, data):
            (output / name).write_text(json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False), encoding='utf-8')
        save('manifest.json', {'pcap_sha256': replay.record['pcap_sha256'], 'source': 'pcap_replay'})
        save('session.json', replay.record)
        save('detection.json', replay.detection)
        save('local_report.json', replay.local_report())
        status = {'output': str(output.resolve()), 'session_id': replay.session_id,
                  'prediction': replay.detection['prediction'], 'anomaly_score': replay.detection['anomaly_score'],
                  'agent_status': 'not_requested'}
        if use_agent:
            from .config import Config, provider_for
            from .credentials import Credentials, active_key
            from .agent import Agent
            from .investigation import high_risk_target
            home = Path(settings_home) if settings_home else Path(__file__).resolve().parents[1]
            config = Config.load(home / 'config.local.json')
            key = active_key(Credentials(home / 'credentials.local.json'), provider_for(config))
            code = hashlib.sha256(b''.join(Path(__file__).with_name(n).read_bytes()
                                          for n in ('agent.py', 'tools.py', 'investigation.py', 'baseline.py', 'replay.py'))).hexdigest()
            cache_key = fingerprint({'pcap': replay.record['pcap_sha256'], 'detector': detector_fingerprint(),
                                     'investigation_code': code, 'model_config': asdict(config)})
            cache = output / 'agent_report.json'
            saved = json.loads(cache.read_text(encoding='utf-8')) if cache.exists() else {}
            if saved.get('cache_key') == cache_key and saved.get('result', {}).get('investigation_report', {}).get('investigation_complete'):
                status['agent_status'] = 'cached_completed_report'
            else:
                target = high_risk_target(replay.store, replay.session_id)
                if not target:
                    c = replay.store.session_connections(replay.session_id)['connections'][0]['metrics']
                    target = dict(src=c['source_ip'], dst=c['destination_ip'], protocol=c['protocol'],
                                  sport=c['source_port'], dport=c['destination_port'], connection_id=c['connection_id'])
                # Use the same persistent budget as the UI without interrupting live captures.
                budget = Store(home / 'data/traffic.db', recover_running=False)
                try:
                    result = Agent(replay.store, None, config, key, budget_store=budget).run(
                        '调查此离线PCAP，核实规则与历史依据并输出报告。',
                        session_id=replay.session_id, remember=False, investigation_target=target)
                finally:
                    budget.close()
                if result.get('ok') and result.get('citation_valid') and result.get('investigation_report', {}).get('investigation_complete'):
                    save('agent_report.json', {'cache_key': cache_key, 'result': result})
                    status['agent_status'] = 'completed'
                else:
                    save('agent_attempt.json', result)
                    status['agent_status'] = 'incomplete'
                    status['agent_error'] = result.get('answer')
        return status
