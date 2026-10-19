"""Label-independent detector evaluation over capture-level JSON/JSONL records."""
import hashlib
import ipaddress
import json
import math
from pathlib import Path
from .anomaly import RULE_VERSION, assess_session_records

FEATURE_VERSION = 2
DEFAULT_THRESHOLD = 40


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def detector_fingerprint():
    return hashlib.sha256(b''.join(Path(__file__).with_name(name).read_bytes()
        for name in ('anomaly.py', 'capture.py', 'connection_instances.py', 'store.py', 'evaluation.py', 'replay.py'))).hexdigest()


def validate_record(record):
    if not isinstance(record, dict) or not {'session_id', 'timestamp', 'features', 'label'} <= record.keys():
        raise ValueError('数据记录需要 session_id/timestamp/features/label')
    if not isinstance(record['session_id'], str) or not record['session_id']:
        raise ValueError('session_id必须为非空字符串')
    if type(record['label']) is not int or record['label'] not in (0, 1):
        raise ValueError('label必须为整数0或1')
    if type(record['timestamp']) not in (float, int) or not math.isfinite(record['timestamp']) or record['timestamp'] < 0:
        raise ValueError('timestamp必须为有限非负Unix秒数')
    features = record['features']
    if not isinstance(features, dict) or features.get('schema_version') not in (1, FEATURE_VERSION) or not isinstance(features.get('connections'), list):
        raise ValueError('features需要schema_version=1或2和connections列表；不能导入预先计算的预测结果')
    if len(features['connections']) > 100000:
        raise ValueError('每条记录最多100000个双向五元组')
    seen = set()
    for row in features['connections']:
        if not isinstance(row, dict):
            raise ValueError('连接指标必须为对象')
        required = {'a', 'ap', 'b', 'bp', 'protocol', 'a_to_b_packets', 'b_to_a_packets',
                    'a_to_b_bytes', 'b_to_a_bytes', 'syn_seen', 'syn_ack_seen', 'fin_seen', 'rst_seen',
                    'client_is_a', 'handshake_status', 'connection_state', 'first_seen', 'last_seen'}
        if not required <= row.keys():
            raise ValueError('连接缺少双向计数/标志位/握手/时间字段')
        for endpoint in ('a', 'b'):
            if str(ipaddress.ip_address(row[endpoint])) != row[endpoint]:
                raise ValueError('IP必须使用标准化形式')
        for port in ('ap', 'bp'):
            if type(row[port]) is not int or not 0 <= row[port] <= 65535:
                raise ValueError('端口无效')
        if (row['a'], row['ap']) > (row['b'], row['bp']):
            raise ValueError('端点需按(a,ap)<=(b,bp)规范化')
        if row['protocol'] not in ('TCP', 'UDP', 'ICMP', 'ICMPv6', 'OTHER'):
            raise ValueError('协议无效')
        for key in ('a_to_b_packets', 'b_to_a_packets', 'a_to_b_bytes', 'b_to_a_bytes'):
            if type(row[key]) is not int or not 0 <= row[key] <= 10**15:
                raise ValueError('计数必须为非负整数')
        for key in ('syn_seen', 'syn_ack_seen', 'fin_seen', 'rst_seen'):
            if type(row[key]) is not int or row[key] not in (0, 1):
                raise ValueError('标志位必须为0/1')
        if row['client_is_a'] is not None and (type(row['client_is_a']) is not int or row['client_is_a'] not in (0, 1)):
            raise ValueError('方向必须为0/1/null')
        if row['handshake_status'] not in ('UNKNOWN', 'NOT_OBSERVED', 'SYN_ONLY', 'SYN_ACK_SEEN', 'CONFIRMED'):
            raise ValueError('握手状态无效')
        if row['connection_state'] not in ('UNKNOWN', 'HANDSHAKE_CONFIRMED', 'ESTABLISHED', 'CLOSED'):
            raise ValueError('连接状态无效')
        for key in ('first_seen', 'last_seen'):
            if type(row[key]) not in (int, float) or not math.isfinite(row[key]) or row[key] < 0:
                raise ValueError('连接时间无效')
        if row['last_seen'] < row['first_seen']:
            raise ValueError('末次观察不能早于首次观察')
        key = tuple(row[k] for k in ('a', 'ap', 'b', 'bp', 'protocol'))
        if features['schema_version'] == 2:
            import re
            if not isinstance(row.get('connection_id'), str) or not re.fullmatch(r'conn_[0-9a-f]{32}', row['connection_id']):
                raise ValueError('v2连接需要有效connection_id')
            if row.get('instance_kind') not in ('tcp_observed', 'transport_aggregate', 'ambiguous_fragment', 'legacy_aggregate', 'untracked_aggregate'):
                raise ValueError('连接记录类型无效')
            if type(row.get('uncertainty_flags')) is not int or not 0 <= row['uncertainty_flags'] <= 1023:
                raise ValueError('连接不确定性标记无效')
            key = row['connection_id']
        if key in seen:
            raise ValueError('同一采集内不能重复计入连接身份')
        seen.add(key)
    return record


def legacy_feature_view(features):
    """Compare old exports only when each tuple still maps to a single instance.

    A reused tuple cannot be reconstructed from old aggregate state. Such a
    dataset needs explicit re-export/review; do not bless it by relaxing checks.
    """
    import copy
    result = copy.deepcopy(features)
    result['schema_version'] = 1
    result.pop('tracking', None)
    seen = set()
    for row in result['connections']:
        key = tuple(row[k] for k in ('a', 'ap', 'b', 'bp', 'protocol'))
        if key in seen:
            raise ValueError('旧版数据集含五元组复用，无法无损对照；请保留原数据并重新导出复核')
        seen.add(key)
        for field in ('connection_id', 'instance_kind', 'boundary_reason', 'uncertainty_flags', 'handshake_basis'):
            row.pop(field, None)
    return result


def load_dataset(path):
    """JSON list, one JSON object, or JSONL; errors fail the whole evaluation."""
    path = Path(path)
    if path.is_dir():
        from .replay import Replay
        records = []
        sessions = sorted(path.rglob('session.json'))
        pcaps = sorted(path.rglob('traffic.pcap'))
        if {p.parent for p in sessions} != {p.parent for p in pcaps}:
            raise ValueError('部分PCAP缺少session.json；不能静默丢弃未完成样本')
        for session in sessions:
            saved = json.loads(session.read_text(encoding='utf-8'))
            label = json.loads(session.with_name('label.json').read_text(encoding='utf-8'))
            with Replay(session.with_name('traffic.pcap')) as replay:
                if (saved['session_id'] != label['session_id'] or replay.session_id != saved['session_id'] or
                    replay.record['pcap_sha256'] != label['pcap_sha256'] or
                    fingerprint(legacy_feature_view(replay.record['features']) if saved['features'].get('schema_version') == 1 else replay.record['features']) != fingerprint(saved['features'])):
                    raise ValueError('PCAP、会话特征或标签摘要不一致，请重新导出/复核')
            records.append(validate_record({**saved, 'label': label['label'],
                'scenario': label.get('scenario', 'unspecified'), 'provenance': label.get('provenance', {})}))
        return records
    if path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError('数据集超过128MiB导入上限')
    if path.suffix.lower() == '.jsonl':
        rows = [json.loads(line) for line in path.read_text(encoding='utf-8-sig').splitlines() if line.strip()]
    else:
        rows = json.loads(path.read_text(encoding='utf-8-sig'))
        rows = rows if isinstance(rows, list) else [rows]
    return [validate_record(row) for row in rows]


def detect(features, threshold=DEFAULT_THRESHOLD):
    if type(threshold) is not int or not 1 <= threshold <= 100:
        raise ValueError('评分阈值必须为1–100')
    # label and provenance are intentionally not accepted by the predictor.
    result = assess_session_records(features['connections'], include_all=True)
    scored = result['candidate_pairs_all'] + result['watch_connections_first_20']
    score = max((s['anomaly_score'] for s in scored), default=0)
    return {'prediction': int(score >= threshold), 'anomaly_score': score,
            'risk_level': 'high' if score >= 70 else 'medium' if score >= 40 else 'watch' if score else 'none',
            'threshold': threshold, 'assessed': result['evaluated_connections'] > 0,
            'connection_coverage': result['evaluated_connections'] / len(features['connections']) if features['connections'] else 0,
            'assessment': result}


def metrics(labels, predictions):
    if len(labels) != len(predictions) or any(type(v) is not int or v not in (0, 1) for v in labels + predictions):
        raise ValueError('标签与预测必须为等长0/1整数列表')
    tp = sum(a == b == 1 for a, b in zip(labels, predictions))
    tn = sum(a == b == 0 for a, b in zip(labels, predictions))
    fp = sum(a == 0 and b == 1 for a, b in zip(labels, predictions))
    fn = sum(a == 1 and b == 0 for a, b in zip(labels, predictions))
    div = lambda n, d: n / d if d else None
    return {'total_sessions': len(labels), 'detected_anomaly': tp + fp,
            'true_positive': tp, 'true_negative': tn, 'false_positive': fp, 'false_negative': fn,
            'precision': div(tp, tp + fp), 'recall': div(tp, tp + fn),
            'f1': div(2 * tp, 2 * tp + fp + fn),
            'false_positive_rate': div(fp, fp + tn), 'false_negative_rate': div(fn, fn + tp)}


def evaluate(records, threshold=DEFAULT_THRESHOLD):
    if not records:
        raise ValueError('数据集为空')
    ids, hashes, items = set(), set(), []
    for row in records:
        validate_record(row)
        digest = row.get('pcap_sha256')
        if row['session_id'] in ids or digest and digest in hashes:
            raise ValueError('重复session_id或PCAP摘要会重复计分，请去重')
        ids.add(row['session_id'])
        if digest:
            hashes.add(digest)
        result = detect(row['features'], threshold)
        items.append({'session_id': row['session_id'], 'label': row['label'],
                      'scenario': row.get('scenario', 'unspecified'),
                      'provenance': row.get('provenance', {}),
                      **{k: result[k] for k in ('prediction', 'anomaly_score', 'risk_level', 'assessed', 'connection_coverage')},
                      'rules': sorted({s['code'] for c in result['assessment']['candidate_pairs_all'] +
                                      result['assessment']['watch_connections_first_20'] for s in c['signals']})})
    def summarize(group):
        return metrics([r['label'] for r in group], [r['prediction'] for r in group])
    return {**summarize(items), 'unassessed_sessions': sum(not r['assessed'] for r in items),
            'unassessed_normal': sum(not r['assessed'] and r['label'] == 0 for r in items),
            'unassessed_anomaly': sum(not r['assessed'] and r['label'] == 1 for r in items),
            'assessed_subset_metrics': summarize([r for r in items if r['assessed']]),
            'human_reviewed_sessions': sum(r['provenance'].get('human_reviewed') is True for r in items),
            'threshold': threshold, 'rule_version': RULE_VERSION, 'detector_sha256': detector_fingerprint(),
            'dataset_sha256': fingerprint(records), 'unit': 'one_labeled_capture',
            'by_scenario': {s: summarize([r for r in items if r['scenario'] == s]) for s in sorted({r['scenario'] for r in items})},
            'sessions': items,
            'limitations': ['未评估协议/证据缺失的样本按未检出计入总指标，并单列数量；不删除漏检',
                            '分母为0的指标返回null；结果依赖固定阈值和标签质量',
                            '本机实验重复样本相关性高，不能外推公网攻击准确率；未验证真实LLM判断质量']}
