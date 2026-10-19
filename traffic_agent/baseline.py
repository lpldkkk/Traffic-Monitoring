"""Descriptive historical references, not a trained classifier or safety verdict."""
from collections import Counter
from math import log1p
from statistics import mean, pstdev


MIN_CAPTURES = 3
MIN_CONNECTIONS = 5


def normal_range(values):
    if not values:
        return None
    avg, std = mean(values), pstdev(values)
    return {'mean': avg, 'lower': max(0, avg - 3 * std), 'upper': avg + 3 * std,
            'samples': len(values), 'method': 'mean_plus_minus_3_population_std',
            'zero_variance': std == 0}


def numeric_comparison(feature, current, reference, ready):
    deviation = None
    if ready and current is not None and reference:
        deviation = current - min(max(current, reference['lower']), reference['upper'])
    return {'feature': feature, 'current_value': current, 'normal_range': reference,
            'deviation': deviation, 'deviation_unit': 'signed_distance_outside_range',
            'status': 'insufficient_evidence' if not ready or current is None else
                      'outside_range' if deviation else 'within_range'}


def service_port(connection):
    return connection['destination_port'] if connection['direction_basis'] == 'observed_syn_initiator' else None


class Baseline:
    def __init__(self, profiles):
        # The store only supplies earlier, complete captures on the same interface.
        self.profiles = [p for p in profiles if p['normal_label'] == 'user_confirmed_normal']

    def summary(self):
        connections = [c for p in self.profiles for c in p['connections']]
        ports = Counter(service_port(c) for c in connections if service_port(c) is not None)
        hosts = Counter(ip for c in connections for ip in {c['source_ip'], c['destination_ip']})
        return {'status': 'available' if len(self.profiles) >= MIN_CAPTURES else 'insufficient_evidence',
                'provenance': 'user_confirmed_normal',
                'capture_numbers': [p['number'] for p in self.profiles],
                'capture_count': len(self.profiles), 'connection_samples': len(connections),
                'minimum_captures': MIN_CAPTURES, 'minimum_connection_samples': MIN_CONNECTIONS,
                'average_connection_count': normal_range([len(p['connections']) for p in self.profiles]),
                'connections_per_300_seconds': normal_range([len(p['connections']) * 300 / p['seconds'] for p in self.profiles]),
                'packets_per_connection': normal_range([c['packets'] for c in connections]),
                'observed_duration': normal_range([c['duration'] for c in connections]),
                'common_ports': [{'port': v, 'connections': n} for v, n in ports.most_common(20)],
                'common_ips': [{'host': v, 'connections': n} for v, n in hosts.most_common(20)],
                'scope': '完整且至少60秒的同网卡历史采集；常见端口仅使用已观察SYN方向的服务端口；IP为双端化名',
                'limitations': ['人工正常标签不是安全证明；历史删除或取消标签会改变参考范围',
                                '均值±3倍标准差仅为描述区间，不是置信区间；偏态、少样本和业务变化可能使区间失真',
                                'duration是首次到末次观察的跨度；连接实例仍受缺包和边界不确定性影响；基线不比较进程或应用语义，不能证明行为安全']}

    def compare(self, session):
        """Compare one connection with the same protocol and known service port."""
        port = service_port(session)
        matched = [(p, c) for p in self.profiles for c in p['connections']
                   if c['protocol'] == session['protocol'] and
                   (port is None or service_port(c) == port)]
        captures = {p['number'] for p, _ in matched}
        connections = [c for _, c in matched]
        ready = len(captures) >= MIN_CAPTURES and len(connections) >= MIN_CONNECTIONS
        comparisons = [numeric_comparison(feature, session[feature],
                       normal_range([c[feature] for c in connections]), ready)
                       for feature in ('packets', 'duration')]
        ips = {ip for p in self.profiles for c in p['connections']
               for ip in (c['source_ip'], c['destination_ip'])}
        ports = {service_port(c) for p in self.profiles for c in p['connections'] if service_port(c) is not None}
        for feature, value, known in [('service_port', port, ports),
                                      ('destination_ip', session['destination_ip'], ips)]:
            available = len(self.profiles) >= MIN_CAPTURES and value is not None
            comparisons.append({'feature': feature, 'current_value': value,
                'normal_range': {'known_values_first_20': sorted(known)[:20], 'known_values_total': len(known)},
                'deviation': int(value not in known) if available else None,
                'deviation_unit': 'unseen_category',
                'status': ('unseen_in_history' if value not in known else 'seen_in_history') if available else 'insufficient_evidence'})
        return {'status': 'available' if ready else 'insufficient_evidence',
                'matched_capture_count': len(captures), 'matched_connection_count': len(connections),
                'matching': {'protocol': session['protocol'], 'service_port': port},
                'comparisons': comparisons,
                'interpretation': '偏离或首次出现只是上下文，不加异常分；未见过不等于恶意'}


def similar_connections(connection, profiles, limit=5):
    """Transparent nearest neighbors; labels never influence similarity ranking."""
    matches = []
    for profile in profiles:
        for other in profile['connections']:
            if other['protocol'] != connection['protocol']:
                continue
            distances = {f: abs(log1p(connection[f]) - log1p(other[f]))
                         for f in ('packets', 'bytes', 'duration') if connection[f] is not None and other[f] is not None}
            if service_port(connection) is not None and service_port(other) is not None:
                distances['service_port'] = int(service_port(connection) != service_port(other))
            if not distances:
                continue
            matches.append({'capture_number': profile['number'], 'normal_label': profile['normal_label'],
                'similarity': 1 / (1 + mean(distances.values())), 'feature_distances': distances,
                'connection': other})
    matches.sort(key=lambda r: (-r['similarity'], r['capture_number'], r['connection']['source_port']))
    return {'matches': matches[:limit], 'matching_connections': len(matches),
            'returned': min(limit, len(matches)), 'truncated': len(matches) > limit,
            'method': 'same_protocol; 1/(1+mean(abs(log1p numeric differences), service-port mismatch))',
            'limitations': ['相似度不是恶意概率；未标记历史不能当作正常样本',
                            '只比较同网卡更早完整采集的连接元数据，不识别应用内容；缺失握手不能由相似记录补全']}
