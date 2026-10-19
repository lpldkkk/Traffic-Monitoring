"""Conservative metadata triage. Scores prioritize review; they are not IDS verdicts."""
from collections import Counter, defaultdict, deque


WINDOW_SECONDS = 300
RULE_VERSION = 2
THRESHOLDS = {
    'PORT_SWEEP': {'distinct_ports': 20, 'syn_only_connections': 10, 'syn_only_ratio': .5},
    'SYN_ONLY_BURST': {'connections': 20, 'ratio': .7},
    'RESET_BURST': {'connections': 15, 'ratio': .6, 'max_observed_duration': WINDOW_SECONDS},
    'SHORT_CONNECTION_BURST': {'connections_same_port': 20, 'max_duration': 3},
    'BULK_OUTBOUND': {'bytes': 50 * 1024 * 1024, 'ratio': .95, 'bytes_per_second': 200 * 1024},
    'SMALL_PACKET_RATE': {'duration': 10, 'packets': 5000, 'packets_per_second': 500, 'mean_bytes': 256},
}


def _level(score):
    return 'high' if score >= 70 else 'medium' if score >= 40 else 'watch' if score else 'none'


def explain_assessment(result, grouped=False):
    """Expose every scoring input; rule thresholds are NOT learned normal ranges."""
    mappings = {
        'PORT_SWEEP': [('distinct_server_ports', 'distinct_ports', '>='), ('syn_only_connections', 'syn_only_connections', '>='), ('syn_only_ratio', 'syn_only_ratio', '>=')],
        'SYN_ONLY_BURST': [('syn_only_connections', 'connections', '>='), ('syn_only_ratio', 'ratio', '>=')],
        'RESET_BURST': [('rst_connections', 'connections', '>='), ('rst_ratio', 'ratio', '>=')],
        'SHORT_CONNECTION_BURST': [('short_closed_connections_same_port', 'connections_same_port', '>=')],
        'BULK_OUTBOUND': [('client_to_server_bytes', 'bytes', '>='), ('ratio', 'ratio', '>='), ('bytes_per_second', 'bytes_per_second', '>=')],
        'SMALL_PACKET_RATE': [('duration', 'duration', '>='), ('packets', 'packets', '>='), ('packets_per_second', 'packets_per_second', '>='), ('mean_bytes', 'mean_bytes', '<=')],
    }
    evidence, components = [], []
    remaining = 100
    for index, signal in enumerate(result['signals']):
        code, observed, thresholds = signal['code'], signal['observed'], signal['thresholds']
        contribution = min(remaining, 10 if grouped and index else signal['score'])
        remaining -= contribution
        components.append({'rule': code, 'rule_score': signal['score'], 'contribution': contribution})
        values = dict(observed)
        if observed.get('connections'):
            values['syn_only_ratio'] = observed['syn_only_connections'] / observed['connections']
            values['rst_ratio'] = observed['rst_connections'] / observed['connections']
        for feature, threshold, operator in mappings[code]:
            evidence.append({'rule': code, 'feature': feature, 'value': values[feature],
                'baseline': thresholds[threshold], 'baseline_kind': 'rule_threshold',
                'operator': operator, 'reason': signal['reason'],
                'window': {k: observed[k] for k in ('first_seen', 'last_seen', 'time_basis') if k in observed}})
        if grouped:
            evidence.append({'rule': code, 'feature': 'window_seconds',
                'value': observed['last_seen'] - observed['first_seen'],
                'baseline': WINDOW_SECONDS, 'baseline_kind': 'rule_threshold',
                'operator': '<=', 'reason': '按连接首次观察时间关联，不是每个标志位发生时间'})
        signal['counting_conditions'] = {
            'RESET_BURST': '仅计入观察跨度<=300秒且含RST的连接；RST实际发生时间未保存',
            'SHORT_CONNECTION_BURST': '仅计入已观察完整握手且CLOSED、观察跨度<=3秒的同服务端口连接',
            'SYN_ONLY_BURST': '仅计入握手状态SYN_ONLY的连接；不等于握手失败',
            'PORT_SWEEP': '方向由SYN确认；distinct_server_ports统计该主机对窗口内全部目标端口',
        }.get(code, '仅在观察完整TCP握手后评估')
    result.update(anomaly_score=result['score'], risk_level=result['level'], evidence=evidence,
                  score_components=components,
                  scoring_method='max_rule_plus_10_per_extra_rule_capped_100' if grouped else 'sum_rules_capped_100',
                  reliability={'kind': 'metadata_heuristic', 'calibrated_probability': None,
                               'reason': '指标可复核；阈值尚未在标注真实流量上校准，不能解释为恶意概率'})
    return result


def assess_connection(metric):
    result = explain_assessment(_assess_connection(metric))
    result['reliability']['handshake_status'] = metric['handshake_status']
    return result


def _assess_connection(metric):
    """A single connection only produces weak leads; missing handshake is not failure."""
    if metric['protocol'] != 'TCP':
        return {'score': 0, 'level': 'none', 'review_required': False,
                'status': 'not_applicable', 'signals': [],
                'limitations': ['当前规则只评估已保存的TCP连接行为；未评估此协议不代表安全']}
    signals = []
    if metric['handshake_status'] == 'CONFIRMED':
        sent = metric['client_to_server_bytes']
        total = metric['bytes']
        bulk = THRESHOLDS['BULK_OUTBOUND']
        rate = THRESHOLDS['SMALL_PACKET_RATE']
        if (sent is not None and sent >= bulk['bytes'] and total and
                sent / total >= bulk['ratio'] and (metric['bytes_per_second'] or 0) >= bulk['bytes_per_second']):
            signals.append({'code': 'BULK_OUTBOUND', 'score': 25,
                            'thresholds': bulk.copy(),
                            'observed': {'client_to_server_bytes': sent, 'total_bytes': total,
                                         'ratio': sent / total, 'bytes_per_second': metric['bytes_per_second']},
                            'reason': '客户端向服务端大额传输；备份、上传等正常业务也可能符合，未证明是本机外传'})
        if ((metric['duration'] or 0) >= rate['duration'] and metric['packets'] >= rate['packets'] and
                (metric['packets_per_second'] or 0) >= rate['packets_per_second'] and
                total / metric['packets'] <= rate['mean_bytes']):
            signals.append({'code': 'SMALL_PACKET_RATE', 'score': 30,
                            'thresholds': rate.copy(),
                            'observed': {'packets': metric['packets'],
                                         'duration': metric['duration'], 'mean_bytes': total / metric['packets'],
                                         'packets_per_second': metric['packets_per_second']},
                            'reason': '持续高频小包，需结合业务与对端核实'})
    score = min(100, sum(item['score'] for item in signals))
    insufficient = metric['protocol'] == 'TCP' and metric['handshake_status'] in ('UNKNOWN', 'SYN_ONLY', 'SYN_ACK_SEEN', 'NOT_OBSERVED')
    return {'score': score, 'level': _level(score), 'review_required': score >= 40,
            'status': 'candidate' if score >= 40 else 'watch' if score else 'insufficient_evidence' if insufficient else 'no_signal',
            'signals': signals,
            'limitations': ['单条连接只有包头元数据；单个 SYN、RST、短连接或大流量不能证明攻击'] +
                           (['握手未完整观察，不能把 UNKNOWN 当作连接失败'] if insufficient else [])}


def grouped_assessment(client, server, signals):
    """Shared scoring policy for the overview and optional window evidence."""
    signals = sorted(signals, key=lambda item: -item['score'])
    score = min(100, signals[0]['score'] + 10 * (len(signals)-1))
    return explain_assessment({'src': client, 'dst': server, 'score': score,
        'level': _level(score), 'signals': signals, 'window_seconds': WINDOW_SECONDS,
        'reason': '仅为需核实的行为线索，不是恶意流量结论'}, grouped=True)


def assess_session_records(records, include_all=False, on_window=None, on_connection=None):
    """Find correlated behavior in five-minute windows, grouped by observed initiator."""
    groups = defaultdict(list)
    unknown = 0
    non_tcp = 0
    watches = []
    for row in records:
        if row['protocol'] != 'TCP':
            non_tcp += 1
            continue
        if row['client_is_a'] is None:
            unknown += 1
            continue
        client = row['a'] if row['client_is_a'] else row['b']
        server = row['b'] if row['client_is_a'] else row['a']
        client_port = row['ap'] if row['client_is_a'] else row['bp']
        port = row['bp'] if row['client_is_a'] else row['ap']
        duration = max(0, row['last_seen'] - row['first_seen'])
        packets = row['a_to_b_packets'] + row['b_to_a_packets']
        total_bytes = row['a_to_b_bytes'] + row['b_to_a_bytes']
        score = assess_connection({'protocol': 'TCP', 'handshake_status': row['handshake_status'],
            'client_to_server_bytes': row['a_to_b_bytes'] if row['client_is_a'] else row['b_to_a_bytes'],
            'bytes': total_bytes, 'packets': packets, 'duration': duration,
            'bytes_per_second': total_bytes / duration if duration else None,
            'packets_per_second': packets / duration if duration else None})
        if score['score']:
            if on_connection is not None:
                on_connection(row, score)
            watches.append({'connection_id': row.get('connection_id'), 'src': client, 'dst': server, 'sport': client_port, 'dport': port,
                            'protocol': 'TCP', **score})
        groups[(client, server)].append((row['first_seen'], port,
            row['handshake_status'] == 'SYN_ONLY',
            bool(row['rst_seen']) and duration <= THRESHOLDS['RESET_BURST']['max_observed_duration'],
            row['handshake_status'] == 'CONFIRMED' and row['connection_state'] == 'CLOSED' and
            duration <= THRESHOLDS['SHORT_CONNECTION_BURST']['max_duration'], row))

    candidates = []
    for (client, server), events in groups.items():
        events.sort(key=lambda event: event[:5])
        active = deque()
        ports = Counter()
        short_ports = Counter()
        syn_only = resets = 0
        strongest = {}
        for index, event in enumerate(events):
            stamp, port, is_syn_only, is_reset, is_short = event[:5]
            active.append(event)
            ports[port] += 1
            if is_short:
                short_ports[port] += 1
            syn_only += is_syn_only
            resets += is_reset
            while active and stamp - active[0][0] > WINDOW_SECONDS:
                old = active.popleft()
                ports[old[1]] -= 1
                if not ports[old[1]]:
                    del ports[old[1]]
                if old[4]:
                    short_ports[old[1]] -= 1
                    if not short_ports[old[1]]:
                        del short_ports[old[1]]
                syn_only -= old[2]
                resets -= old[3]
            count = len(active)
            observations = {'connections': count, 'distinct_server_ports': len(ports),
                            'syn_only_connections': syn_only, 'rst_connections': resets,
                            'short_closed_connections_same_port': short_ports.get(port, 0) if is_short else 0,
                            'short_connection_server_port': port if is_short else None,
                            'first_seen': active[0][0], 'last_seen': stamp,
                            'time_basis': 'connection_first_seen'}
            sweep = THRESHOLDS['PORT_SWEEP']
            syn = THRESHOLDS['SYN_ONLY_BURST']
            reset = THRESHOLDS['RESET_BURST']
            checks = (
                ('PORT_SWEEP', len(ports) >= sweep['distinct_ports'] and syn_only >= sweep['syn_only_connections'] and syn_only / count >= sweep['syn_only_ratio'],
                 70, '5分钟内访问多个目标端口且至少半数仅观察到SYN；可能是探测，也可能是采集缺包'),
                ('SYN_ONLY_BURST', syn_only >= syn['connections'] and syn_only / count >= syn['ratio'],
                 50, '5分钟内多条连接只观察到SYN；不能据此证明目标拒绝连接'),
                ('RESET_BURST', resets >= reset['connections'] and resets / count >= reset['ratio'],
                 45, '5分钟内开始的多条短时连接含RST记录；需核实应用关闭方式或网络故障，RST准确时间未保存'),
                ('SHORT_CONNECTION_BURST', observations['short_closed_connections_same_port'] >= THRESHOLDS['SHORT_CONNECTION_BURST']['connections_same_port'],
                 40, '5分钟内同一服务端口反复建立并快速关闭；正常轮询也可能符合'),
            )
            window_signals = []
            for code, matched, score, reason in checks:
                if matched and on_window is not None:
                    window_signals.append({'code': code, 'score': score, 'reason': reason,
                        'thresholds': {**THRESHOLDS[code], 'window_seconds': WINDOW_SECONDS},
                        'observed': observations.copy()})
                if matched and (code not in strongest or count > strongest[code]['observed']['connections']):
                    strongest[code] = {'code': code, 'score': score, 'reason': reason,
                                       'thresholds': {**THRESHOLDS[code], 'window_seconds': WINDOW_SECONDS},
                                       'observed': observations.copy()}
            if window_signals:
                # The immutable sorted list plus slice avoids copying an ever
                # growing active window on every packet/connection.
                on_window(client, server, window_signals, events, index+1-len(active), index+1)
        if strongest:
            candidates.append(grouped_assessment(client, server, list(strongest.values())))
    candidates.sort(key=lambda item: (-item['score'], item['src'], item['dst']))
    watches.sort(key=lambda item: (-item['score'], item['src'], item['sport']))
    result = {'rule_version': RULE_VERSION, 'window_seconds': WINDOW_SECONDS,
            'evaluated_connections': len(records)-unknown-non_tcp,
            'unknown_direction_connections': unknown,
            'non_tcp_connections': non_tcp,
            'candidate_pairs_total': len(candidates),
            'candidate_pairs_first_20': candidates[:20],
            'watch_connections_total': len(watches),
            'watch_connections_first_20': watches[:20],
            'scope': '仅基于本次采集保存的包头元数据与已观察到的客户端方向；驱动层丢包未知，分数只用于调查排序'}
    if include_all:
        result['candidate_pairs_all'] = candidates
    return result
