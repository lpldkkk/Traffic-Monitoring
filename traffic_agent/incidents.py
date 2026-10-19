"""Deterministic evidence adapters and conservative incident correlation.

This module consumes the existing detector; it does not introduce a detector,
an LLM call, a process resolver or a background investigation queue.
"""
import copy
import hashlib
import json

from .anomaly import RULE_VERSION, assess_session_records, grouped_assessment
from .applications import PROXY_APPS

CORRELATION_VERSION = 1
CORRELATION_WINDOW = 300
WINDOW_SELECTION = 'strongest_window_per_rule_per_300s_bucket'


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def identity(prefix, *values):
    return prefix + hashlib.sha256(encoded(values).encode()).hexdigest()[:32]


def risk_level(score):
    return 'high' if score >= 70 else 'medium' if score >= 40 else 'watch' if score else 'none'


def detector_windows(records):
    """Save bounded representative windows without copying every sliding deque.

    The original overview still uses its original strongest-window policy.
    Each selected window retains the exact context records and contributing
    members. The selection policy is exposed, not presented as exhaustive.
    """
    selected, singles = {}, []

    def window(client, server, signals, events, start, end):
        for signal in signals:
            key = (client, server, signal['code'], int(signal['observed']['last_seen']//CORRELATION_WINDOW))
            old = selected.get(key)
            if old is None or end-start > old[4]-old[3]:
                selected[key] = (client, server, signals, start, end, events)

    assess_session_records(records, on_window=window,
                           on_connection=lambda row, score: singles.append((row, score)))
    seen = set()
    for client, server, signals, start, end, events in selected.values():
        key = (client, server, start, end)
        if key in seen:
            continue
        seen.add(key)
        assessment = grouped_assessment(client, server, copy.deepcopy(signals))
        context = events[start:end]
        members = {}
        for signal in signals:
            code = signal['code']
            members[code] = [event[5] for event in context if (
                code == 'PORT_SWEEP' or code == 'SYN_ONLY_BURST' and event[2] or
                code == 'RESET_BURST' and event[3] or code == 'SHORT_CONNECTION_BURST' and
                event[4] and event[1] == signal['observed']['short_connection_server_port'])]
        yield 'group_window', assessment, [e[5] for e in context], members
    for row, score in singles:
        yield 'connection', score, [row], {s['code']: [row] for s in score['signals']}


def subject_processes(connection, application):
    """Use saved identity evidence only. Names never define process equality."""
    if connection['direction_basis'] != 'observed_syn_initiator':
        return [], []
    endpoint = (connection['source_ip'], connection['source_port'])
    observations = application['observations']
    owners = [o for o in observations if o['role'] == 'socket_owner' and
              (o['endpoint_host'], o['endpoint_port']) == endpoint and o['pid'] is not None and
              o['process_created'] is not None and o['confidence'] == 'snapshot_match' and
              o['app'].casefold() not in PROXY_APPS and o['matched_packets'] > 0]
    tokens = sorted({(o['pid'], o['process_created']) for o in owners})
    # Multiple lifetime candidates at the initiating endpoint are ambiguous.
    if len(tokens) != 1:
        return [], []
    proxy_peer = any(o['role'] == 'socket_owner' and o['app'].casefold() in PROXY_APPS and
                     (o['endpoint_host'], o['endpoint_port']) ==
                     (connection['destination_ip'], connection['destination_port']) and
                     o['confidence'] == 'snapshot_match' and o['matched_packets'] > 0 for o in observations)
    verified = [o for o in observations if proxy_peer and o['role'] == 'proxy_original' and
                (o['endpoint_host'], o['endpoint_port']) == endpoint and
                (o['pid'], o['process_created']) == tokens[0] and o['matched_packets'] > 0]
    return [list(t) for t in tokens], [list(tokens[0])] if verified else []


def family(rule):
    return 'connection_attempts' if rule in ('PORT_SWEEP', 'SYN_ONLY_BURST') else rule


def correlate(finding, other, event):
    """Return a reproducible relation, never infer causality or maliciousness."""
    a, b = finding['data'], other['data']
    same_connection = (finding['session_id'], finding['connection_id']) == (other['session_id'], other['connection_id'])
    within = event['anchor_time'] <= finding['first_seen'] <= event['anchor_time']+CORRELATION_WINDOW
    if not same_connection and (not within or a['capture_scope'] != b['capture_scope']):
        return None
    rule, confidence, fields = None, None, {}
    if same_connection:
        rule, confidence = 'SAME_CONNECTION_INSTANCE', 'high'
        fields = {'session_id': finding['session_id'], 'connection_id': finding['connection_id']}
    elif (family(finding['rule_code']) == family(other['rule_code']) and
          a['connection']['destination_ip'] == b['connection']['destination_ip'] and
          a['connection']['protocol'] == b['connection']['protocol']):
        same_process = set(map(tuple, a['subject_processes'])) & set(map(tuple, b['subject_processes']))
        same_proxy = set(map(tuple, a['verified_proxy_processes'])) & set(map(tuple, b['verified_proxy_processes']))
        same_service = (family(finding['rule_code']) == 'connection_attempts' or
                        a['connection']['destination_port'] == b['connection']['destination_port'])
        if same_service and same_proxy:
            rule, confidence = 'VERIFIED_PROXY_INBOUND_PROCESS', 'medium'
            fields = {'process_instances': sorted(same_proxy), 'required_evidence':
                ['proxy_original', 'matching_initiator_socket_owner', 'proxy_peer_socket_owner']}
        elif same_service and same_process:
            rule, confidence = 'SAME_LOCAL_PROCESS_BEHAVIOR', 'medium'
            fields = {'process_instances': sorted(same_process), 'identity_basis': 'saved_socket_snapshot'}
        elif (finding['session_id'] == other['session_id'] and a['score_scope'] == b['score_scope'] == 'group_window'
              and finding['rule_code'] == other['rule_code'] and same_service and
              a['connection']['source_ip'] == b['connection']['source_ip'] and
              a['connection']['direction_basis'] == b['connection']['direction_basis'] == 'observed_syn_initiator'):
            rule, confidence = 'SAME_INITIATOR_DETECTED_PATTERN', 'medium'
            fields = {'initiator': a['connection']['source_ip'], 'detector_rule': finding['rule_code'],
                      'identity_basis': 'observed_syn_and_matching_group_behavior_not_ip_alone'}
        if rule:
            fields.update(target=a['connection']['destination_ip'], protocol=a['connection']['protocol'],
                          behavior_family=family(finding['rule_code']), capture_scope=a['capture_scope'],
                          observed_service_ports=[a['connection']['destination_port'], b['connection']['destination_port']])
    if rule is None:
        return None
    return {'rule': rule, 'version': CORRELATION_VERSION, 'confidence': confidence,
            'fields': fields, 'window': {'anchor': event['anchor_time'], 'seconds': CORRELATION_WINDOW,
                'time_basis': 'connection_first_seen', 'same_connection_exempt': same_connection},
            'evidence_references': sorted(set(a['evidence_references']+b['evidence_references'])),
            'meaning': '可解释的共同调查范围；关联不证明因果关系或恶意行为'}
