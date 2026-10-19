"""Observation identities, not proof of successful TCP delivery or application use."""
import hashlib
import ipaddress
import json

TRACKING_VERSION = 1
IDLE_SECONDS = 300
FLAGS = {
    'midstream': 1, 'idle_boundary': 2, 'out_of_order': 4,
    'missing_sequence': 8, 'sequence_mismatch': 16, 'replaced_without_close': 32,
    'ambiguous_packet': 64, 'state_loss_possible': 128,
    'legacy_aggregate': 256, 'untracked_aggregate': 512,
}


def stable_id(namespace, key, marker):
    value = json.dumps([TRACKING_VERSION, namespace, key, marker], separators=(',', ':'))
    return 'conn_' + hashlib.sha256(value.encode()).hexdigest()[:32]


def canonical(row):
    a, b = sorted(((str(ipaddress.ip_address(row['src'])), int(row['sport'])),
                   (str(ipaddress.ip_address(row['dst'])), int(row['dport']))))
    return (a[0], a[1], b[0], b[1], row['protocol'])


def uncertainty_names(mask):
    return [name for name, flag in FLAGS.items() if int(mask) & flag]


def annotate(tracker, row):
    """Bounded state addition to the existing capture/replay writer pipeline.

    New SYN ISNs split instances; a timeout without SYN splits *observations*
    conservatively. Recently retired instances are only matched by captured
    header fingerprints or non-overlapping observed sequence spaces. Other
    late packets are isolated rather than assigned to a new socket owner.
    Sequence values stay in local metadata/tracker memory, never in model tools.
    """
    if not row.get('session_id'):
        return
    key = canonical(row)
    if row['protocol'] != 'TCP':
        row.update(connection_id=stable_id(row['session_id'], key, 'transport'),
                   instance_kind='transport_aggregate', boundary_reason='non_tcp_tuple',
                   uncertainty_flags=0, handshake_basis='not_observed')
        return
    tracker._tcp_ordinal += 1
    stamp = float(row['timestamp'])
    direction = int((str(ipaddress.ip_address(row['src'])), row['sport']) != key[:2])
    state_key = (row['session_id'], key)
    entry = tracker._tcp_states.get(state_key)
    seq, ackno = row.get('tcp_seq'), row.get('tcp_ack')
    fingerprint = (direction, seq, ackno, row.get('syn', 0), row.get('syn_ack', 0),
                   row.get('ack', 0), row.get('fin', 0), row.get('rst', 0), row.get('payload_bytes', 0))
    syn = bool(row.get('syn'))

    def new(reason, flags=0, kind='tcp_observed'):
        return dict(id=stable_id(row['session_id'], key, tracker._tcp_ordinal),
                    kind=kind, reason=reason, flags=flags, first=stamp, last=stamp,
                    client=direction if syn and kind != 'ambiguous_fragment' else None, isn=seq if syn else None,
                    server_isn=None, phase='SYN_ONLY' if syn and kind != 'ambiguous_fragment' else 'UNKNOWN',
                    basis='not_observed', closed=False, fins=set(), fingerprints=[], ends={})

    def fits(candidate):
        if seq is None or candidate['client'] is None:
            return False
        base = candidate['isn'] if direction == candidate['client'] else candidate['server_isn']
        peer = candidate['server_isn'] if direction == candidate['client'] else candidate['isn']
        if base is None:
            return False
        gap = 1 if candidate['closed'] else 65536
        if (seq-base) % 2**32 > candidate['ends'].get(direction, 0) + gap:
            return False
        return not row.get('ack') or peer is not None and ackno is not None and (
            (ackno-peer) % 2**32 <= candidate['ends'].get(1-direction, 0) + gap)

    def matches_current(candidate):
        if syn:
            return direction == candidate['client'] and seq == candidate['isn']
        if candidate['phase'] == 'SYN_ONLY' and row.get('syn_ack'):
            return candidate['isn'] is not None and ackno == (candidate['isn']+1) % 2**32
        if candidate['phase'] == 'SYN_ONLY' and direction == candidate['client'] and candidate['isn'] is not None:
            return seq is not None and (seq-candidate['isn']) % 2**32 <= 65536
        return fits(candidate)

    if entry is None:
        state = new('observed_syn' if syn else 'midstream',
                    (0 if syn else FLAGS['midstream']) |
                    (FLAGS['state_loss_possible'] if tracker._tcp_state_lost else 0))
        entry = {'current': state, 'retired': []}
        tracker._tcp_states[state_key] = entry
    else:
        tracker._tcp_states.move_to_end(state_key)
        current = entry['current']
        state = current
        retired = next((old for old in reversed(entry['retired']) if
            (syn and seq is not None and old['client'] == direction and old['isn'] == seq) or
            (seq is not None and fingerprint in old['fingerprints'])), None)
        if syn and current['closed'] and stamp >= current['last']:
            state = new('new_syn_after_close', FLAGS['ambiguous_packet'] if seq == current['isn'] else 0)
        elif retired is not None and (matches_current(current) or
                current['isn'] is not None and current['isn'] == retired['isn'] and current['client'] == retired['client']):
            # Reused/overlapping sequence numbers are not unique evidence.
            state = new('generation_ambiguous', FLAGS['ambiguous_packet'], 'ambiguous_fragment')
        elif retired is not None:
            state = retired
            state['flags'] |= FLAGS['out_of_order']
        elif stamp < current['first']:
            state = new('late_ambiguous', FLAGS['out_of_order'] | FLAGS['ambiguous_packet'], 'ambiguous_fragment')
        elif syn and (current['closed'] or current['client'] != direction or
                      (seq is not None and current['isn'] != seq) or
                      (seq is None and current['closed']) or stamp-current['last'] > IDLE_SECONDS):
            flags = 0 if current['closed'] else FLAGS['replaced_without_close']
            if stamp < current['last']:
                flags |= FLAGS['out_of_order']
            if seq is None:
                flags |= FLAGS['missing_sequence']
            if current['closed'] and seq == current['isn']:
                flags |= FLAGS['ambiguous_packet']
            state = new('new_syn_after_close' if current['closed'] else 'new_syn', flags)
        elif stamp-current['last'] > IDLE_SECONDS:
            state = new('idle_gap', FLAGS['idle_boundary'] | (0 if syn else FLAGS['midstream']))
        elif (current['closed'] and not entry['retired'] and not syn
              and fingerprint not in current['fingerprints'] and not fits(current)):
            state = new('post_close_without_syn', FLAGS['midstream'] | FLAGS['ambiguous_packet'])
        elif entry['retired'] and not syn:
            # A SYN-ACK must acknowledge this generation. A third ACK must
            # acknowledge its peer ISN. Do not let a retired handshake seed it.
            mismatch = (row.get('syn_ack') and current['isn'] is not None and
                        ackno != (current['isn']+1) % 2**32)
            mismatch |= (current['phase'] == 'SYN_ACK_SEEN' and direction == current['client'] and
                         current['server_isn'] is not None and row.get('ack') and
                         ackno != (current['server_isn']+1) % 2**32)
            if mismatch:
                state = new('generation_ambiguous', FLAGS['ambiguous_packet'] | FLAGS['sequence_mismatch'], 'ambiguous_fragment')
            elif current['phase'] in ('HANDSHAKE_CONFIRMED', 'ESTABLISHED'):
                # Once a tuple is reused, sequence spaces are additional
                # association evidence. Overlap/large gaps cannot be resolved
                # without reassembly; isolate instead of guessing the owner.
                matches = [candidate for candidate in [current, *entry['retired']] if fits(candidate)]
                if len(matches) == 1:
                    state = matches[0]
                    if state is not current:
                        state['flags'] |= FLAGS['out_of_order']
                else:
                    state = new('generation_ambiguous', FLAGS['ambiguous_packet'], 'ambiguous_fragment')
        if state is not current and state not in entry['retired'] and state['kind'] != 'ambiguous_fragment':
            entry['retired'] = (entry['retired'] + [current])[-2:]
            entry['current'] = state
    if len(tracker._tcp_states) > 50000:
        tracker._tcp_states.popitem(last=False)
        tracker._tcp_state_lost = True
    if stamp < state['last']:
        state['flags'] |= FLAGS['out_of_order']
    ordered = stamp >= state['last'] and state['kind'] != 'ambiguous_fragment'
    if seq is None or ackno is None:
        state['flags'] |= FLAGS['missing_sequence']
    if ordered and state['phase'] == 'SYN_ONLY' and row.get('syn_ack') and direction != state['client']:
        if state['isn'] is not None and ackno is not None and ackno != (state['isn']+1) % 2**32:
            state['flags'] |= FLAGS['sequence_mismatch']
        else:
            state['phase'], state['server_isn'] = 'SYN_ACK_SEEN', seq
    elif (ordered and state['phase'] == 'SYN_ACK_SEEN' and direction == state['client']
          and row.get('ack') and not any(row.get(flag) for flag in ('syn', 'syn_ack', 'rst', 'fin'))):
        if seq is not None and state['isn'] is not None and state['server_isn'] is not None and ackno is not None:
            valid = seq == (state['isn']+1) % 2**32 and ackno == (state['server_isn']+1) % 2**32
            if not valid:
                state['flags'] |= FLAGS['sequence_mismatch']
        else:
            valid = True  # compatibility for explicitly supplied metadata without sequence fields
        if valid:
            state['phase'] = 'HANDSHAKE_CONFIRMED'
            state['basis'] = 'flags_only' if state['flags'] & FLAGS['missing_sequence'] else 'sequence_checked'
    elif ordered and state['phase'] in ('HANDSHAKE_CONFIRMED', 'ESTABLISHED') and row.get('payload_bytes'):
        state['phase'] = 'ESTABLISHED'
    if row.get('fin'):
        state['fins'].add(direction)
    if row.get('rst') or len(state['fins']) == 2:
        state['closed'] = True
    if seq is not None and state['client'] is not None:
        base = state['isn'] if direction == state['client'] else state['server_isn']
        if base is not None:
            end = (seq-base) % 2**32 + row.get('payload_bytes', 0) + int(syn or bool(row.get('syn_ack'))) + int(bool(row.get('fin')))
            state['ends'][direction] = max(state['ends'].get(direction, 0), end)
    state['last'] = max(state['last'], stamp)
    state['fingerprints'] = (state['fingerprints'] + [fingerprint])[-32:]
    confirmed = state['phase'] in ('HANDSHAKE_CONFIRMED', 'ESTABLISHED')
    row['identity_match_allowed'] = state is entry['current'] and not (state['flags'] & FLAGS['out_of_order'])
    # A previous socket's still-fresh OS/proxy snapshot must not label a new
    # generation. Midstream observations have no known opening boundary.
    row['identity_not_before'] = state['first'] if state['client'] is not None or state['reason'] == 'post_close_without_syn' else None
    row.update(connection_id=state['id'], instance_kind=state['kind'], boundary_reason=state['reason'],
               uncertainty_flags=state['flags'], handshake_basis=state['basis'],
               client_is_a=None if state['client'] is None else int(state['client'] == 0),
               handshake_status='CONFIRMED' if confirmed else state['phase'],
               connection_state='CLOSED' if confirmed and state['closed'] else state['phase'] if confirmed else 'UNKNOWN')
