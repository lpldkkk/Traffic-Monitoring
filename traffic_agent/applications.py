"""Snapshot identity metadata only: never paths, command lines, domains or payloads."""
import ntpath
import ipaddress
import math

PROXY_APPS = {'verge-mihomo.exe', 'mihomo.exe', 'clash-meta.exe', 'clash.exe', 'mihomo', 'clash'}


def application_name(value):
    return ''.join(c for c in ntpath.basename(str(value or '')) if c.isprintable())[:160]


def observation(owner, endpoint, role='socket_owner', basis=None, confidence=None):
    app = application_name(owner.get('app'))
    return dict(endpoint_ip=endpoint[0], endpoint_port=endpoint[1], role=role,
                app=app, pid=owner.get('pid'), process_created=owner.get('created'),
                sampled_at=owner['sampled_at'], basis=basis or owner.get('basis', ''),
                confidence=confidence or ('snapshot_match' if role == 'socket_owner' else 'inferred'),
                proxy_process=app.casefold() in PROXY_APPS)


def identity_label(identity):
    names = list(dict.fromkeys(r['app'] for r in identity.get('observations', []) if r['role'] == 'socket_owner'))
    if not names:
        original = list(dict.fromkeys(r['app'] for r in identity.get('observations', [])))
        return '应用未识别' if not original else ' / '.join(original[:3]) + ' · 代理推测'
    suffix = {'partial': ' · 部分匹配', 'multiple_identities': ' · 归属变化',
              'inferred': ' · 推测关联', 'snapshot_match': ' · 快照匹配'}.get(identity['status'], '')
    return ' / '.join(names[:3]) + (' …' if len(names) > 3 else '') + suffix


def storage_values(row, key, timestamp, size, packets):
    values, seen = [], set()
    if row.get('identity_match_allowed') is False:
        return values
    observations = row.get('application_observations')
    if not isinstance(observations, list):
        return values
    for item in observations[:4]:
        try:
            endpoint = (str(ipaddress.ip_address(item['endpoint_ip'])), int(item['endpoint_port']))
            if endpoint not in ((key[0], key[1]), (key[2], key[3])):
                continue
            role, confidence = item['role'], item['confidence']
            if role not in ('socket_owner', 'proxy_original') or confidence not in ('snapshot_match', 'inferred'):
                continue
            app = application_name(item['app'])
            sampled = float(item['sampled_at'])
            if row.get('identity_not_before') is not None and sampled < row['identity_not_before']:
                continue
            pid = -1 if item.get('pid') is None else int(item['pid'])
            created = -1 if item.get('process_created') is None else float(item['process_created'])
            if not app or not math.isfinite(sampled) or not math.isfinite(created) or abs(sampled-timestamp) > 2:
                continue
            if created > timestamp or pid < -1:
                continue
            basis = ''.join(c for c in str(item['basis']) if c.isprintable())[:160]
            identity = (*endpoint, role, pid, created, app, basis, confidence)
            if identity in seen:
                continue
            seen.add(identity)
            values.append((row['session_id'], *key, int(timestamp//60)*60, *identity,
                           size, packets, timestamp, timestamp, sampled, sampled, row['connection_id']))
        except (KeyError, ValueError, TypeError, OverflowError):
            continue
    return values
