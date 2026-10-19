"""Local connection dashboard. OS process snapshots are never proof of packet ownership."""
from collections import defaultdict
import hashlib
import ipaddress
import socket
import threading
import time
from datetime import datetime

import psutil
from .applications import PROXY_APPS, application_name, observation


def address(value):
    return str(ipaddress.ip_address(str(value).split('%')[0]))


def endpoint_text(ip, port):
    return f"[{ip}]:{port}" if ':' in ip else f"{ip}:{port}"


def format_bytes(value):
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if abs(value) < 1024 or unit == 'TB':
            return f"{value:,.0f} {unit}" if unit == 'B' else f"{value:,.1f} {unit}"
        value /= 1024


def connection_page(connections, page=0, query=''):
    """Filter the complete snapshot before paging; page size never limits collection."""
    terms = query.strip().casefold().split()
    matches = connections
    if terms:
        fields = ('app', 'destination', 'local_ip', 'remote_ip', 'local_port', 'remote_port', 'protocol')
        matches = [c for c in connections if all(term in ' '.join(str(c.get(k, '')) for k in fields).casefold() for term in terms)]
    pages = max(1, (len(matches)+9)//10)
    page = min(max(0, page), pages-1)
    offset = page*10
    return dict(items=matches[offset:offset+10], page=page, pages=pages, offset=offset,
                total=len(connections), matched=len(matches))


class ProcessResolver:
    """Poll connection tables once/second, never inspect paths, command lines or payloads."""
    def __init__(self):
        self.lock = threading.RLock()
        self.local_ips = {'127.0.0.1', '::1'}
        self.tcp, self.udp = {}, {}
        self.sampled_at = 0
        self.error = None

    def refresh(self):
        now = time.time()
        ips = {'127.0.0.1', '::1'}
        try:
            for entries in psutil.net_if_addrs().values():
                for a in entries:
                    if a.family in (socket.AF_INET, socket.AF_INET6):
                        ips.add(address(a.address))
        except (OSError, psutil.Error):
            pass
        tcp, udp, processes = defaultdict(dict), defaultdict(dict), {}
        error = None
        try:
            for c in psutil.net_connections(kind='inet'):
                if not c.laddr or c.pid is None:
                    continue
                if c.pid not in processes:
                    try:
                        process = psutil.Process(c.pid)
                        processes[c.pid] = {'pid': c.pid, 'app': application_name(process.name()), 'created': process.create_time()}
                    except (OSError, psutil.Error):
                        processes[c.pid] = None
                owner = processes[c.pid]
                if owner is None:
                    continue
                local = (address(c.laddr.ip), c.laddr.port)
                if c.type == socket.SOCK_STREAM and c.raddr:
                    tcp[(*local, address(c.raddr.ip), c.raddr.port)][c.pid] = owner
                elif c.type == socket.SOCK_DGRAM:
                    udp[local][c.pid] = owner
        except (OSError, psutil.Error, RuntimeError) as exc:
            error = '应用归属读取受限（' + type(exc).__name__ + '）；流量采集不受影响'
        with self.lock:
            self.local_ips, self.tcp, self.udp = ips, dict(tcp), dict(udp)
            self.sampled_at, self.error = now, error

    def identify(self, protocol, local, remote, stamp):
        with self.lock:
            # Never label an old packet using a current reused socket/PID.
            if abs(stamp-self.sampled_at) > 2:
                return None
            if protocol == 'TCP':
                owners = self.tcp.get((*local, *remote), {})
                basis = 'TCP完整端点匹配（连接表快照）'
            elif protocol == 'UDP':
                owners = dict(self.udp.get(local, {}))
                wildcard = '::' if ':' in local[0] else '0.0.0.0'
                owners.update(self.udp.get((wildcard, local[1]), {}))
                basis = 'UDP本地端口匹配（非逐包归属证明）'
            else:
                return None
            if len(owners) != 1:
                return None
            owner = next(iter(owners.values()))
            if owner['created'] > stamp:
                return None
            return {**owner, 'basis': basis, 'sampled_at': self.sampled_at}

    def identify_proxy(self, metadata, started, stamp):
        """Match the app-to-proxy socket, requiring the reverse socket to belong to Mihomo."""
        try:
            source = (address(metadata['sourceIP']), int(metadata['sourcePort']))
            inbound_port = int(metadata['inboundPort'])
            inbound_ip = address(metadata['inboundIP'])
            created_before = datetime.fromisoformat(started.replace('Z', '+00:00')).timestamp()
        except (KeyError, ValueError, TypeError):
            return None
        if metadata.get('network', '').lower() != 'tcp':
            return None
        with self.lock:
            if abs(stamp-self.sampled_at) > 2:
                return None
            candidates = {}
            for key, owners in self.tcp.items():
                if key[:2] != source or key[3] != inbound_port:
                    continue
                if inbound_ip not in ('0.0.0.0', '::') and key[2] != inbound_ip:
                    continue
                reverse = self.tcp.get((key[2], key[3], key[0], key[1]), {})
                if not any(o['app'].lower() in PROXY_APPS for o in reverse.values()):
                    continue
                candidates.update(owners)
            if len(candidates) != 1:
                return None
            owner = next(iter(candidates.values()))
            if owner['created'] > created_before:
                return None
            return {**owner, 'basis': '代理源端点 + 本地完整TCP端点 + 代理反向进程快照匹配', 'sampled_at': self.sampled_at}


def rank_connections(rows, local_ips, identify=None, now=None):
    """Combine both directions and all time buckets before ranking; only metadata enters."""
    now = time.time() if now is None else now
    combined, targets = {}, defaultdict(set)
    for row in rows:
        src, dst = (address(row['src']), row.get('sport', 0)), (address(row['dst']), row.get('dport', 0))
        src_local, dst_local = src[0] in local_ips, dst[0] in local_ips
        if src_local != dst_local:
            local, remote = (src, dst) if src_local else (dst, src)
        else:
            local, remote = sorted((src, dst))
        direction_known = src_local or dst_local
        loopback = src_local and dst_local
        key = (row['protocol'], *local, *remote, row.get('connection_id'))
        if key not in combined:
            combined[key] = dict(id=hashlib.sha256(repr(key).encode()).hexdigest()[:20],
                connection_id=row.get('connection_id'), protocol=row['protocol'], local_ip=local[0], local_port=local[1], remote_ip=remote[0], remote_port=remote[1],
                direction_known=direction_known, local_connection=loopback, bytes=0, upload=0, download=0,
                packets=0, syn=0, rst=0, first=row.get('first', row.get('timestamp', now)), last=0,
                owners={}, unknown_bytes=0, flow_ids=[], source=row['source'])
        c = combined[key]
        size, stamp = row['bytes'], row.get('last', row.get('timestamp', now))
        c['bytes'] += size
        c['packets'] += row.get('packets', 1)
        c['syn'] += row.get('syn', 0)
        c['rst'] += row.get('rst', 0)
        c['first'] = min(c['first'], row.get('first', stamp))
        c['last'] = max(c['last'], stamp)
        # Local-to-local traffic is not internet upload/download. Show its own total only.
        if direction_known and not loopback:
            c['upload' if src == local else 'download'] += size
        if row.get('id') is not None and len(c['flow_ids']) < 20:
            c['flow_ids'].append(row['id'])
        if row['protocol'] == 'TCP' and row.get('syn', 0):
            targets[(src[0], dst[0])].add(dst[1])
        # Live rows carry the owner observed at ingestion; offline rows must never be reattributed.
        owner = row.get('owner')
        if owner is None and identify:
            owner = identify(row['protocol'], local, remote, stamp)
        if owner:
            owner_key = (owner['pid'], owner['created'], owner['app'])
            item = c['owners'].setdefault(owner_key, {**owner, 'bytes': 0})
            item['bytes'] += size
        else:
            c['unknown_bytes'] += size
    output = []
    for c in combined.values():
        c['owners'] = sorted(c['owners'].values(), key=lambda o: o['bytes'], reverse=True)
        c['app'] = c['owners'][0]['app'] if len(c['owners']) == 1 else '多个进程 / 归属变化' if c['owners'] else '应用未识别'
        c['ownership_ratio'] = 1-c['unknown_bytes']/max(c['bytes'], 1)
        c['recent'] = now-c['last'] <= 10
        reasons = []
        ports = max(len(targets.get((c['local_ip'], c['remote_ip']), ())), len(targets.get((c['remote_ip'], c['local_ip']), ())))
        if ports >= 20:
            reasons.append(f'近5分钟观测到同一来源向同一对端的 {ports} 个端口发送SYN，存在端口扫描迹象；需核实业务')
        if c['syn'] >= 20 and c['packets'] and c['syn']/c['packets'] >= .8:
            reasons.append(f"该连接 {c['syn']} 个SYN占包数80%以上，存在重复握手迹象；不等于连接失败")
        if c['rst'] >= 20:
            reasons.append(f"该连接观察到 {c['rst']} 个RST，存在频繁连接重置")
        c['alerts'] = reasons
        c['anomaly'] = bool(reasons)
        output.append(c)
    output.sort(key=lambda c: (-c['bytes'], c['id']))
    return {'connections': output, 'count': len(output), 'bytes': sum(c['bytes'] for c in output),
            'upload': sum(c['upload'] for c in output), 'download': sum(c['download'] for c in output),
            'alerts': sum(c['anomaly'] for c in output), 'local_bytes': sum(c['bytes'] for c in output if c['local_connection']),
            'unknown_direction_bytes': sum(c['bytes'] for c in output if not c['direction_known'])}


class ConnectionTracker:
    """A bounded, in-memory 5-second ledger, refreshed outside the GUI thread."""
    def __init__(self, start=True):
        from .proxy import ProxyConnections
        self.resolver = ProcessResolver()
        self.proxy = ProxyConnections(self.resolver)
        self.lock = threading.RLock()
        self.buckets = {}
        self.evicted = 0
        self.error = None
        self.stop_event = threading.Event()
        self.thread = None
        if start:
            self.thread = threading.Thread(target=self._loop, daemon=True)
            self.thread.start()

    def _loop(self):
        while not self.stop_event.is_set():
            try:
                self.resolver.refresh()
                self.proxy.refresh()
                self.error = None
            except Exception as exc:
                self.error = '应用快照刷新失败：' + type(exc).__name__
            self.stop_event.wait(1)

    def reset(self):
        with self.lock:
            self.buckets.clear()
            self.evicted = 0

    def dashboard(self, wire=False):
        data = None if wire else self.proxy.snapshot()
        if data is not None:
            return data
        data = self.snapshot()
        if not wire and any('mihomo' in c['app'].lower() or 'clash' in c['app'].lower() for c in data['connections']):
            data['proxy_notice'] = self.proxy.error or '正在关联代理内的原始应用；当前显示网卡出口'
        return data

    def annotate(self, rows):
        """Bind both local endpoints to contemporaneous evidence before persistence."""
        with self.resolver.lock:
            ips = set(self.resolver.local_ips)
            for r in rows:
                src, dst = (address(r['src']), r.get('sport', 0)), (address(r['dst']), r.get('dport', 0))
                stamp = r.get('timestamp', time.time())
                observations, owners = [], {}
                if r['source'] == 'live' and r.get('identity_match_allowed', True):
                    for local, remote in ((src, dst), (dst, src)):
                        if local[0] not in ips:
                            continue
                        owner = self.resolver.identify(r['protocol'], local, remote, stamp)
                        if owner and (r.get('identity_not_before') is None or owner['sampled_at'] >= r['identity_not_before']):
                            owners[local] = owner
                            observations.append(observation(owner, local, confidence=
                                'snapshot_match' if r['protocol'] == 'TCP' else 'inferred'))
                # The original app is correlated only to its exact app-to-proxy
                # inbound socket, never to an encrypted/multiplexed exit tunnel.
                r['application_observations'] = observations
                local = src if src[0] in ips and dst[0] not in ips else dst if dst[0] in ips and src[0] not in ips else min(src, dst)
                r['owner'] = owners.get(local)
        for r in rows:
            if r['source'] == 'live' and r.get('identity_match_allowed', True):
                earliest = r.get('identity_not_before')
                r['application_observations'].extend(o for o in self.proxy.identify_wire(r)
                    if earliest is None or o['sampled_at'] >= earliest and o.get('connection_started', 0) >= earliest)

    def ingest(self, rows):
        unannotated = [r for r in rows if 'application_observations' not in r]
        if unannotated:
            self.annotate(unannotated)
        with self.resolver.lock:
            ips = set(self.resolver.local_ips)
        with self.lock:
            for r in rows:
                src, dst = (address(r['src']), r.get('sport', 0)), (address(r['dst']), r.get('dport', 0))
                if (src[0] in ips) != (dst[0] in ips):
                    local, remote = (src, dst) if src[0] in ips else (dst, src)
                else:
                    local, remote = sorted((src, dst))
                stamp = r.get('timestamp', time.time())
                owner = r.get('owner')
                owner_key = (owner['pid'], owner['created'], owner['app']) if owner else None
                key = (int(stamp//5)*5, r['protocol'], *src, *dst, owner_key, r.get('connection_id'))
                if key not in self.buckets:
                    self.buckets[key] = {**r, 'owner': owner, 'bytes': 0, 'packets': 0, 'syn': 0, 'rst': 0, 'first': stamp, 'last': stamp}
                b = self.buckets[key]
                for field in ('bytes', 'packets', 'syn', 'rst'):
                    b[field] += r.get(field, 1 if field == 'packets' else 0)
                b['last'] = max(b['last'], stamp)
            cutoff = int((time.time()-300)//5)*5
            for key in list(self.buckets):
                if key[0] < cutoff:
                    del self.buckets[key]
            if len(self.buckets) > 20000:
                old = sorted(self.buckets, key=lambda k: k[0])[:len(self.buckets)-20000]
                for key in old:
                    del self.buckets[key]
                self.evicted += len(old)

    def snapshot(self):
        with self.resolver.lock:
            ips = set(self.resolver.local_ips)
        with self.lock:
            cutoff = int((time.time()-300)//5)*5
            rows = [dict(v) for k, v in self.buckets.items() if k[0] >= cutoff]
        result = rank_connections(rows, ips)
        result.update(source='live', error=self.error or self.resolver.error, evicted=self.evicted,
                      scope='本次运行/当前网卡，近5分钟；应用归属为连接表快照匹配，短连接可能无法识别')
        return result

    def for_agent(self, store, limit=10, page=1, local_port=None):
        snapshot = self.dashboard()
        connections = snapshot['connections']
        if local_port is not None:
            connections = [c for c in connections if c['local_port'] == local_port]
        items = []
        for c in connections[(page-1)*limit:page*limit]:
            items.append({k: c[k] for k in ('protocol', 'local_port', 'remote_port', 'bytes', 'upload', 'download', 'packets', 'alerts', 'ownership_ratio')} |
                         {'connection_id': c.get('connection_id'), 'local_host': store.alias(c['local_ip']), 'remote_host': store.alias(c['remote_ip']) if c['remote_ip'] else None,
                          'application': c['app'], 'basis': c.get('basis', '本地连接表快照匹配；不是逐包进程证明')})
        return {'connections': items, 'scope': snapshot['scope'], 'total_connections': snapshot['count'],
                'matched_connections': len(connections), 'page': page, 'pages': max(1, (len(connections)+limit-1)//limit),
                'error': snapshot['error']}

    def close(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=5)
