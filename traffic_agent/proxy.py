"""Read-only Mihomo connection metadata; credentials and paths never leave this module."""
import ipaddress
import json
import ntpath
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

import httpx

LIMIT = 4 * 1024 * 1024
PIPE_CLIENT = r'''
import http.client,json,sys
settings=json.load(sys.stdin)
class Stream:
    def makefile(self, *args, **kwargs): return self.file
stream=Stream()
stream.file=open(settings['pipe'], 'r+b', buffering=0)
request='GET /connections HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n'
if settings['secret']: request+='Authorization: Bearer '+settings['secret']+'\r\n'
stream.file.write((request+'\r\n').encode())
response=http.client.HTTPResponse(stream)
response.begin()
if response.status != 200: raise ValueError('controller status')
body=response.read(4194305)
if len(body)>4194304: raise ValueError('response too large')
sys.stdout.buffer.write(body)
stream.file.close()
'''


def discover():
    """Read only top-level controller settings, never profiles/subscriptions."""
    root = Path(os.environ.get('APPDATA', '')) / 'io.github.clash-verge-rev.clash-verge-rev'
    for name in ('clash-verge.yaml', 'config.yaml'):
        file = root / name
        if not file.is_file():
            continue
        fields = {}
        with file.open(encoding='utf-8') as stream:
            for line in stream:
                key, sep, value = line.partition(':')
                if sep and key in ('external-controller', 'external-controller-pipe', 'secret'):
                    value = value.strip()
                    if value.startswith('"'):
                        value = json.loads(value)
                    elif value.startswith("'") and value.endswith("'"):
                        value = value[1:-1].replace("''", "'")
                    else:
                        value = value.split(' #', 1)[0].strip()
                    fields[key] = value
        secret = fields.get('secret', '')
        if '\r' in secret or '\n' in secret:
            raise ValueError('invalid controller credential')
        pipe = fields.get('external-controller-pipe', '')
        if os.name == 'nt' and pipe.startswith('\\\\.\\pipe\\') and ntpath.basename(pipe).startswith(('verge-mihomo-', 'mihomo', 'clash')):
            return {'pipe': pipe, 'secret': secret}
        endpoint = fields.get('external-controller', '')
        if endpoint:
            url = urlsplit('http://' + endpoint)
            if not url.username and not url.password and not url.path and not url.query and not url.fragment and ipaddress.ip_address(url.hostname).is_loopback and url.port:
                return {'url': 'http://' + endpoint, 'secret': secret}
        # Runtime configuration is authoritative, including disabled controllers.
        return None
    return None


def fetch(settings):
    if 'pipe' in settings:
        result = subprocess.run([sys.executable, '-c', PIPE_CLIENT], input=json.dumps(settings).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), check=True)
        body = result.stdout
    else:
        with httpx.Client(trust_env=False, follow_redirects=False, timeout=2) as client:
            headers = {'Authorization': 'Bearer ' + settings['secret']} if settings['secret'] else {}
            with client.stream('GET', settings['url'] + '/connections', headers=headers) as response:
                response.raise_for_status()
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > LIMIT:
                        raise ValueError('response too large')
    if len(body) > LIMIT:
        raise ValueError('response too large')
    result = json.loads(body)
    if not isinstance(result.get('connections'), list) or len(result['connections']) > 10000:
        raise ValueError('invalid connection list')
    return result['connections']


def clean(value, limit=160):
    return ''.join(c for c in str(value or '') if c.isprintable())[:limit]


class ProxyConnections:
    """Current active logical connections, lifetime counters; never added to wire bytes."""
    def __init__(self, resolver=None):
        self.resolver = resolver
        self.lock = threading.RLock()
        self.enabled = False
        self.rows = []
        self.wire_identities = {}
        self.updated = 0
        self.error = None
        self.next_poll = 0

    def reset(self):
        with self.lock:
            self.rows, self.updated, self.error = [], 0, None
            self.wire_identities = {}
        self.next_poll = 0

    def refresh(self):
        if not self.enabled or time.monotonic() < self.next_poll:
            return
        self.next_poll = time.monotonic() + 2
        try:
            settings = discover()
            if settings is None:
                raise ValueError('controller unavailable')
            self.update(fetch(settings))
        except Exception as exc:
            with self.lock:
                self.error = '原始应用识别未连接：本地代理接口不可用（' + type(exc).__name__ + '）'
            self.next_poll = time.monotonic() + 10

    def update(self, connections, now=None):
        from .connections import address
        from .applications import observation
        from datetime import datetime
        now = time.time() if now is None else now
        rows, identities = [], {}
        for item in connections:
            try:
                m = item['metadata']
                app = clean(ntpath.basename(m.get('processPath') or m.get('process') or '')) or '原始应用未识别'
                owner = self.resolver.identify_proxy(m, item.get('start', ''), now) if self.resolver and app == '原始应用未识别' else None
                if owner:
                    app = owner['app']
                up, down = int(item['upload']), int(item['download'])
                sport, dport = int(m['sourcePort']), int(m['destinationPort'])
                if min(up, down) < 0 or not 0 <= sport <= 65535 or not 0 <= dport <= 65535:
                    continue
                src = address(m['sourceIP'])
                # Domain-routed connections may have no destination IP; never invent one.
                dst = address(m['destinationIP']) if m.get('destinationIP') else ''
                if app != '原始应用未识别' and m.get('network', '').lower() == 'tcp':
                    try:
                        inbound = (address(m['inboundIP']), int(m['inboundPort']))
                        started_at = datetime.fromisoformat(item['start'].replace('Z', '+00:00')).timestamp()
                        if inbound[0] not in ('0.0.0.0', '::') and 0 < inbound[1] <= 65535:
                            key = tuple(sorted(((src, sport), inbound)))
                            identity = observation(owner or {'app': app, 'sampled_at': now}, (src, sport),
                                role='proxy_original', basis='proxy_inbound_exact_socket' if owner else 'proxy_reported_inbound_socket',
                                confidence='inferred')
                            identity['connection_started'] = started_at
                            identities.setdefault(key, []).append(identity)
                    except (KeyError, ValueError, TypeError, OverflowError):
                        pass
                rows.append(dict(id=clean(item['id']), app=app, protocol=clean(m['network']).upper(),
                    local_ip=src, local_port=sport, remote_ip=dst, remote_port=dport,
                    destination=clean(m.get('host')) or dst or '目标地址未知',
                    direction_known=True, local_connection=False, bytes=up+down, upload=up, download=down,
                    packets=None, syn=None, rst=None, first=now, last=now, start=clean(item.get('start')),
                    owners=[{**owner, 'bytes': up+down}] if owner else [], unknown_bytes=up+down if app == '原始应用未识别' else 0,
                    ownership_ratio=0 if app == '原始应用未识别' else 1,
                    recent=True, alerts=[], anomaly=False, source='live', proxy=True,
                    basis=(owner['basis'] if owner else 'Mihomo报告的进程名' if app != '原始应用未识别' else '代理未报告进程且本地快照无法匹配') + '；活动连接自建立以来累计，不含代理隧道开销'))
            except (KeyError, ValueError, TypeError):
                continue
        rows.sort(key=lambda c: (-c['bytes'], c['id']))
        with self.lock:
            self.rows, self.updated, self.error = rows, now, None
            self.wire_identities = identities

    def identify_wire(self, row):
        """No endpoint/port-only or exit-node fallback; ambiguous mappings stay unknown."""
        if row['protocol'] != 'TCP':
            return []
        key = tuple(sorted(((row['src'], row['sport']), (row['dst'], row['dport']))))
        stamp = row.get('timestamp', time.time())
        with self.lock:
            if not self.enabled or self.error or abs(stamp-self.updated) > 2:
                return []
            matches = self.wire_identities.get(key, [])
            if len(matches) != 1:
                return []
            identity = matches[0]
            if stamp < identity['connection_started'] or abs(stamp-identity['sampled_at']) > 2:
                return []
            return [dict(identity)]

    def snapshot(self):
        with self.lock:
            if not self.enabled or not self.updated or self.error or time.time()-self.updated > 8:
                return None
            rows = [dict(c) for c in self.rows]
        return dict(connections=rows, count=len(rows), bytes=sum(c['bytes'] for c in rows),
            upload=sum(c['upload'] for c in rows), download=sum(c['download'] for c in rows),
            alerts=0, local_bytes=0, unknown_direction_bytes=0, source='live', error=None, proxy=True,
            scope='本机Mihomo活动连接自建立以来累计；只含经过代理核心的应用，与网卡近5分钟抓包分别计量；无逐包异常检测')
