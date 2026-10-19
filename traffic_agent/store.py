"""Minute-bucket directional flows. No payload, DNS names or HTTP contents."""
from collections import defaultdict, deque
import csv
import hashlib
import hmac
import ipaddress
import math
import secrets
import sqlite3
import threading
import time
import uuid

from .anomaly import assess_connection, assess_session_records
from .baseline import Baseline, numeric_comparison, similar_connections
from .applications import PROXY_APPS, storage_values
from .connection_instances import stable_id, uncertainty_names
from .migrations import prepare_backup, migrate


class Store:
    def __init__(self, path="data/traffic.db", max_rows=100000, recover_running=True):
        from pathlib import Path
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        self.max_rows = max_rows
        try:
            self.migration_backup = prepare_backup(self.db, path)
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('BEGIN IMMEDIATE')
            schema = """
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS flows(
              id INTEGER PRIMARY KEY, bucket INTEGER, source TEXT, src TEXT, dst TEXT,
              protocol TEXT, sport INTEGER, dport INTEGER, bytes INTEGER, packets INTEGER,
              records INTEGER, syn INTEGER, rst INTEGER, first REAL, last REAL,
              duration REAL, UNIQUE(bucket,source,src,dst,protocol,sport,dport));
            CREATE INDEX IF NOT EXISTS flows_time ON flows(source,bucket);
            CREATE TABLE IF NOT EXISTS capture_sessions(
              id TEXT PRIMARY KEY, interface TEXT NOT NULL, started REAL NOT NULL,
              stopped REAL, state TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS session_flows(
              id INTEGER PRIMARY KEY, session_id TEXT NOT NULL, bucket INTEGER NOT NULL,
              src TEXT NOT NULL, dst TEXT NOT NULL, protocol TEXT NOT NULL,
              sport INTEGER NOT NULL, dport INTEGER NOT NULL, bytes INTEGER NOT NULL,
              packets INTEGER NOT NULL, records INTEGER NOT NULL, syn INTEGER NOT NULL,
              rst INTEGER NOT NULL, first REAL NOT NULL, last REAL NOT NULL,
              UNIQUE(session_id,bucket,src,dst,protocol,sport,dport));
            CREATE INDEX IF NOT EXISTS session_flows_lookup ON session_flows(session_id,bucket);
            CREATE INDEX IF NOT EXISTS session_flows_endpoints ON session_flows(session_id,src,dst,protocol,sport,dport);
            CREATE INDEX IF NOT EXISTS session_flows_global_key ON session_flows(bucket,src,dst,protocol,sport,dport);
            CREATE TABLE IF NOT EXISTS session_connection_metrics(
              session_id TEXT NOT NULL, a TEXT NOT NULL, ap INTEGER NOT NULL,
              b TEXT NOT NULL, bp INTEGER NOT NULL, protocol TEXT NOT NULL,
              a_to_b_packets INTEGER NOT NULL, b_to_a_packets INTEGER NOT NULL,
              a_to_b_bytes INTEGER NOT NULL, b_to_a_bytes INTEGER NOT NULL,
              syn_seen INTEGER NOT NULL, syn_ack_seen INTEGER NOT NULL,
              fin_seen INTEGER NOT NULL, rst_seen INTEGER NOT NULL,
              client_is_a INTEGER, handshake_status TEXT NOT NULL,
              connection_state TEXT NOT NULL, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
              PRIMARY KEY(session_id,a,ap,b,bp,protocol));
            CREATE TABLE IF NOT EXISTS capture_reports(
              session_id TEXT PRIMARY KEY, created REAL NOT NULL, answer TEXT NOT NULL,
              citation_valid INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS session_applications(
              session_id TEXT NOT NULL,a TEXT NOT NULL,ap INTEGER NOT NULL,b TEXT NOT NULL,bp INTEGER NOT NULL,
              protocol TEXT NOT NULL,bucket INTEGER NOT NULL,endpoint_ip TEXT NOT NULL,endpoint_port INTEGER NOT NULL,
              role TEXT NOT NULL,pid INTEGER NOT NULL,process_created REAL NOT NULL,app TEXT NOT NULL,
              basis TEXT NOT NULL,confidence TEXT NOT NULL,matched_bytes INTEGER NOT NULL,matched_packets INTEGER NOT NULL,
              first_seen REAL NOT NULL,last_seen REAL NOT NULL,first_sampled REAL NOT NULL,last_sampled REAL NOT NULL,
              PRIMARY KEY(session_id,a,ap,b,bp,protocol,bucket,endpoint_ip,endpoint_port,role,pid,process_created,app,basis,confidence));
            CREATE TABLE IF NOT EXISTS budget(id INTEGER PRIMARY KEY CHECK(id=1),
              calls INTEGER, reserved REAL, reported REAL);
            INSERT OR IGNORE INTO budget VALUES(1,0,0,0);
            """
            for statement in schema.split(';'):
                if statement.strip():
                    self.db.execute(statement)
            columns = {row['name'] for row in self.db.execute('PRAGMA table_info(capture_sessions)')}
            if 'number' not in columns:
                self.db.execute('ALTER TABLE capture_sessions ADD COLUMN number INTEGER')
            if 'filtered' not in columns:
                self.db.execute('ALTER TABLE capture_sessions ADD COLUMN filtered INTEGER NOT NULL DEFAULT 0')
            if 'original_connections' not in columns:
                self.db.execute('ALTER TABLE capture_sessions ADD COLUMN original_connections INTEGER')
            if 'legacy_incomplete' not in columns:
                self.db.execute('ALTER TABLE capture_sessions ADD COLUMN legacy_incomplete INTEGER NOT NULL DEFAULT 0')
                self.db.execute('UPDATE capture_sessions SET legacy_incomplete=1')
            if 'revision' not in columns:
                self.db.execute('ALTER TABLE capture_sessions ADD COLUMN revision INTEGER NOT NULL DEFAULT 0')
            if 'normal_label' not in columns:
                self.db.execute("ALTER TABLE capture_sessions ADD COLUMN normal_label TEXT NOT NULL DEFAULT 'unreviewed'")
            if 'normal_label_at' not in columns:
                self.db.execute('ALTER TABLE capture_sessions ADD COLUMN normal_label_at REAL')
            if 'source_kind' not in columns:
                self.db.execute("ALTER TABLE capture_sessions ADD COLUMN source_kind TEXT NOT NULL DEFAULT 'live'")
            counter = int(self.db.execute("SELECT coalesce(max(number),0) FROM capture_sessions").fetchone()[0])
            for row in self.db.execute('SELECT id FROM capture_sessions WHERE number IS NULL ORDER BY started,id').fetchall():
                counter += 1
                self.db.execute('UPDATE capture_sessions SET number=? WHERE id=?', (counter, row['id']))
            old_counter = self.db.execute("SELECT value FROM meta WHERE key='session_counter'").fetchone()
            counter = max(counter, int(old_counter['value']) if old_counter else 0)
            self.db.execute("INSERT INTO meta(key,value) VALUES('session_counter',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(counter),))
            self.db.execute("INSERT OR IGNORE INTO meta VALUES('salt',?)", (secrets.token_hex(32),))
            migrate(self.db)
            if recover_running:
                self.db.execute("UPDATE capture_sessions SET state='interrupted',stopped=? WHERE state='running'", (time.time(),))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            self.db.close()
            raise
        self.salt = bytes.fromhex(self.db.execute("SELECT value FROM meta WHERE key='salt'").fetchone()[0])
        from .incident_store import IncidentStore
        self.incidents = IncidentStore(self)
        from .jobs import JobStore
        self.jobs = JobStore(self)

    def process_incidents(self, session_id):
        return self.incidents.process_session(session_id)

    def alias(self, ip):
        value = str(ipaddress.ip_address(ip))
        return "host_" + hmac.new(self.salt, value.encode(), hashlib.sha256).hexdigest()[:16]

    def add(self, rows):
        values = []
        session_values = []
        connection_values = []
        application_values = []
        for original in rows:
            r = dict(original)
            t = float(r.get("timestamp", time.time()))
            duration = float(r.get("duration", 0))
            if not math.isfinite(t) or not math.isfinite(duration) or t < 0 or duration < 0:
                raise ValueError("无效时间")
            if r["source"] not in {"live", "csv", "simulation"}:
                raise ValueError("无效来源")
            src, dst = str(ipaddress.ip_address(r["src"])), str(ipaddress.ip_address(r["dst"]))
            sport, dport = int(r.get("sport", 0)), int(r.get("dport", 0))
            size, packets = int(r["bytes"]), int(r.get("packets", 1))
            if not (0 <= sport <= 65535 and 0 <= dport <= 65535 and 0 <= size <= 10**12 and 0 <= packets <= 10**9):
                raise ValueError("无效端口或计数")
            protocol = r["protocol"]
            if protocol not in {"TCP", "UDP", "ICMP", "ICMPv6", "OTHER"}:
                raise ValueError("无效协议")
            values.append((int(t // 60) * 60, r["source"], src, dst, protocol, sport, dport,
                           size, packets, 1, int(r.get("syn", 0)), int(r.get("rst", 0)), t, t, duration))
            if r["source"] == "live" and r.get("session_id"):
                a, b = sorted(((src, sport), (dst, dport)))
                r['connection_id'] = r.get('connection_id') or stable_id(r['session_id'], (*a, *b, protocol), 'untracked')
                session_values.append((r["session_id"], int(t // 60) * 60, src, dst, protocol,
                                       sport, dport, size, packets, 1, int(r.get("syn", 0)),
                                       int(r.get("rst", 0)), t, t, r['connection_id']))
                left, right = (src, sport), (dst, dport)
                a, b = sorted((left, right))
                forward = left == a
                application_values.extend(storage_values(r, (a[0], a[1], b[0], b[1], protocol), t, size, packets))
                connection_values.append((r['session_id'], a[0], a[1], b[0], b[1], protocol,
                                          packets if forward else 0, 0 if forward else packets,
                                          size if forward else 0, 0 if forward else size,
                                          int(bool(r.get('syn'))), int(bool(r.get('syn_ack'))),
                                          int(bool(r.get('fin'))), int(bool(r.get('rst'))),
                                          r.get('client_is_a'), r.get('handshake_status', 'NOT_OBSERVED'),
                                          r.get('connection_state', 'UNKNOWN'), t, t, r['connection_id'],
                                          r.get('instance_kind', 'untracked_aggregate'),
                                          r.get('boundary_reason', 'metadata_without_tracker'),
                                          r.get('uncertainty_flags', 512), r.get('handshake_basis', 'not_observed')))
        with self.lock, self.db:
            self.db.executemany("""INSERT INTO flows(bucket,source,src,dst,protocol,sport,dport,
              bytes,packets,records,syn,rst,first,last,duration) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
              ON CONFLICT(bucket,source,src,dst,protocol,sport,dport) DO UPDATE SET
              bytes=bytes+excluded.bytes, packets=packets+excluded.packets,
              records=records+excluded.records,syn=syn+excluded.syn,rst=rst+excluded.rst,
              first=min(first,excluded.first),last=max(last,excluded.last),duration=duration+excluded.duration""", values)
            if session_values:
                self.db.executemany("UPDATE capture_sessions SET normal_label='unreviewed',normal_label_at=NULL WHERE id=?",
                                    [(sid,) for sid in {r[0] for r in session_values}])
                self.db.executemany("""INSERT INTO session_flows(session_id,bucket,src,dst,protocol,sport,dport,
                  bytes,packets,records,syn,rst,first,last,connection_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                  ON CONFLICT(session_id,bucket,src,dst,protocol,sport,dport,connection_id) DO UPDATE SET
                  bytes=bytes+excluded.bytes,packets=packets+excluded.packets,
                  records=records+excluded.records,syn=syn+excluded.syn,rst=rst+excluded.rst,
                  first=min(first,excluded.first),last=max(last,excluded.last)""", session_values)
                self.db.executemany("""INSERT INTO session_connection_metrics VALUES(
                  ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                  ON CONFLICT(session_id,a,ap,b,bp,protocol,connection_id) DO UPDATE SET
                  a_to_b_packets=a_to_b_packets+excluded.a_to_b_packets,
                  b_to_a_packets=b_to_a_packets+excluded.b_to_a_packets,
                  a_to_b_bytes=a_to_b_bytes+excluded.a_to_b_bytes,
                  b_to_a_bytes=b_to_a_bytes+excluded.b_to_a_bytes,
                  syn_seen=max(syn_seen,excluded.syn_seen),
                  syn_ack_seen=max(syn_ack_seen,excluded.syn_ack_seen),
                  fin_seen=max(fin_seen,excluded.fin_seen),rst_seen=max(rst_seen,excluded.rst_seen),
                  client_is_a=coalesce(client_is_a,excluded.client_is_a),
                  handshake_status=CASE WHEN excluded.handshake_status='NOT_OBSERVED' OR
                    (excluded.handshake_status='UNKNOWN' AND handshake_status='CONFIRMED')
                    THEN handshake_status ELSE excluded.handshake_status END,
                  connection_state=CASE WHEN excluded.connection_state='UNKNOWN'
                    THEN connection_state ELSE excluded.connection_state END,
                  first_seen=min(first_seen,excluded.first_seen),last_seen=max(last_seen,excluded.last_seen),
                  uncertainty_flags=uncertainty_flags | excluded.uncertainty_flags,
                  handshake_basis=CASE WHEN excluded.handshake_basis='not_observed' THEN handshake_basis ELSE excluded.handshake_basis END""",
                  connection_values)
                self.db.executemany("""INSERT INTO session_applications VALUES(
                  ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                  ON CONFLICT(session_id,a,ap,b,bp,protocol,bucket,endpoint_ip,endpoint_port,role,pid,process_created,app,basis,confidence,connection_id)
                  DO UPDATE SET matched_bytes=matched_bytes+excluded.matched_bytes,
                  matched_packets=matched_packets+excluded.matched_packets,
                  first_seen=min(first_seen,excluded.first_seen),last_seen=max(last_seen,excluded.last_seen),
                  first_sampled=min(first_sampled,excluded.first_sampled),last_sampled=max(last_sampled,excluded.last_sampled)""",
                  application_values)

    def start_session(self, interface):
        session_id = uuid.uuid4().hex
        with self.lock, self.db:
            count = self.db.execute('SELECT count(*) FROM capture_sessions').fetchone()[0]
            if count >= 10:
                raise ValueError('已保存 10 次采集；请到“采集记录”删除不需要的记录后再开始')
            number = int(self.db.execute("SELECT value FROM meta WHERE key='session_counter'").fetchone()[0]) + 1
            self.db.execute("UPDATE meta SET value=? WHERE key='session_counter'", (str(number),))
            self.db.execute("""INSERT INTO capture_sessions(id,interface,started,stopped,state,number)
              VALUES(?,?,?,NULL,'running',?)""", (session_id, str(interface), time.time(), number))
        return session_id

    def end_session(self, session_id, state='stopped'):
        with self.lock, self.db:
            self.db.execute("UPDATE capture_sessions SET stopped=?,state=? WHERE id=? AND state='running'",
                            (time.time(), state, session_id))

    def latest_session(self):
        with self.lock:
            row = self.db.execute("SELECT * FROM capture_sessions ORDER BY number DESC LIMIT 1").fetchone()
        return dict(row) if row else None

    def list_sessions(self):
        with self.lock:
            return [dict(row) for row in self.db.execute("""SELECT s.*,
              coalesce((SELECT sum(bytes) FROM session_flows WHERE session_id=s.id),0) bytes,
              coalesce((SELECT sum(packets) FROM session_flows WHERE session_id=s.id),0) packets,
              (SELECT count(*) FROM session_flows WHERE session_id=s.id) flow_buckets,
              (SELECT count(*) FROM capture_reports WHERE session_id=s.id) reports
              FROM capture_sessions s ORDER BY number DESC""")]

    @staticmethod
    def _canonical_sql():
        forward = '(src<dst OR (src=dst AND sport<=dport))'
        return (f'CASE WHEN {forward} THEN src ELSE dst END',
                f'CASE WHEN {forward} THEN sport ELSE dport END',
                f'CASE WHEN {forward} THEN dst ELSE src END',
                f'CASE WHEN {forward} THEN dport ELSE sport END')

    def _instance_key(self, session_id, key, connection_id=None):
        key = tuple(key)
        if len(key) == 6:
            connection_id, key = key[5], key[:5]
        a, ap, b, bp, protocol = key
        with self.lock:
            ids = [r[0] for r in self.db.execute("""SELECT DISTINCT connection_id FROM session_flows
                WHERE session_id=? AND protocol=? AND
                ((src=? AND sport=? AND dst=? AND dport=?) OR (src=? AND sport=? AND dst=? AND dport=?))
                ORDER BY connection_id""", (session_id, protocol, a, ap, b, bp, b, bp, a, ap))]
        if connection_id is not None:
            if connection_id not in ids:
                raise ValueError('connection_id不属于当前采集或指定五元组')
        elif len(ids) > 1:
            raise ValueError('该五元组有多个连接实例；请从session_connection_history选择connection_id：' + ','.join(ids[:3]))
        else:
            connection_id = ids[0] if ids else ''
        return (*key, connection_id)

    def _connection_metric(self, session_id, key):
        """Return observed bidirectional evidence; old databases remain explicitly uncertain."""
        key = self._instance_key(session_id, key)
        a, ap, b, bp, protocol, connection_id = key
        with self.lock:
            row = self.db.execute("""SELECT * FROM session_connection_metrics WHERE
              session_id=? AND a=? AND ap=? AND b=? AND bp=? AND protocol=? AND connection_id=?""", (session_id, *key)).fetchone()
            if row:
                metric = dict(row)
            else:
                metric = dict(self.db.execute("""SELECT
                  coalesce(sum(CASE WHEN src=? AND sport=? THEN packets ELSE 0 END),0) a_to_b_packets,
                  coalesce(sum(CASE WHEN src=? AND sport=? THEN 0 ELSE packets END),0) b_to_a_packets,
                  coalesce(sum(CASE WHEN src=? AND sport=? THEN bytes ELSE 0 END),0) a_to_b_bytes,
                  coalesce(sum(CASE WHEN src=? AND sport=? THEN 0 ELSE bytes END),0) b_to_a_bytes,
                  min(first) first_seen,max(last) last_seen FROM session_flows WHERE
                  session_id=? AND protocol=? AND connection_id=? AND
                  ((src=? AND sport=? AND dst=? AND dport=?) OR
                   (src=? AND sport=? AND dst=? AND dport=?))""",
                  (a, ap, a, ap, a, ap, a, ap, session_id, protocol, connection_id,
                   a, ap, b, bp, b, bp, a, ap)).fetchone())
                metric.update(syn_seen=None, syn_ack_seen=None, fin_seen=None, rst_seen=None,
                              client_is_a=None, handshake_status='NOT_OBSERVED', connection_state='UNKNOWN',
                              instance_kind='legacy_aggregate', boundary_reason='missing_metrics', uncertainty_flags=256, handshake_basis='not_observed')
        duration = max(0.0, metric['last_seen']-metric['first_seen']) if metric['first_seen'] is not None else None
        known_client = metric['client_is_a'] is not None and protocol == 'TCP'
        outgoing = 'a_to_b' if metric['client_is_a'] else 'b_to_a'
        incoming = 'b_to_a' if metric['client_is_a'] else 'a_to_b'
        confirmed = metric['handshake_status'] == 'CONFIRMED'
        result = {'connection_id': connection_id, 'instance_kind': metric['instance_kind'],
                'boundary_reason': metric['boundary_reason'], 'uncertainties': uncertainty_names(metric['uncertainty_flags']),
                'handshake_basis': metric['handshake_basis'],
                'observation_notice': ('聚合记录不能恢复为精确连接实例；原有握手标记可能合并了多次连接，不可作为单次连接成功证据'
                    if metric['instance_kind'] in ('legacy_aggregate', 'untracked_aggregate') else
                    '连接实例是抓包观察划分；CONFIRMED表示观察到匹配握手，不保证端点收到报文或应用连接成功'),
                'source_ip': self.alias(a if not known_client or metric['client_is_a'] else b),
                'source_port': ap if not known_client or metric['client_is_a'] else bp,
                'destination_ip': self.alias(b if not known_client or metric['client_is_a'] else a),
                'destination_port': bp if not known_client or metric['client_is_a'] else ap,
                'direction_basis': 'observed_syn_initiator' if known_client else 'canonical_endpoints_only',
                'protocol': protocol,
                'a_to_b_packets': metric['a_to_b_packets'], 'b_to_a_packets': metric['b_to_a_packets'],
                'a_to_b_bytes': metric['a_to_b_bytes'], 'b_to_a_bytes': metric['b_to_a_bytes'],
                'client_to_server_packets': metric[outgoing+'_packets'] if known_client else None,
                'server_to_client_packets': metric[incoming+'_packets'] if known_client else None,
                'client_to_server_bytes': metric[outgoing+'_bytes'] if known_client else None,
                'server_to_client_bytes': metric[incoming+'_bytes'] if known_client else None,
                'packets': metric['a_to_b_packets']+metric['b_to_a_packets'],
                'bytes': metric['a_to_b_bytes']+metric['b_to_a_bytes'],
                'syn_seen': metric['syn_seen'], 'syn_ack_seen': metric['syn_ack_seen'],
                'fin_seen': metric['fin_seen'], 'rst_seen': metric['rst_seen'],
                'first_seen': metric['first_seen'], 'last_seen': metric['last_seen'],
                'duration': duration,
                'packets_per_second': round((metric['a_to_b_packets']+metric['b_to_a_packets'])/duration, 3) if duration else None,
                'bytes_per_second': round((metric['a_to_b_bytes']+metric['b_to_a_bytes'])/duration, 3) if duration else None,
                'short_connection_flag': bool(duration <= 3 and metric['connection_state'] == 'CLOSED') if confirmed and duration is not None else None,
                'handshake_status': metric['handshake_status'], 'connection_state': metric['connection_state'],
                'tcp_state': metric['connection_state'] if protocol == 'TCP' else 'NOT_APPLICABLE'}
        result['assessment'] = assess_connection(result)
        return result

    def session_connections(self, session_id, search='', page=1, page_size=50):
        self._session(session_id)
        if page < 1 or page_size < 1 or page_size > 100:
            raise ValueError('无效页码')
        a, ap, b, bp = self._canonical_sql()
        query = f"""WITH normalized AS (SELECT {a} a,{ap} ap,{b} b,{bp} bp,
          protocol,connection_id,bytes,packets,syn,rst FROM session_flows WHERE session_id=?),
          grouped AS (SELECT a,ap,b,bp,protocol,connection_id,sum(bytes) bytes,sum(packets) packets,
          sum(syn) syn,sum(rst) rst FROM normalized GROUP BY a,ap,b,bp,protocol,connection_id)
          SELECT * FROM grouped"""
        term = search.strip()[:100]
        params = [session_id]
        if term:
            query += ' WHERE a LIKE ? OR b LIKE ? OR protocol LIKE ? OR CAST(ap AS TEXT) LIKE ? OR CAST(bp AS TEXT) LIKE ?'
            params += [f'%{term}%'] * 5
        with self.lock:
            rows = [dict(row) for row in self.db.execute(query + ' ORDER BY bytes DESC,a,ap,b,bp,connection_id LIMIT ? OFFSET ?',
                                                       (*params, page_size, (page-1)*page_size))]
            total = self.db.execute('SELECT count(*) FROM (' + query + ')', params).fetchone()[0]
        for row in rows:
            row['key'] = (row['a'], row['ap'], row['b'], row['bp'], row['protocol'], row['connection_id'])
            row['metrics'] = self._connection_metric(session_id, row['key'])
            row['application_identity'] = self._application_identity(session_id, row['key'])
        return {'session_id': session_id, 'page': page, 'page_size': page_size, 'total': total,
                'pages': max(1, math.ceil(total/page_size)), 'connections': rows}

    def _subtract_live(self, rows):
        # Both tables received the same live contribution when a packet was
        # captured. Subtract only that session's contribution; preserve data
        # belonging to another capture in the same minute.
        self.db.executemany("""UPDATE flows SET bytes=max(0,bytes-?),packets=max(0,packets-?),
          records=max(0,records-?),syn=max(0,syn-?),rst=max(0,rst-?)
          WHERE source='live' AND bucket=? AND src=? AND dst=? AND protocol=? AND sport=? AND dport=?""",
          [(r['bytes'],r['packets'],r['records'],r['syn'],r['rst'],r['bucket'],r['src'],r['dst'],
            r['protocol'],r['sport'],r['dport']) for r in rows])
        self.db.execute("DELETE FROM flows WHERE source='live' AND bytes=0 AND packets=0 AND records=0")

    def _refresh_live_times(self, rows):
        keys = {(r['bucket'], r['src'], r['dst'], r['protocol'], r['sport'], r['dport']) for r in rows}
        for key in keys:
            times = self.db.execute("""SELECT min(first) first,max(last) last FROM session_flows
              WHERE bucket=? AND src=? AND dst=? AND protocol=? AND sport=? AND dport=?""", key).fetchone()
            if times['first'] is not None:
                self.db.execute("""UPDATE flows SET first=?,last=? WHERE source='live' AND
                  bucket=? AND src=? AND dst=? AND protocol=? AND sport=? AND dport=?""",
                  (times['first'], times['last'], *key))

    def retain_session_connections(self, session_id, keys):
        session = self._session(session_id)
        if session['state'] == 'running':
            raise ValueError('请先停止采集再筛选保存')
        ids = {self._instance_key(session_id, key)[5] for key in keys}
        if not ids or '' in ids:
            raise ValueError('至少选择一条存在的连接实例')
        with self.lock, self.db:
            self.db.execute('CREATE TEMP TABLE IF NOT EXISTS selected_instances(connection_id TEXT PRIMARY KEY) WITHOUT ROWID')
            self.db.execute('DELETE FROM selected_instances')
            self.db.executemany('INSERT INTO selected_instances VALUES(?)', [(cid,) for cid in ids])
            all_count = self.db.execute('SELECT count(DISTINCT connection_id) FROM session_flows WHERE session_id=?', (session_id,)).fetchone()[0]
            matching = len(ids)
            if matching == all_count:
                self.db.execute('DELETE FROM selected_instances')
                return {'kept': matching, 'deleted': 0, 'removed_flow_buckets': 0, 'changed': False}
            predicate = 'connection_id NOT IN (SELECT connection_id FROM selected_instances)'
            removed = [dict(row) for row in self.db.execute(
                f'SELECT * FROM session_flows WHERE session_id=? AND {predicate}', (session_id,))]
            self._subtract_live(removed)
            self.incidents.invalidate_session(session_id)
            for table in ('session_flows', 'session_connection_metrics', 'session_applications'):
                self.db.execute(f'DELETE FROM {table} WHERE session_id=? AND {predicate}', (session_id,))
            self._refresh_live_times(removed)
            self.db.execute('DELETE FROM capture_reports WHERE session_id=?', (session_id,))
            self.db.execute("""UPDATE capture_sessions SET filtered=1,revision=revision+1,
              normal_label='unreviewed',normal_label_at=NULL,
              original_connections=coalesce(original_connections,?) WHERE id=?""", (all_count, session_id))
            self.db.execute('DELETE FROM selected_instances')
        return {'kept': matching, 'deleted': all_count-matching, 'removed_flow_buckets': len(removed), 'changed': True}

    def delete_session(self, session_id):
        session = self._session(session_id)
        if session['state'] == 'running':
            raise ValueError('请先停止采集再删除')
        with self.lock, self.db:
            rows = [dict(row) for row in self.db.execute('SELECT * FROM session_flows WHERE session_id=?', (session_id,))]
            self._subtract_live(rows)
            self.incidents.invalidate_session(session_id)
            self.db.execute('DELETE FROM session_flows WHERE session_id=?', (session_id,))
            self.db.execute('DELETE FROM session_connection_metrics WHERE session_id=?', (session_id,))
            self.db.execute('DELETE FROM session_applications WHERE session_id=?', (session_id,))
            self._refresh_live_times(rows)
            self.db.execute('DELETE FROM capture_reports WHERE session_id=?', (session_id,))
            self.db.execute('DELETE FROM capture_sessions WHERE id=?', (session_id,))
        return {'number': session['number'], 'removed_flow_buckets': len(rows)}

    def save_session_report(self, session_id, answer, citation_valid, expected_revision=None):
        answer = str(answer)
        if len(answer) > 200000:
            return False
        with self.lock, self.db:
            row = self.db.execute('SELECT revision FROM capture_sessions WHERE id=?', (session_id,)).fetchone()
            if not row or (expected_revision is not None and row['revision'] != expected_revision):
                return False
            self.db.execute("""INSERT INTO capture_reports VALUES(?,?,?,?)
              ON CONFLICT(session_id) DO UPDATE SET created=excluded.created,
              answer=excluded.answer,citation_valid=excluded.citation_valid""",
              (session_id, time.time(), answer, int(bool(citation_valid))))
        return True

    def session_report(self, session_id):
        with self.lock:
            row = self.db.execute("SELECT * FROM capture_reports WHERE session_id=?", (session_id,)).fetchone()
        return dict(row) if row else None

    def _session(self, session_id):
        with self.lock:
            row = self.db.execute("SELECT * FROM capture_sessions WHERE id=?", (session_id,)).fetchone()
        if not row:
            raise ValueError("采集会话不存在")
        return dict(row)

    def _alias_assessment(self, assessment):
        candidates = assessment.get('candidate_pairs_all', assessment['candidate_pairs_first_20'])
        for item in candidates + assessment['watch_connections_first_20']:
            item['src'], item['dst'] = self.alias(item['src']), self.alias(item['dst'])
        return assessment

    def set_session_normal(self, session_id, normal=True):
        """Local human labeling only; deliberately not exposed as an Agent tool."""
        with self.lock, self.db:
            session = self._session(session_id)
            if normal:
                if (session['state'] != 'stopped' or session['filtered'] or session['legacy_incomplete'] or
                        session['stopped'] - session['started'] < 60):
                    raise ValueError('正常基线仅接受已停止、未筛选、非旧版且至少60秒的完整采集')
                a, ap, b, bp = self._canonical_sql()
                counts = self.db.execute(f'SELECT count(*) FROM (SELECT {a},{ap},{b},{bp},protocol,connection_id FROM session_flows WHERE session_id=? GROUP BY 1,2,3,4,5,6)', (session_id,)).fetchone()[0]
                metrics = self.db.execute('SELECT count(*) FROM session_connection_metrics WHERE session_id=?', (session_id,)).fetchone()[0]
                if not counts or counts != metrics:
                    raise ValueError('没有完整的连接指标，不能作为正常基线')
            self.db.execute('UPDATE capture_sessions SET normal_label=?,normal_label_at=? WHERE id=?',
                            ('user_confirmed_normal' if normal else 'unreviewed', time.time() if normal else None, session_id))

    def _reference_connection(self, row):
        known = row['client_is_a'] is not None and row['protocol'] == 'TCP'
        forward = not known or bool(row['client_is_a'])
        return {'connection_id': row['connection_id'], 'instance_kind': row['instance_kind'],
                'boundary_reason': row['boundary_reason'], 'uncertainties': uncertainty_names(row['uncertainty_flags']),
                'handshake_basis': row['handshake_basis'],
                'source_ip': self.alias(row['a'] if forward else row['b']),
                'source_port': row['ap'] if forward else row['bp'],
                'destination_ip': self.alias(row['b'] if forward else row['a']),
                'destination_port': row['bp'] if forward else row['ap'],
                'direction_basis': 'observed_syn_initiator' if known else 'canonical_endpoints_only',
                'protocol': row['protocol'], 'packets': row['a_to_b_packets'] + row['b_to_a_packets'],
                'bytes': row['a_to_b_bytes'] + row['b_to_a_bytes'],
                'duration': max(0, row['last_seen'] - row['first_seen']),
                'first_seen': row['first_seen'], 'last_seen': row['last_seen'],
                'handshake_status': row['handshake_status'], 'connection_state': row['connection_state']}

    def _historical_profiles(self, session_id):
        current = self._session(session_id)
        # Enforce temporal separation and capture scope, not merely a different id.
        sessions = self.db.execute("""SELECT * FROM capture_sessions WHERE number<? AND stopped<=?
            AND interface=? AND state='stopped' AND filtered=0 AND legacy_incomplete=0
            AND stopped-started>=60 ORDER BY number""",
            (current['number'], current['started'], current['interface'])).fetchall()
        profiles = []
        current_units = {r[0] for r in self.db.execute('SELECT DISTINCT instance_kind FROM session_connection_metrics WHERE session_id=?', (session_id,))}
        a, ap, b, bp = self._canonical_sql()
        for session in sessions:
            if session['source_kind'] != current['source_kind']:
                continue
            rows = self.db.execute('SELECT * FROM session_connection_metrics WHERE session_id=?', (session['id'],)).fetchall()
            total = self.db.execute(f'SELECT count(*) FROM (SELECT {a},{ap},{b},{bp},protocol,connection_id FROM session_flows WHERE session_id=? GROUP BY 1,2,3,4,5,6)', (session['id'],)).fetchone()[0]
            if rows and len(rows) == total and {r['instance_kind'] for r in rows} == current_units:
                profiles.append({'number': session['number'], 'normal_label': session['normal_label'],
                                 'seconds': session['stopped'] - session['started'],
                                 'connections': [self._reference_connection(row) for row in rows]})
        return profiles

    def _queried_connection(self, session_id, src, dst, protocol, sport, dport, connection_id=None):
        history = self.session_connection_history(session_id, src, dst, protocol, sport, dport, connection_id=connection_id)
        if history['connection_metrics_total'] > 1:
            raise ValueError('该五元组有多个连接实例；请先查询session_connection_history并指定connection_id')
        if len(history['connection_metrics']) != 1:
            raise ValueError('当前采集中没有该双向五元组')
        return history['connection_metrics'][0]

    def _application_identity(self, session_id, key, page=1):
        if type(page) is not int or page < 1:
            raise ValueError('无效页码')
        key = self._instance_key(session_id, key)
        where = 'session_id=? AND a=? AND ap=? AND b=? AND bp=? AND protocol=? AND connection_id=?'
        params = (session_id, *key)
        grouped = f"""SELECT endpoint_ip,endpoint_port,role,pid,process_created,app,basis,confidence,
          sum(matched_bytes) matched_bytes,sum(matched_packets) matched_packets,
          min(first_seen) first_seen,max(last_seen) last_seen,
          min(first_sampled) first_sampled,max(last_sampled) last_sampled
          FROM session_applications WHERE {where}
          GROUP BY endpoint_ip,endpoint_port,role,pid,process_created,app,basis,confidence"""
        with self.lock:
            rows = [dict(r) for r in self.db.execute(grouped +
                ' ORDER BY endpoint_ip,endpoint_port,role,first_seen,pid,process_created,app,basis,confidence LIMIT 20 OFFSET ?',
                (*params, (page-1)*20))]
            total = self.db.execute('SELECT count(*) FROM (' + grouped + ')', params).fetchone()[0]
            # Group by process lifetime as well as PID; a recycled PID is a new identity.
            owners = [dict(r) for r in self.db.execute(f"""SELECT endpoint_ip,endpoint_port,pid,process_created,app,
              sum(matched_packets) packets,min(confidence) confidence FROM session_applications WHERE {where} AND role='socket_owner'
              GROUP BY endpoint_ip,endpoint_port,pid,process_created,app""", params)]
            counters = self.db.execute(f"""SELECT a_to_b_packets+b_to_a_packets packets
              FROM session_connection_metrics WHERE {where}""", params).fetchone()
        packets = counters['packets'] if counters else 0
        endpoints = []
        for ip, port in ((key[0], key[1]), (key[2], key[3])):
            matches = [r for r in owners if (r['endpoint_ip'], r['endpoint_port']) == (ip, port)]
            matched = sum(r['packets'] for r in matches)
            endpoints.append({'host': self.alias(ip), 'port': port, 'process_identities': len(matches),
                'matched_packets': matched, 'total_connection_packets': packets,
                'matched_packet_ratio': round(matched/packets, 4) if packets else None,
                'status': 'multiple_identities' if len(matches) > 1 else 'partial' if matches and matched < packets else
                          'inferred' if any(r['confidence'] == 'inferred' for r in matches) else 'snapshot_match' if matches else 'unknown'})
        for row in rows:
            row['endpoint_host'] = self.alias(row.pop('endpoint_ip'))
            row['pid'] = None if row['pid'] == -1 else row['pid']
            row['process_created'] = None if row['process_created'] == -1 else row['process_created']
            row['proxy_process'] = row['app'].casefold() in PROXY_APPS
        statuses = {e['status'] for e in endpoints}
        status = ('multiple_identities' if 'multiple_identities' in statuses else
                  'partial' if 'partial' in statuses else 'snapshot_match' if 'snapshot_match' in statuses else 'inferred' if total else 'unknown')
        return {'connection_id': key[5], 'status': status, 'endpoints': endpoints, 'observations': rows,
                'total_observations': total, 'page': page, 'pages': max(1, math.ceil(total/20)),
                'scope': '采集当时保存的本地应用匹配；此处的first_seen/last_seen仅表示匹配到身份的流量范围，不是进程或完整连接寿命',
                'limitations': [
                    'snapshot_match仅确认连接表快照唯一匹配，不是逐包进程归属或可信软件证明',
                    'UDP端口匹配及代理报告均为推测关联；未知可能由短连接、权限、过期快照或旧数据导致，不能用现在的进程补全',
                    'proxy_original只关联精确的应用到代理入站五元组；代理出口可能承载多个应用，不能反推原始应用',
                    '同一连接两端、socket_owner与proxy_original可能描述相同流量，matched_bytes/packets不可相加当作总流量']}

    def query_application_identity(self, session_id, src, dst, protocol, sport, dport, page=1, connection_id=None):
        self._session(session_id)
        ip1, ip2 = self._session_endpoints(session_id, src, dst)
        a, b = sorted(((ip1, sport), (ip2, dport)))
        key = self._instance_key(session_id, (a[0], a[1], b[0], b[1], protocol), connection_id)
        if self._connection_metric(session_id, key)['first_seen'] is None:
            raise ValueError('当前采集中没有该双向五元组')
        return {'session_id': session_id, 'protocol': protocol, **self._application_identity(session_id, key, page)}

    def _session_endpoints(self, session_id, src, dst):
        with self.lock:
            ips = {r[0] for r in self.db.execute('SELECT src FROM session_flows WHERE session_id=? UNION SELECT dst FROM session_flows WHERE session_id=?',
                                                (session_id, session_id))}
        lookup = {self.alias(ip): ip for ip in ips}
        if src not in lookup or dst not in lookup:
            raise ValueError('该会话没有对应主机化名')
        return lookup[src], lookup[dst]

    def query_connection_baseline(self, session_id, src, dst, protocol, sport, dport, connection_id=None):
        with self.lock:
            connection = self._queried_connection(session_id, src, dst, protocol, sport, dport, connection_id)
            reference = Baseline(self._historical_profiles(session_id))
            summary = reference.summary()
            session = self._session(session_id)
            count = self.db.execute('SELECT count(*) FROM session_connection_metrics WHERE session_id=?', (session_id,)).fetchone()[0]
            seconds = (session['stopped'] or time.time()) - session['started']
            rate = count * 300 / seconds if seconds >= 60 else None
            comparable = summary['status'] == 'available' and not session['filtered'] and not session['legacy_incomplete']
            return {'connection_id': connection['connection_id'], 'baseline': summary, 'connection_comparison': reference.compare(connection),
                    'connection_quality': {'handshake_status': connection['handshake_status'],
                                           'direction_basis': connection['direction_basis'],
                                           'warning': '历史参考不能补全当前握手或证明本次连接安全'},
                    'capture_comparison': numeric_comparison('connections_per_300_seconds', rate,
                         summary['connections_per_300_seconds'], comparable),
                    'scope': '历史与当前使用相同连接记录类型，旧聚合不混入新实例基线；连接包数和跨度按同协议/已知服务端口比较；连接数量仅在整次采集按观察时长归一化，不是瞬时峰值'}

    def query_similar_sessions(self, session_id, src, dst, protocol, sport, dport, limit=5, connection_id=None):
        if not 1 <= limit <= 10:
            raise ValueError('limit必须在1到10之间')
        with self.lock:
            connection = self._queried_connection(session_id, src, dst, protocol, sport, dport, connection_id)
            profiles = self._historical_profiles(session_id)
            result = similar_connections(connection, profiles, limit)
            result['connection_id'] = connection['connection_id']
            result['historical_capture_count'] = len(profiles)
            result['status'] = 'available' if result['matches'] else 'insufficient_evidence'
            return result

    def query_anomaly_evidence(self, session_id, src, dst, protocol, sport=None, dport=None, connection_id=None):
        with self.lock:
            history = self.session_connection_history(session_id, src, dst, protocol, sport, dport, connection_id=connection_id)
            if not history['connection_metrics']:
                raise ValueError('当前采集中没有匹配连接')
            return {'connection_assessments': [{'connection_id': c['connection_id'], 'source_ip': c['source_ip'], 'source_port': c['source_port'],
                        'destination_ip': c['destination_ip'], 'destination_port': c['destination_port'],
                        'handshake_status': c['handshake_status'], 'assessment': c['assessment']}
                        for c in history['connection_metrics']],
                    'connection_metrics_total': history['connection_metrics_total'],
                    'connection_metrics_pages': history['connection_metrics_pages'],
                    'pair_assessment': history['pair_assessment'],
                    'capture_quality': {k: self._session(session_id)[k] for k in ('state', 'filtered', 'legacy_incomplete')},
                    'scope': '单连接评分与主机对聚集评分分别解释；主机对信号不证明每条连接异常。超过50条请使用session_connection_history翻页',
                    'reliability': '阈值证据可复核，非概率。缺少握手、驱动丢包未知或缺少历史时应保留不确定性'}

    def session_anomaly_assessment(self, session_id, include_all=False):
        """Evaluate persisted connection behavior on demand; never create a security verdict."""
        session = self._session(session_id)
        a, ap, b, bp = self._canonical_sql()
        with self.lock:
            records = [dict(row) for row in self.db.execute(
                'SELECT * FROM session_connection_metrics WHERE session_id=?', (session_id,))]
            total = self.db.execute(f"""SELECT count(*) FROM (SELECT {a},{ap},{b},{bp},protocol,connection_id
              FROM session_flows WHERE session_id=? GROUP BY 1,2,3,4,5,6)""", (session_id,)).fetchone()[0]
        result = self._alias_assessment(assess_session_records(records, include_all=include_all))
        result['total_connections'] = total
        kinds = defaultdict(int)
        for record in records:
            kinds[record['instance_kind']] += 1
        result['connection_record_kinds'] = dict(kinds)
        result['connection_count_basis'] = '观察实例、无法归属的片段及显式聚合记录；不是精确的成功连接次数'
        result['unassessed_legacy_connections'] = max(0, total-len(records))
        result['evaluation_coverage_ratio'] = round(result['evaluated_connections']/total, 4) if total else None
        result['status'] = ('no_data' if not total else
                            'not_applicable' if result['non_tcp_connections'] == total else
                            'insufficient_evidence' if not result['evaluated_connections'] else
                            'partial' if result['evaluated_connections'] < total or session['legacy_incomplete'] else 'assessed')
        result['limitations'] = [
            '候选分数是固定阈值的调查优先级，不是恶意概率或攻击结论',
            '未命中规则不能证明安全；抓包可见范围和驱动层丢包未知',
            '新TCP记录按观察到的连接实例计数；旧聚合、缺包或不确定边界仍可能影响连接次数',
        ]
        if session['filtered']:
            result['limitations'].append('此采集经过筛选，评估只覆盖保留连接')
        if result['unassessed_legacy_connections'] or session['legacy_incomplete']:
            result['limitations'].append('旧数据缺少连接状态或可能被裁剪，不能按新规则完整评估')
        if result['unknown_direction_connections']:
            result['limitations'].append('部分TCP连接未观察到发起端，未参加依赖方向的评估')
        if result['non_tcp_connections']:
            result['limitations'].append('当前连接行为规则仅支持TCP，其他协议未参与评估')
        if session['state'] == 'running':
            result['limitations'].append('采集仍在运行，当前结果会随新流量变化')
        return result

    def session_summary(self, session_id, include_assessment=True):
        """Aggregate every retained minute bucket in the selected capture session."""
        session = self._session(session_id)
        as_of = session['stopped'] if session['stopped'] is not None else time.time()
        duration = max(0, as_of-session['started'])
        bin_width = max(60, math.ceil(duration/120/60)*60)
        with self.lock:
            totals = dict(self.db.execute("""SELECT count(*) flow_buckets,coalesce(sum(bytes),0) bytes,
              coalesce(sum(packets),0) packets,coalesce(sum(syn),0) syn,coalesce(sum(rst),0) rst,
              min(first) first_observed,max(last) last_observed FROM session_flows WHERE session_id=?""", (session_id,)).fetchone())
            protocols = [dict(r) for r in self.db.execute("""SELECT protocol,sum(bytes) bytes,sum(packets) packets
              FROM session_flows WHERE session_id=? GROUP BY protocol ORDER BY bytes DESC""", (session_id,))]
            timeline = [dict(r) for r in self.db.execute("""SELECT (bucket / ?)*? AS bucket,
              sum(bytes) bytes,sum(packets) packets,sum(syn) syn,sum(rst) rst
              FROM session_flows WHERE session_id=? GROUP BY (bucket / ?) ORDER BY bucket""",
              (bin_width, bin_width, session_id, bin_width))]
            top = [dict(r) for r in self.db.execute("""SELECT src,dst,protocol,sport,dport,connection_id,
              sum(bytes) bytes,sum(packets) packets,sum(syn) syn,sum(rst) rst,
              min(first) first,max(last) last FROM session_flows WHERE session_id=?
              GROUP BY src,dst,protocol,sport,dport,connection_id ORDER BY bytes DESC,connection_id LIMIT 20""", (session_id,))]
            candidates = [dict(r) for r in self.db.execute("""SELECT src,dst,count(DISTINCT dport) ports,
              sum(syn) syn,sum(rst) rst,sum(bytes) bytes FROM session_flows
              WHERE session_id=? AND protocol='TCP' GROUP BY src,dst
              HAVING ports>=20 OR syn>=20 OR rst>=20 ORDER BY syn DESC,rst DESC LIMIT 20""", (session_id,))]
        for row in top + candidates:
            row['src'], row['dst'] = self.alias(row['src']), self.alias(row['dst'])
        return {'session_id': session_id, 'number': session['number'], 'filtered': bool(session['filtered']),
                'source_kind': session['source_kind'],
                'legacy_incomplete': bool(session['legacy_incomplete']),
                'original_connections': session['original_connections'],
                'state': session['state'], 'started': session['started'],
                'stopped': session['stopped'], 'as_of': as_of, 'duration_seconds': duration,
                'time_basis': 'Unix seconds UTC; capture interval differs from first/last observed packet',
                'interface_selected': bool(session['interface']), **totals,
                'protocols': protocols, 'time_bin_seconds': bin_width, 'time_bins': timeline,
                'top_flows_first_20': top, 'candidate_pairs_first_20': candidates,
                'anomaly_assessment': self.session_anomaly_assessment(session_id) if include_assessment else None,
                'scope': '本次采集经用户筛选后保留的连接分钟流桶；其他连接已删除；不可代表筛选前全貌' if session['filtered'] else
                         '旧版记录可能已被历史保留策略裁剪，不保证覆盖原采集全程' if session['legacy_incomplete'] else
                         '本次采集全部已保存的连接分钟流桶；双向分别记录，非逐包明细；候选线索不是恶意结论'}

    def session_connection_history(self, session_id, src, dst, protocol, sport=None, dport=None, page=1, page_size=50, connection_id=None):
        """Bidirectional minute timeline for a host pair or exact five-tuple."""
        session = self._session(session_id)
        if type(page_size) is not int or not 1 <= page_size <= 50 or type(page) is not int or page < 1:
            raise ValueError('无效分页：page >= 1，page_size 为 1–50')
        if (sport is None) != (dport is None):
            raise ValueError('源端口与目标端口须同时填写')
        if sport is not None and (min(sport, dport) < 0 or max(sport, dport) > 65535):
            raise ValueError('无效端口')
        ip1, ip2 = self._session_endpoints(session_id, src, dst)
        if sport is None:
            params = (session_id, protocol, ip1, ip2, ip2, ip1)
            where = "session_id=? AND protocol=? AND ((src=? AND dst=?) OR (src=? AND dst=?))"
        else:
            params = (session_id, protocol, ip1, ip2, sport, dport, ip2, ip1, dport, sport)
            where = """session_id=? AND protocol=? AND
              ((src=? AND dst=? AND sport=? AND dport=?) OR
               (src=? AND dst=? AND sport=? AND dport=?))"""
        if connection_id is not None:
            if sport is None:
                raise ValueError('查询connection_id必须同时指定两端端口')
            a_endpoint, b_endpoint = sorted(((ip1, sport), (ip2, dport)))
            self._instance_key(session_id, (*a_endpoint, *b_endpoint, protocol), connection_id)
            where += ' AND connection_id=?'
            params = (*params, connection_id)
        with self.lock:
            totals = dict(self.db.execute(f"""SELECT count(*) flow_buckets,coalesce(sum(bytes),0) bytes,
              coalesce(sum(packets),0) packets,coalesce(sum(syn),0) syn,coalesce(sum(rst),0) rst,
              min(first) first,max(last) last FROM session_flows WHERE {where}""", params).fetchone())
            rows = [dict(r) for r in self.db.execute(f"""SELECT bucket,src,dst,sport,dport,bytes,packets,syn,rst,first,last,connection_id
              FROM session_flows WHERE {where} ORDER BY bucket,id LIMIT ? OFFSET ?""", (*params, page_size, (page-1)*page_size))]
            a, ap, b, bp = self._canonical_sql()
            keys = [tuple(r) for r in self.db.execute(f"""SELECT {a} a,{ap} ap,{b} b,{bp} bp,protocol,connection_id
              FROM session_flows WHERE {where} GROUP BY 1,2,3,4,5,6
              ORDER BY 1,2,3,4,6 LIMIT ? OFFSET ?""", (*params, page_size, (page-1)*page_size))]
            connection_count = self.db.execute(f"""SELECT count(*) FROM (SELECT {a},{ap},{b},{bp},protocol,connection_id
              FROM session_flows WHERE {where} GROUP BY 1,2,3,4,5,6)""", params).fetchone()[0]
        for row in rows:
            row['src'], row['dst'] = self.alias(row['src']), self.alias(row['dst'])
        with self.lock:
            pair_rows = [dict(row) for row in self.db.execute("""SELECT * FROM session_connection_metrics WHERE
              session_id=? AND protocol=? AND ((a=? AND b=?) OR (a=? AND b=?))""",
              (session_id, protocol, ip1, ip2, ip2, ip1))]
        pair_assessment = self._alias_assessment(assess_session_records(pair_rows))
        pair_assessment['scope'] += '；此主机对的所查协议全部端口上下文，不限于本页或指定单条连接'
        return {'session_id': session_id, 'protocol': protocol, 'src': src, 'dst': dst,
                'sport': sport, 'dport': dport, 'connection_id': connection_id, **totals, 'page': page,
                'page_size': page_size,
                'pages': max(1, math.ceil(totals['flow_buckets']/page_size)), 'timeline': rows,
                'connection_metrics': [self._connection_metric(session_id, key) for key in keys],
                'connection_metrics_total': connection_count,
                'connection_metrics_pages': max(1, math.ceil(connection_count/page_size)),
                'pair_assessment': pair_assessment,
                'scope': ('仅保留用户筛选的连接；' if session['filtered'] else
                          '旧版记录可能已被历史保留策略裁剪；' if session['legacy_incomplete'] else '') +
                         f'本次采集双向分钟桶，{page_size}行一页；不含原始报文或应用层内容'}

    def prune(self):
        with self.lock, self.db:
            self.db.execute("DELETE FROM flows WHERE bucket < ?", (int(time.time()) - 7*86400,))
            self.db.execute("""DELETE FROM flows WHERE id IN
              (SELECT id FROM flows ORDER BY bucket DESC,id DESC LIMIT -1 OFFSET ?)""", (self.max_rows,))

    def read(self, source="live", seconds=300, end=None):
        end = time.time() if end is None else end
        start = int((end-seconds)//60)*60
        with self.lock:
            rows = [dict(r) for r in self.db.execute(
                "SELECT * FROM flows WHERE source=? AND bucket>=? AND bucket<=? ORDER BY bucket,id",
                (source, start, int(end//60)*60))]
        return rows

    def resolve(self, host):
        try:
            return str(ipaddress.ip_address(host))
        except ValueError:
            pass
        with self.lock:
            ips = [r[0] for r in self.db.execute("SELECT src FROM flows UNION SELECT dst FROM flows")]
        for ip in ips:
            if self.alias(ip) == host:
                return ip
        raise ValueError("未知 host 化名或 IP")

    def summary(self, source="live", seconds=300):
        rows = self.read(source, seconds)
        protocols = defaultdict(lambda: {"bytes": 0, "packets": 0, "records": 0})
        nodes = defaultdict(lambda: {"in_bytes": 0, "out_bytes": 0, "https_bytes": 0})
        for r in rows:
            for k in ("bytes", "packets", "records"):
                protocols[r["protocol"]][k] += r[k]
            nodes[r["src"]]["out_bytes"] += r["bytes"]
            nodes[r["dst"]]["in_bytes"] += r["bytes"]
            if r["protocol"] == "TCP" and 443 in (r["sport"], r["dport"]):
                nodes[r["src"]]["https_bytes"] += r["bytes"]
                nodes[r["dst"]]["https_bytes"] += r["bytes"]
        ranked = []
        for ip, n in nodes.items():
            total = n["in_bytes"] + n["out_bytes"]
            ranked.append({"host": self.alias(ip), **n, "total_bytes": total,
                           "out_ratio": round(n["out_bytes"]/max(total, 1), 4)})
        ranked.sort(key=lambda n: n["total_bytes"], reverse=True)
        return {"source": source, "window_seconds": seconds, "resolution_seconds": 60,
                "time_basis": {"csv": "import_time_not_capture_time", "simulation": "synthetic_time", "live": "capture_time"}[source],
                "first_observed_at": min((r["first"] for r in rows), default=None),
                "last_observed_at": max((r["last"] for r in rows), default=None),
                "coverage": "本地保留最多约100000个分钟流桶/7天；空窗口不代表网络安全；不含驱动层丢包信息",
                "bytes": sum(r["bytes"] for r in rows), "packets": sum(r["packets"] for r in rows),
                "records": sum(r["records"] for r in rows), "flow_buckets": len(rows),
                "hosts": len(nodes), "protocols": dict(protocols), "top_hosts": ranked[:30]}

    def flow_query(self, source="live", seconds=300, host=None, protocol=None, port=None, limit=30):
        ip = self.resolve(host) if host else None
        rows = self.read(source, seconds)
        matched = [r for r in rows if (not ip or ip in (r["src"], r["dst"]))
                   and (not protocol or r["protocol"] == protocol)
                   and (port is None or port in (r["sport"], r["dport"]))]
        matched.sort(key=lambda r: r["bytes"], reverse=True)
        public = []
        for r in matched[:limit]:
            public.append({k: self.alias(v) if k in {"src", "dst"} else v for k, v in r.items()})
        return {"flows": public, "matched": len(matched), "truncated": len(matched) > limit,
                "resolution_seconds": 60, "source": source}

    def behavior(self, host, source="live", seconds=300):
        ip = self.resolve(host)
        rows = [r for r in self.read(source, seconds) if ip in (r["src"], r["dst"])]
        outbound = [r for r in rows if r["src"] == ip]
        incoming = sum(r["bytes"] for r in rows if r["dst"] == ip)
        outgoing = sum(r["bytes"] for r in outbound)
        peers = {r["dst"] if r["src"] == ip else r["src"] for r in rows}
        ports = {r["dport"] for r in outbound}
        hints = []
        if len(ports) >= 20:
            hints.append("目的端口较分散，需排查扫描或正常多服务访问")
        if outgoing > 1024*1024 and outgoing/max(incoming+outgoing, 1) > .8:
            hints.append("出向字节占比较高，需结合备份/上传业务验证")
        return {"host": self.alias(ip), "source": source, "out_bytes": outgoing, "in_bytes": incoming,
                "peer_count": len(peers), "peers": sorted(self.alias(p) for p in peers)[:30],
                "destination_port_count": len(ports), "destination_ports": sorted(ports)[:100],
                "syn_without_ack_packets": sum(r["syn"] for r in outbound),
                "rst_packets": sum(r["rst"] for r in rows), "hints_not_verdicts": hints,
                "evidence_flow_ids": [r["id"] for r in rows[:30]],
                "limitations": "单点可见性；无进程/载荷/情报；SYN不是失败连接证明；CSV无包数/标志位"}

    def history(self, source="live", seconds=3600, host=None):
        ip = self.resolve(host) if host else None
        buckets = defaultdict(lambda: {"bytes": 0, "packets": 0, "records": 0})
        # At most 60 time bins even for seven-day queries.
        width = max(60, math.ceil(seconds/60/60)*60)
        for r in self.read(source, seconds):
            if ip and ip not in (r["src"], r["dst"]):
                continue
            b = int(r["bucket"]//width)*width
            for k in ("bytes", "packets", "records"):
                buckets[b][k] += r[k]
        return {"source": source, "bin_seconds": width,
                "bins": [{"timestamp": b, **v} for b, v in sorted(buckets.items())]}

    def graph(self, source="live", seconds=300, host=None, target=None):
        rows = self.read(source, seconds)
        adjacent = defaultdict(set)
        directed = defaultdict(set)
        for r in rows:
            adjacent[r["src"]].add(r["dst"])
            adjacent[r["dst"]].add(r["src"])
            directed[r["src"]].add(r["dst"])
        stars = sorted(({"center": self.alias(n), "leaf_count": sum(len(adjacent[p]) == 1 for p in peers)}
                        for n, peers in adjacent.items()), key=lambda x: x["leaf_count"], reverse=True)[:20]
        path, component, edges = [], [], []
        if host:
            start = self.resolve(host)
            seen, queue = ({start}, deque([start])) if start in adjacent else (set(), deque())
            while queue:
                n = queue.popleft()
                for p in adjacent[n]-seen:
                    seen.add(p)
                    queue.append(p)
            component = sorted(self.alias(n) for n in seen)[:100]
            selected = set(component)
            edges = [{"src": self.alias(r["src"]), "dst": self.alias(r["dst"])} for r in rows
                     if self.alias(r["src"]) in selected and self.alias(r["dst"]) in selected][:200]
            if target and start in adjacent:
                goal = self.resolve(target)
                queue, previous = deque([start]), {start: None}
                while queue:
                    n = queue.popleft()
                    if n == goal:
                        while n is not None:
                            path.append(self.alias(n))
                            n = previous[n]
                        path.reverse()
                        break
                    for p in directed[n]:
                        if p not in previous:
                            previous[p] = n
                            queue.append(p)
        return {"stars": stars, "component_first_100": component, "edges_first_200": edges, "directed_path": path,
                "meaning": "观测通信关系图，不代表物理拓扑、真实路由、拥塞或恶意行为"}

    def local_hosts(self, source="live", seconds=300):
        """Local UI only. Intentionally absent from the model tool registry."""
        ips = {r[k] for r in self.read(source, seconds) for k in ("src", "dst")}
        return {"notice": "IP对照仅供本地查看，不会加入模型上下文", "hosts_first_200":
                [{"ip": ip, "host": self.alias(ip)} for ip in sorted(ips)[:200]]}

    def import_csv(self, path):
        imported = rejected = 0
        stamp = time.time()
        batch = []
        with open(path, encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            required = {"Source", "Destination", "Protocol", "SrcPort", "DstPort", "DataSize", "Duration"}
            if not required.issubset(reader.fieldnames or []):
                raise ValueError("CSV 缺少字段：" + ", ".join(sorted(required)))
            for item in reader:
                if imported + rejected >= 100000:
                    raise ValueError("CSV 超过 100000 行；已导入前面的有效行")
                try:
                    r = dict(source="csv", src=str(ipaddress.ip_address(item["Source"])),
                             dst=str(ipaddress.ip_address(item["Destination"])),
                             protocol={6:"TCP",17:"UDP",1:"ICMP",58:"ICMPv6"}.get(int(item["Protocol"]),"OTHER"),
                             sport=int(item["SrcPort"] or 0), dport=int(item["DstPort"] or 0),
                             bytes=int(item["DataSize"]), duration=float(item["Duration"] or 0), packets=0, timestamp=stamp)
                    if not (0 <= r["sport"] <= 65535 and 0 <= r["dport"] <= 65535 and 0 <= r["bytes"] <= 10**12
                            and math.isfinite(r["duration"]) and r["duration"] >= 0):
                        raise ValueError()
                    batch.append(r)
                    imported += 1
                except (ValueError, TypeError, KeyError):
                    rejected += 1
                if len(batch) >= 500:
                    self.add(batch)
                    batch = []
            self.add(batch)
        self.prune()
        return {"imported": imported, "rejected": rejected, "source": "csv",
                "notice": "时间为导入时间，包数未知；重复导入会累加"}

    def usage(self):
        with self.lock:
            return dict(self.db.execute("SELECT calls,reserved,reported FROM budget WHERE id=1").fetchone())

    def reserve(self, amount, config):
        with self.lock, self.db:
            changed = self.db.execute("""UPDATE budget SET calls=calls+1,reserved=reserved+?
              WHERE id=1 AND reserved+?<=?""", (amount, amount, config.max_cost)).rowcount
            if not changed:
                raise ValueError("费用预留已达到上限；采集继续运行")

    def report_cost(self, amount, reservation=0):
        with self.lock, self.db:
            self.db.execute("UPDATE budget SET reported=reported+?,reserved=reserved+? WHERE id=1",
                            (amount, max(0, amount-reservation)))

    def close(self):
        with self.lock:
            self.db.close()
