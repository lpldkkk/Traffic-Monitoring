"""Deterministic identity snapshots; real packet integration is in test_integration."""
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from traffic_agent.connections import ConnectionTracker
from traffic_agent.capture import Collector
from traffic_agent.store import Store
from traffic_agent.tools import Toolset
from test_connections import row
from test_proxy import connection, resolver


class ApplicationTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(':memory:')
        self.tracker = ConnectionTracker(start=False)
        self.sid = self.store.start_session('snapshot-fixture')
        self.now = time.time()
        self.tracker.resolver.local_ips.add('192.0.2.1')
        self.owner()

    def tearDown(self):
        self.tracker.close()
        self.store.close()

    def owner(self, app='browser.exe', pid=42, created=None):
        self.tracker.resolver.sampled_at = self.now
        self.tracker.resolver.tcp = {('192.0.2.1', 1234, '198.51.100.2', 443):
            {pid: {'pid': pid, 'app': app, 'created': self.now-100 if created is None else created}}}

    def add(self, **kwargs):
        rows = [row(session_id=self.sid, timestamp=self.now, **kwargs)]
        self.tracker.annotate(rows)
        self.store.add(rows)

    def args(self):
        return dict(src=self.store.alias('192.0.2.1'), dst=self.store.alias('198.51.100.2'),
                    protocol='TCP', sport=1234, dport=443)

    def identity(self):
        return self.store.query_application_identity(self.sid, **self.args())

    def test_persists_process_lifetime_time_and_matching_scope_without_backfill(self):
        self.add()
        self.now += 10
        self.add()  # old snapshot is stale
        self.owner(app='replacement.exe')  # must never rewrite history
        data = self.identity()
        self.assertEqual(data['status'], 'partial')
        self.assertEqual(data['observations'][0]['app'], 'browser.exe')
        self.assertEqual(data['observations'][0]['matched_packets'], 1)
        self.assertEqual(data['endpoints'][0]['matched_packet_ratio'], .5)
        self.assertEqual(data['observations'][0]['first_sampled'], self.now-10)
        self.assertEqual(data['observations'][0]['process_created'], self.now-110)

    def test_pid_reuse_has_separate_lifetimes_even_with_same_name(self):
        self.add()
        self.now += 1
        self.owner(created=self.now-.1)
        self.add()
        data = self.identity()
        self.assertEqual(data['status'], 'multiple_identities')
        self.assertEqual(len(data['observations']), 2)
        self.assertEqual(data['endpoints'][0]['process_identities'], 2)

    def test_loopback_keeps_client_and_server_as_distinct_endpoints(self):
        self.tracker.resolver.local_ips.add('198.51.100.2')
        self.tracker.resolver.tcp[('198.51.100.2', 443, '192.0.2.1', 1234)] = {
            90: {'pid': 90, 'app': 'service.exe', 'created': self.now-50}}
        self.add()
        data = self.identity()
        self.assertEqual({r['app'] for r in data['observations']}, {'browser.exe', 'service.exe'})
        self.assertEqual({r['endpoint_port'] for r in data['observations']}, {1234, 443})
        self.assertEqual(self.store.session_summary(self.sid)['bytes'], 100)

    def test_udp_is_inferred_and_shared_port_is_unknown(self):
        self.tracker.resolver.udp = {('0.0.0.0', 1234): {42: {'pid': 42, 'app': 'dns.exe', 'created': self.now-50}}}
        self.add(protocol='UDP')
        data = self.store.query_application_identity(self.sid, **{**self.args(), 'protocol': 'UDP'})
        self.assertEqual(data['status'], 'inferred')
        self.tracker.resolver.udp[('0.0.0.0', 1234)][43] = {'pid': 43, 'app': 'shared.exe', 'created': 0}
        self.add(protocol='UDP')
        data = self.store.query_application_identity(self.sid, **{**self.args(), 'protocol': 'UDP'})
        self.assertEqual(data['observations'][0]['matched_packets'], 1)
        self.assertEqual(data['endpoints'][0]['matched_packet_ratio'], .5)

    def test_proxy_inbound_original_app_is_separate_and_exit_is_never_inferred(self):
        self.tracker.resolver = resolver()
        self.tracker.proxy.resolver = self.tracker.resolver
        self.tracker.proxy.enabled = True
        self.tracker.proxy.update([connection()])
        rows = [row(session_id=self.sid, src='127.0.0.1', dst='127.0.0.1', sport=51001, dport=7897)]
        self.tracker.annotate(rows)
        self.store.add(rows)
        args = dict(src=self.store.alias('127.0.0.1'), dst=self.store.alias('127.0.0.1'), protocol='TCP', sport=51001, dport=7897)
        data = self.store.query_application_identity(self.sid, **args)
        originals = [r for r in data['observations'] if r['role'] == 'proxy_original']
        self.assertEqual(originals[0]['app'], 'browser.exe')
        self.assertEqual(originals[0]['confidence'], 'inferred')
        self.assertTrue(any(r['proxy_process'] for r in data['observations']))
        exit_row = row(session_id=self.sid, src='127.0.0.1', sport=51001, dst='203.0.113.8', dport=7897)
        self.tracker.annotate([exit_row])
        self.assertFalse(exit_row['application_observations'])
        self.tracker.proxy.updated -= 10
        self.assertEqual(self.tracker.proxy.identify_wire(rows[0]), [])

    def test_proxy_ambiguous_mapping_and_old_packet_not_attributed(self):
        self.tracker.proxy.enabled = True
        item = connection(app=r'C:\Users\private\browser.exe')
        self.tracker.proxy.update([item, {**item, 'id': 'another-logical-connection'}])
        packet = row(src='127.0.0.1', dst='127.0.0.1', sport=51001, dport=7897)
        self.assertEqual(self.tracker.proxy.identify_wire(packet), [])
        self.tracker.proxy.update([item])
        packet['timestamp'] -= 30
        self.assertEqual(self.tracker.proxy.identify_wire(packet), [])

    def test_reopen_keeps_saved_identity_without_any_live_process_query(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'capture.db'
            saved = Store(path)
            try:
                sid = saved.start_session('snapshot-fixture')
                rows = [row(session_id=sid)]
                self.tracker.annotate(rows)
                saved.add(rows)
                saved.end_session(sid)
            finally:
                saved.close()
            reopened = Store(path)
            try:
                args = {**self.args(), 'src': reopened.alias('192.0.2.1'), 'dst': reopened.alias('198.51.100.2')}
                with patch('psutil.net_connections', side_effect=AssertionError('historical query must not inspect current OS')):
                    data = reopened.query_application_identity(sid, **args)
                self.assertEqual(data['observations'][0]['app'], 'browser.exe')
            finally:
                reopened.close()

    def test_tool_redaction_scope_and_legacy_unknown(self):
        self.owner(app=r'C:\Users\private\browser.exe')
        self.add()
        tool = Toolset(self.store, None, session_id=self.sid)
        result = tool.call('query_application_identity', json.dumps(self.args()))
        self.assertTrue(result['ok'], result)
        for secret in ('192.0.2.1', '198.51.100.2', 'Users', 'private'):
            self.assertNotIn(secret, json.dumps(result))
        self.assertFalse(tool.call('query_application_identity', json.dumps({**self.args(), 'session_id': 'foreign'}))['ok'])
        self.assertFalse(tool.call('query_application_identity', json.dumps({**self.args(), 'sport': 9}))['ok'])
        self.store.db.execute('DELETE FROM session_applications')
        self.assertEqual(self.identity()['status'], 'unknown')

    def test_retain_and_delete_remove_only_affected_identity_records(self):
        self.add()
        self.tracker.resolver.tcp[('192.0.2.1', 1234, '198.51.100.2', 80)] = self.tracker.resolver.tcp[('192.0.2.1', 1234, '198.51.100.2', 443)]
        self.add(dport=80)
        self.store.end_session(self.sid)
        self.store.retain_session_connections(self.sid, [('192.0.2.1', 1234, '198.51.100.2', 443, 'TCP')])
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM session_applications').fetchone()[0], 1)
        self.assertEqual(self.identity()['observations'][0]['app'], 'browser.exe')
        self.store.delete_session(self.sid)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM session_applications').fetchone()[0], 0)

    def test_capture_identity_failure_does_not_drop_packet(self):
        collector = Collector(self.store, self.tracker)
        try:
            with patch.object(self.tracker, 'annotate', side_effect=RuntimeError('snapshot failure')):
                collector.queue.put(row(session_id=self.sid))
                collector.queue.join()
            self.assertEqual(self.store.session_summary(self.sid)['packets'], 1)
            self.assertEqual(self.identity()['status'], 'unknown')
            self.assertIn('身份匹配失败', collector.connection_error)
        finally:
            collector.close()

    def test_all_process_lifetimes_remain_queryable_across_pages(self):
        for i in range(23):
            self.owner(app=f'app-{i}.exe', pid=100+i)
            self.add()
            self.now += 1
        first = self.identity()
        second = self.store.query_application_identity(self.sid, **self.args(), page=2)
        self.assertEqual(first['pages'], 2)
        self.assertEqual(first['total_observations'], 23)
        self.assertEqual(len(first['observations']), 20)
        self.assertEqual(len(second['observations']), 3)
        self.assertEqual(len({r['pid'] for r in first['observations']+second['observations']}), 23)
        self.assertEqual(first['endpoints'][0]['process_identities'], 23)


if __name__ == '__main__':
    unittest.main()
