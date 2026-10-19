import os
from pathlib import Path
import socket
import sys
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / '.runtime'))

from traffic_agent.connections import ConnectionTracker, ProcessResolver, connection_page, rank_connections
from traffic_agent.capture import Collector
from traffic_agent.store import Store
from traffic_agent.tools import Toolset


def row(**kwargs):
    return dict(dict(source='live', src='192.0.2.1', dst='198.51.100.2', sport=1234, dport=443,
                     protocol='TCP', bytes=100, packets=1, syn=0, rst=0, timestamp=time.time()), **kwargs)


class ConnectionTests(unittest.TestCase):
    def test_all_connections_reachable_in_ten_row_pages(self):
        rows = [{'id': i, 'app': 'browser.exe', 'destination': f'site-{i}.example'} for i in range(23)]
        self.assertEqual([len(connection_page(rows, i)['items']) for i in range(3)], [10, 10, 3])
        self.assertEqual([c['id'] for i in range(3) for c in connection_page(rows, i)['items']], list(range(23)))
        self.assertEqual(connection_page(rows[:2], 2)['page'], 0)
        self.assertEqual(connection_page([], 2)['items'], [])
        self.assertEqual(connection_page(rows, -1)['page'], 0)

    def test_search_includes_connections_beyond_first_ten(self):
        rows = [{'app': 'browser.exe', 'destination': 'other.example', 'local_port': i} for i in range(23)]
        rows[22]['destination'] = 'www.bilibili.com'
        result = connection_page(rows, 0, 'BILIBILI browser')
        self.assertEqual(result['matched'], 1)
        self.assertEqual(result['total'], 23)
        self.assertEqual(result['items'][0]['local_port'], 22)
        self.assertEqual(connection_page(rows, 0, 'missing')['matched'], 0)

    def test_bidirectional_merge_and_rank_after_merge(self):
        rows = [row(bytes=80), row(src='198.51.100.2', dst='192.0.2.1', sport=443, dport=1234, bytes=90),
                row(dst='203.0.113.2', bytes=150)]
        result = rank_connections(rows, {'192.0.2.1'})
        self.assertEqual(result['count'], 2)
        self.assertEqual(result['connections'][0]['bytes'], 170)
        self.assertEqual((result['upload'], result['download']), (230, 90))

    def test_top_ten_are_connections_not_hosts(self):
        result = rank_connections([row(dport=i+1, bytes=(i+1)*10) for i in range(15)], {'192.0.2.1'})
        self.assertEqual(len(result['connections'][:10]), 10)
        self.assertEqual(result['connections'][0]['remote_port'], 15)
        self.assertEqual(result['count'], 15)

    def test_both_inbound_and_outbound_scan_indicators(self):
        for ips in ({'192.0.2.1'}, {'198.51.100.2'}, set()):
            result = rank_connections([row(dport=i+1, syn=1) for i in range(20)], ips)
            self.assertEqual(result['alerts'], 20)

    def test_large_download_not_flagged(self):
        result = rank_connections([row(bytes=500*1024*1024)], {'192.0.2.1'})
        self.assertEqual(result['alerts'], 0)

    def test_loopback_and_unknown_not_internet_upload(self):
        for ips in ({'192.0.2.1', '198.51.100.2'}, set()):
            result = rank_connections([row()], ips)
            self.assertEqual(result['upload']+result['download'], 0)
            self.assertEqual(result['bytes'], 100)

    def test_snapshot_pid_matching_staleness_and_shared_udp(self):
        resolver = ProcessResolver()
        now = time.time()
        resolver.sampled_at = now
        owner = {'pid': 42, 'app': 'browser.exe', 'created': now-100}
        resolver.tcp = {('192.0.2.1', 1234, '198.51.100.2', 443): {42: owner}}
        args = ('TCP', ('192.0.2.1', 1234), ('198.51.100.2', 443))
        self.assertEqual(resolver.identify(*args, now)['app'], 'browser.exe')
        self.assertIsNone(resolver.identify(*args, now-10))
        resolver.udp = {('0.0.0.0', 1234): {42: owner, 43: {**owner, 'pid': 43}}}
        self.assertIsNone(resolver.identify('UDP', args[1], args[2], now))
        resolver.tcp[(*args[1], *args[2])][42]['created'] = now+1
        self.assertIsNone(resolver.identify(*args, now))

    def test_partial_ownership_preserved_and_not_backfilled(self):
        tracker = ConnectionTracker(start=False)
        now = time.time()
        tracker.resolver.local_ips.add('192.0.2.1')
        tracker.ingest([row(timestamp=now-10)])
        tracker.resolver.sampled_at = now
        tracker.resolver.tcp = {('192.0.2.1', 1234, '198.51.100.2', 443): {42: {'pid':42, 'app':'browser.exe', 'created':now-100}}}
        tracker.ingest([row(timestamp=now)])
        c = tracker.snapshot()['connections'][0]
        self.assertEqual(c['app'], 'browser.exe')
        self.assertEqual(c['ownership_ratio'], .5)
        tracker.resolver.tcp.clear()
        self.assertEqual(tracker.snapshot()['connections'][0]['ownership_ratio'], .5)

    def test_reused_socket_multiple_processes_not_one_app(self):
        owner = {'pid':42, 'app':'browser.exe', 'created':1, 'basis':'test'}
        rows = [row(owner=owner), row(owner={**owner, 'pid':43, 'app':'other.exe'})]
        result = rank_connections(rows, {'192.0.2.1'})['connections'][0]
        self.assertEqual(len(result['owners']), 2)
        self.assertIn('多个进程', result['app'])

    def test_no_old_rows_after_window(self):
        tracker = ConnectionTracker(start=False)
        tracker.ingest([row(timestamp=time.time()-400)])
        self.assertEqual(tracker.snapshot()['count'], 0)

    def test_process_table_permission_error_degrades(self):
        import psutil
        resolver = ProcessResolver()
        with patch('psutil.net_connections', side_effect=psutil.AccessDenied()):
            resolver.refresh()
        self.assertIn('受限', resolver.error)
        self.assertEqual(resolver.tcp, {})

    def test_model_tool_has_no_raw_ip(self):
        store = Store(':memory:')
        tracker = ConnectionTracker(start=False)
        collector = Collector(store, tracker)
        try:
            tracker.ingest([row()])
            result = Toolset(store, collector).call('top_connections', '{}')
            self.assertTrue(result['ok'])
            self.assertNotIn('192.0.2.1', str(result))
            self.assertNotIn('198.51.100.2', str(result))
            self.assertFalse(Toolset(store, collector, 'csv').call('top_connections', '{}')['ok'])
        finally:
            collector.close()
            store.close()

    def test_real_local_udp_process_snapshot(self):
        # OS metadata only, no packet sent or external connection made.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(('127.0.0.1', 0))
            resolver = ProcessResolver()
            resolver.refresh()
            if resolver.error:
                self.skipTest(resolver.error)
            owner = resolver.identify('UDP', sock.getsockname(), ('127.0.0.1', 12345), time.time())
            self.assertIsNotNone(owner)
            self.assertEqual(owner['pid'], os.getpid())
        finally:
            sock.close()


if __name__ == '__main__':
    unittest.main()
