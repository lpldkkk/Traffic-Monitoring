"""Proxy fixtures are simulated unless RUN_LOCAL_PROXY_TEST=1 is explicitly set."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from traffic_agent.connections import ConnectionTracker, ProcessResolver
from traffic_agent.proxy import ProxyConnections, discover, fetch
from traffic_agent.store import Store


def connection(port=51001, app='', download=900):
    return {'id': str(port), 'start': datetime.fromtimestamp(time.time()-10, timezone.utc).isoformat(),
        'upload': 100, 'download': download, 'metadata': {'network': 'tcp', 'sourceIP': '127.0.0.1',
        'sourcePort': str(port), 'destinationIP': '', 'destinationPort': '443', 'host': 'private.example',
        'inboundIP': '127.0.0.1', 'inboundPort': '7897', 'processPath': app}}


def resolver():
    r = ProcessResolver()
    r.sampled_at = time.time()
    for port, pid, app in ((51001, 100, 'browser.exe'), (51002, 200, 'chat.exe')):
        r.tcp[('127.0.0.1', port, '127.0.0.1', 7897)] = {pid: {'pid': pid, 'app': app, 'created': time.time()-100}}
        r.tcp[('127.0.0.1', 7897, '127.0.0.1', port)] = {300: {'pid': 300, 'app': 'verge-mihomo.exe', 'created': time.time()-100}}
    return r


class ProxyTests(unittest.TestCase):
    def test_model_can_page_or_find_application_beyond_top_ten(self):
        from traffic_agent.capture import Collector
        from traffic_agent.tools import Toolset
        tracker = ConnectionTracker(start=False)
        tracker.proxy.enabled = True
        tracker.proxy.update([connection(port=51000+i, app='browser.exe', download=1000-i) for i in range(23)])
        store = Store(':memory:')
        collector = Collector(store, tracker)
        try:
            tool = Toolset(store, collector)
            result = tool.call('top_connections', '{"page":3}')
            self.assertTrue(result['ok'])
            self.assertEqual(len(result['data']['connections']), 3)
            self.assertEqual(result['data']['total_connections'], 23)
            result = tool.call('top_connections', '{"local_port":51022}')
            self.assertEqual(result['data']['matched_connections'], 1)
            self.assertEqual(result['data']['connections'][0]['local_port'], 51022)
            self.assertFalse(tool.call('top_connections', '{"page":0}')['ok'])
        finally:
            collector.close()
            store.close()

    def test_same_proxy_distinct_original_apps_and_destinations(self):
        p = ProxyConnections(resolver())
        p.enabled = True
        p.update([connection(), connection(51002, download=2000)])
        s = p.snapshot()
        self.assertEqual([c['app'] for c in s['connections']], ['chat.exe', 'browser.exe'])
        self.assertEqual(s['bytes'], 3100)
        self.assertEqual(s['connections'][0]['destination'], 'private.example')
        self.assertIsNone(s['connections'][0]['packets'])

    def test_unproven_stale_or_reused_socket_stays_unknown(self):
        for variant in ('no_reverse', 'wrong_inbound', 'stale', 'reused', 'ambiguous', 'udp'):
            r, c = resolver(), connection()
            if variant == 'no_reverse':
                r.tcp.pop(('127.0.0.1', 7897, '127.0.0.1', 51001))
            elif variant == 'wrong_inbound':
                c['metadata']['inboundPort'] = '9999'
            elif variant == 'stale':
                r.sampled_at -= 5
            elif variant == 'reused':
                r.tcp[('127.0.0.1', 51001, '127.0.0.1', 7897)][100]['created'] = time.time()
            elif variant == 'ambiguous':
                r.tcp[('127.0.0.1', 51001, '127.0.0.1', 7897)][101] = {'pid':101, 'app':'other', 'created':0}
            else:
                c['metadata']['network'] = 'udp'
            p = ProxyConnections(r)
            p.update([c])
            self.assertEqual(p.rows[0]['app'], '原始应用未识别', variant)

    def test_process_path_basename_only_and_model_redaction(self):
        tracker = ConnectionTracker(start=False)
        tracker.proxy.enabled = True
        tracker.proxy.update([connection(app=r'C:\Users\private\browser.exe')])
        store = Store(':memory:')
        try:
            c = tracker.dashboard()['connections'][0]
            self.assertEqual(c['app'], 'browser.exe')
            result = json.dumps(tracker.for_agent(store))
            for value in ('private.example', '127.0.0.1', 'Users', 'processPath'):
                self.assertNotIn(value, result)
            self.assertIsNone(tracker.for_agent(store)['connections'][0]['remote_host'])
        finally:
            tracker.close()
            store.close()

    def test_wire_and_proxy_scopes_not_added_and_failure_falls_back(self):
        tracker = ConnectionTracker(start=False)
        tracker.proxy.enabled = True
        tracker.proxy.update([connection(app='browser.exe')])
        self.assertEqual(tracker.dashboard()['bytes'], 1000)
        self.assertEqual(tracker.dashboard(wire=True)['bytes'], 0)
        tracker.proxy.error = 'unavailable'
        self.assertFalse(tracker.dashboard().get('proxy', False))
        tracker.proxy.error = None
        tracker.proxy.updated -= 20
        self.assertIsNone(tracker.proxy.snapshot())

    def test_closed_connections_removed_and_malformed_rows_ignored(self):
        p = ProxyConnections()
        p.update([connection(), {}, connection(download=-1)])
        self.assertEqual(len(p.rows), 1)
        p.update([])
        self.assertEqual(p.rows, [])

    def test_discovery_only_local_runtime_controller(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, APPDATA=tmp):
            root = Path(tmp)/'io.github.clash-verge-rev.clash-verge-rev'
            root.mkdir()
            file = root/'clash-verge.yaml'
            file.write_text('external-controller: 127.0.0.1:9097\nsecret: "local-test"\n', encoding='utf-8')
            self.assertEqual(discover(), {'url':'http://127.0.0.1:9097','secret':'local-test'})
            file.write_text('external-controller: 203.0.113.1:9097\n', encoding='utf-8')
            self.assertIsNone(discover())
            file.write_text("external-controller: ''\n", encoding='utf-8')
            (root/'config.yaml').write_text('external-controller: 127.0.0.1:9097\n', encoding='utf-8')
            self.assertIsNone(discover())

    def test_disabled_capture_does_not_read_proxy(self):
        p = ProxyConnections()
        with patch('traffic_agent.proxy.discover') as read:
            p.refresh()
            read.assert_not_called()
        p.update([connection()])
        self.assertIsNone(p.snapshot())

    @unittest.skipUnless(os.getenv('RUN_LOCAL_PROXY_TEST') == '1', '需显式启用本机代理只读测试')
    def test_real_local_proxy_original_applications(self):
        r = ProcessResolver()
        r.refresh()
        self.assertIsNone(r.error)
        p = ProxyConnections(r)
        p.enabled = True
        settings = discover()
        self.assertIsNotNone(settings, '本机未配置受支持的代理接口')
        p.update(fetch(settings))
        s = p.snapshot()
        self.assertIsNotNone(s)
        self.assertGreater(s['count'], 0, '需本机代理有活动连接')
        names = {c['app'] for c in s['connections'] if c['app'] != '原始应用未识别'}
        self.assertGreater(len(names), 1, '需实际识别至少两个不同应用')
        print('\n真实本机代理测试：', s['count'], '个连接；识别应用：', ', '.join(sorted(names)))


if __name__ == '__main__':
    unittest.main()
