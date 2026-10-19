"""Opt-in tests: real local HTTP wire and real Npcap loopback capture.

RUN_LOCAL_INTEGRATION=1 python -m unittest discover -s tests -v
The HTTP model is scripted, not a real LLM API.
"""
import json
import http.client
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / ".runtime"))
from traffic_agent.agent import Agent
from traffic_agent.capture import Collector, seed_simulation
from traffic_agent.config import Config
from traffic_agent.store import Store
from traffic_agent.connections import ConnectionTracker
from test_agent import ModelFixture, call, response


@unittest.skipUnless(os.getenv("RUN_LOCAL_INTEGRATION") == "1", "需要显式启用本地网络/真实抓包测试")
class IntegrationTests(unittest.TestCase):
    @staticmethod
    def _loopback_interface():
        loop = next((i for i in Collector.interfaces() if 'Loopback' in i['id']), None)
        if loop is None:
            raise AssertionError('Npcap Loopback 未找到；真实 TCP 抓包无法验证')
        return loop['id']

    @staticmethod
    def _http_server():
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'local-tcp-metrics-test'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def test_real_npcap_loopback_tcp_http_handshake(self):
        store = Store(':memory:')
        collector = Collector(store)
        server = self._http_server()
        try:
            collector.select(self._loopback_interface())
            collector.start()
            sid = collector.session_id
            connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
            try:
                connection.request('GET', '/')
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), b'local-tcp-metrics-test')
            finally:
                connection.close()
            time.sleep(.5)
            collector.stop()
            rows = [row for row in store.session_connections(sid)['connections']
                    if server.server_port in (row['ap'], row['bp'])]
            self.assertTrue(rows, '真实回环 HTTP 连接没有进入会话')
            metrics = [row['metrics'] for row in rows]
            self.assertTrue(any(m['syn_seen'] and m['syn_ack_seen'] and m['fin_seen'] for m in metrics), metrics)
            self.assertTrue(any(m['handshake_status'] == 'CONFIRMED' for m in metrics), metrics)
            self.assertTrue(all(m['duration'] is not None and m['duration'] >= 0 for m in metrics))
            self.assertTrue(all(not m['assessment']['review_required'] for m in metrics), metrics)
            print(f'\n真实 Npcap TCP 测试：HTTP 端口 {server.server_port}，连接 {len(rows)} 条，握手与 FIN 已观察。')
        finally:
            collector.close()
            server.shutdown()
            server.server_close()
            store.close()

    def test_real_npcap_application_identity_survives_socket_close_and_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'identity.db'
            store = Store(path)
            tracker = ConnectionTracker(start=False)
            collector = Collector(store, tracker)
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            accepted = None
            try:
                listener.bind(('127.0.0.1', 0))
                listener.listen(1)
                listener.settimeout(3)
                client.settimeout(3)
                collector.select(self._loopback_interface())
                collector.start()
                sid = collector.session_id
                client.connect(listener.getsockname())
                accepted, _ = listener.accept()
                accepted.settimeout(3)
                source_port, destination_port = client.getsockname()[1], listener.getsockname()[1]
                tracker.resolver.refresh()  # Real OS table while both sockets are alive.
                self.assertIsNone(tracker.resolver.error)
                client.sendall(b'local-identity-test')
                self.assertEqual(accepted.recv(128), b'local-identity-test')
                accepted.sendall(b'local-reply')
                self.assertEqual(client.recv(128), b'local-reply')
                time.sleep(.5)
                collector.stop()
                args = dict(src=store.alias('127.0.0.1'), dst=store.alias('127.0.0.1'),
                            protocol='TCP', sport=source_port, dport=destination_port)
                identity = store.query_application_identity(sid, **args)
                self.assertEqual({r['endpoint_port'] for r in identity['observations']}, {source_port, destination_port})
                self.assertTrue(all(r['pid'] == os.getpid() for r in identity['observations']))
                self.assertTrue(all(r['matched_packets'] > 0 for r in identity['observations']))
                self.assertNotIn('local-identity-test', json.dumps(identity))
                print('\n真实 Npcap 应用身份测试：本机 TCP 两端均匹配当前 Python PID，未保存载荷。')
            finally:
                client.close()
                if accepted:
                    accepted.close()
                listener.close()
                collector.close()
                tracker.close()
                store.close()
            reopened = Store(path)
            try:
                with patch('psutil.net_connections', side_effect=AssertionError('禁止历史反推')):
                    self.assertEqual(reopened.query_application_identity(sid, **args), identity)
            finally:
                reopened.close()

    def test_real_npcap_loopback_tcp_multiport(self):
        store = Store(':memory:')
        collector = Collector(store)
        servers = [self._http_server() for _ in range(3)]
        try:
            collector.select(self._loopback_interface())
            collector.start()
            sid = collector.session_id
            for server in servers:
                connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
                try:
                    connection.request('GET', '/')
                    self.assertEqual(connection.getresponse().read(), b'local-tcp-metrics-test')
                finally:
                    connection.close()
            time.sleep(.5)
            collector.stop()
            rows = store.session_connections(sid)['connections']
            for server in servers:
                matching = [row for row in rows if server.server_port in (row['ap'], row['bp'])]
                self.assertEqual(len(matching), 1, f'端口 {server.server_port} 应为独立连接')
                metric = matching[0]['metrics']
                self.assertEqual(metric['packets'], matching[0]['packets'])
                self.assertEqual(metric['bytes'], matching[0]['bytes'])
                self.assertGreater(metric['a_to_b_packets'], 0)
                self.assertGreater(metric['b_to_a_packets'], 0)
                self.assertFalse(metric['assessment']['review_required'])
            print('\n真实 Npcap 多端口测试：3个本机 HTTP 端口分别记录，双向包/字节与会话聚合一致。')
        finally:
            collector.close()
            for server in servers:
                server.shutdown()
                server.server_close()
            store.close()

    def test_real_npcap_same_tuple_reconnect_has_distinct_instances(self):
        """Three real local sockets reuse one client port; abortive close avoids TIME_WAIT."""
        store = Store(':memory:')
        collector = Collector(store)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind(('127.0.0.1', 0))
            listener.listen(3)
            listener.settimeout(3)
            collector.select(self._loopback_interface())
            collector.start()
            sid = collector.session_id
            local_port = 0
            for index in range(3):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                    client.settimeout(3)
                    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                      struct.pack('HH' if os.name == 'nt' else 'ii', 1, 0))
                    client.bind(('127.0.0.1', local_port))
                    local_port = client.getsockname()[1]
                    client.connect(listener.getsockname())
                    accepted, _ = listener.accept()
                    with accepted:
                        accepted.settimeout(3)
                        client.sendall(bytes([index]))
                        self.assertEqual(accepted.recv(1), bytes([index]))
                        accepted.sendall(b'ok')
                        self.assertEqual(client.recv(2), b'ok')
                        client.close()  # RST while the peer still exists.
                time.sleep(.2)
            time.sleep(.5)
            collector.stop()
            ports = {local_port, listener.getsockname()[1]}
            rows = [r for r in store.session_connections(sid)['connections'] if {r['ap'], r['bp']} == ports]
            self.assertEqual(len(rows), 3, rows)
            self.assertEqual(len({r['connection_id'] for r in rows}), 3)
            for row in rows:
                self.assertEqual(row['metrics']['handshake_status'], 'CONFIRMED')
                self.assertEqual(row['metrics']['handshake_basis'], 'sequence_checked')
                self.assertTrue(row['metrics']['rst_seen'])
                self.assertEqual(row['metrics']['connection_state'], 'CLOSED')
                self.assertEqual(row['metrics']['packets'], row['packets'])
                self.assertEqual(row['metrics']['bytes'], row['bytes'])
            print('\n真实 Npcap 五元组复用测试：同一客户端/服务端端口重连3次，保存3个独立实例及各自握手、RST和计数。')
        finally:
            collector.close()
            listener.close()
            store.close()

    def test_archive_behavior_badge_and_local_evidence(self):
        import tkinter as tk
        from traffic_agent.ui import App
        with tempfile.TemporaryDirectory() as home:
            root = tk.Tk()
            root.withdraw()
            app = App(root, home)
            try:
                sid = app.store.start_session('synthetic-ui-fixture')
                stamp = time.time()
                app.store.add([dict(source='live', session_id=sid, timestamp=stamp+i,
                    src='192.0.2.1', dst='198.51.100.2', protocol='TCP', sport=40000+i,
                    dport=2000+i, bytes=60, syn=1, client_is_a=1,
                    handshake_status='SYN_ONLY', connection_state='UNKNOWN') for i in range(22)])
                app.store.end_session(sid)
                app.latest_session_id = sid
                app.show_page('captures')
                root.update()
                self.assertTrue(app.archive_table.get_children())
                self.assertTrue(all(app.archive_table.set(iid, 'risk').startswith('!')
                                    for iid in app.archive_table.get_children()))
                app.archive_table.selection_set(app.archive_table.get_children()[0])
                app.show_archive_assessment()
                root.update()
                self.assertTrue(any(isinstance(child, tk.Toplevel) and '连接行为评估' in child.title()
                                    for child in root.winfo_children()))
                with patch.object(app, 'background') as background:
                    app.connection_history(dict(source='live', local_ip='192.0.2.1', remote_ip='198.51.100.2',
                                                protocol='TCP', local_port=40000, remote_port=2000))
                    history = background.call_args.args[0]()
                    self.assertEqual(history['bytes'], 60)
                    self.assertEqual(history['pair_assessment']['candidate_pairs_total'], 1)
            finally:
                app.close()
                deadline = time.time()+5
                while time.time() < deadline:
                    try:
                        root.update()
                        if not root.winfo_exists():
                            break
                    except tk.TclError:
                        break
                    time.sleep(.1)

    def test_real_http_wire_with_scripted_model(self):
        fixture = ModelFixture()
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                output = json.dumps(fixture.complete(None, None, body)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(output)))
                self.end_headers()
                self.wfile.write(output)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        store = Store(":memory:")
        collector = Collector(store)
        try:
            seed_simulation(store)
            config = Config(base_url=f"http://127.0.0.1:{server.server_port}/v1", input_price=1, output_price=2)
            result = Agent(store, collector, config, "local-test-key").run("分析模拟流量", "simulation")
            self.assertTrue(result["ok"], result)
            self.assertEqual(len(result["trace"]), 3)
            print("\nHTTP 协议测试：模拟模型，4次 HTTP 调用，3个依赖工具，证据引用通过。")
        finally:
            collector.close()
            store.close()
            server.shutdown()
            server.server_close()

    def test_real_npcap_loopback_udp(self):
        interfaces = Collector.interfaces()
        loop = next((i for i in interfaces if "Loopback" in i["id"]), None)
        self.assertIsNotNone(loop, "Npcap Loopback 未找到；不能将此测试标成成功")
        store = Store(":memory:")
        tracker = ConnectionTracker(start=False)
        collector = Collector(store, tracker)
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            receiver.bind(("127.0.0.1", 0))
            sender.bind(("127.0.0.1", 0))
            receiver.settimeout(2)
            port = receiver.getsockname()[1]
            collector.select(loop["id"])
            collector.start()
            session_id = collector.status()['session_id']
            self.assertTrue(session_id)
            for i in range(8):
                sender.sendto(b"traffic-agent-local-capture-test", ("127.0.0.1", port))
                receiver.recvfrom(1024)
                time.sleep(.1)
            time.sleep(1)
            collector.stop()
            self.assertEqual(collector.status()['last_session_id'], session_id)
            self.assertEqual(store.session_summary(session_id)['state'], 'stopped')
            self.assertGreaterEqual(store.session_summary(session_id)['packets'], 8)
            rows = store.flow_query("live", port=port)["flows"]
            packets = sum(r["packets"] for r in rows)
            self.assertGreaterEqual(packets, 8)
            self.assertTrue(all(r["source"] == "live" for r in rows))
            connections = [c for c in tracker.snapshot()['connections'] if port in (c['local_port'], c['remote_port'])]
            self.assertEqual(len(connections), 1)
            self.assertTrue(connections[0]['owners'], '真实采集连接应匹配到本机测试进程')
            self.assertEqual(connections[0]['owners'][0]['pid'], os.getpid())
            print(f"\n真实 Npcap 测试：回环 UDP，发送8包，采集匹配 {packets} 包 / {sum(r['bytes'] for r in rows)} 字节。")
        finally:
            collector.close()
            sender.close()
            receiver.close()
            tracker.close()
            store.close()

    def test_tkinter_event_jobs_and_background_refresh(self):
        import tkinter as tk
        from traffic_agent.ui import App
        from test_incidents import IncidentTests
        from test_runtime import ScriptModel
        with tempfile.TemporaryDirectory() as home:
            root=tk.Tk(); root.withdraw(); app=App(root,home)
            try:
                base=IncidentTests(); base.store=app.store; base.serial=0
                base.sid=app.store.start_session('SYNTHETIC UI job fixture')
                base.add(pid=41); base.process(); app.store.end_session(base.sid)
                app.agent.transport=ScriptModel(); app.agent.api_key='scripted-only'
                app.show_page('jobs'); root.geometry('980x620'); root.deiconify()
                deadline=time.time()+5
                while not app.job_event_ids and time.time()<deadline:
                    root.update(); time.sleep(.02)
                self.assertTrue(app.job_event_ids)
                app.enqueue_event()
                deadline=time.time()+5
                while time.time()<deadline:
                    root.update(); time.sleep(.02)
                    if any(r['status']=='completed' for r in app.job_rows.values()): break
                self.assertTrue(any(r['status']=='completed' for r in app.job_rows.values()))
                job_id=next(iter(app.job_rows)); app.job_tree.selection_set(job_id)
                app.job_action('view')
                deadline=time.time()+3
                while not any(isinstance(w,tk.Toplevel) for w in root.winfo_children()) and time.time()<deadline:
                    root.update(); time.sleep(.02)
                self.assertTrue(any(isinstance(w,tk.Toplevel) for w in root.winfo_children()))
                # A deliberately blocked DB query must not block Tk's heartbeat.
                held=threading.Event(); release=threading.Event(); heartbeats=[]
                def hold():
                    with app.store.lock:
                        held.set(); release.wait(3)
                worker=threading.Thread(target=hold); worker.start(); held.wait(2)
                try:
                    app.refresh_jobs(); root.after(20,lambda:heartbeats.append(True))
                    deadline=time.time()+.2
                    while time.time()<deadline: root.update(); time.sleep(.01)
                    self.assertTrue(heartbeats)
                finally: release.set(); worker.join()
            finally:
                app.close(); deadline=time.time()+8
                while time.time()<deadline:
                    try: root.update()
                    except tk.TclError: break
                    time.sleep(.02)
                    if not app.investigator.thread.is_alive():
                        try:
                            if not root.winfo_exists(): break
                        except tk.TclError: break
                self.assertFalse(app.investigator.thread.is_alive())

    def test_tkinter_ui_lifecycle(self):
        import tkinter as tk
        from traffic_agent.ui import App
        with tempfile.TemporaryDirectory() as home:
            root = tk.Tk()
            root.withdraw()
            app = App(root, home)
            try:
                root.geometry('980x620')
                root.deiconify()
                app.show_page('agent')
                root.update()
                self.assertIn("Agent", root.title())
                self.assertTrue(app.ask_button.winfo_viewable())
                self.assertLess(app.ask_button.winfo_rooty()+app.ask_button.winfo_height(), root.winfo_rooty()+root.winfo_height())
                app.simulate()
                app.local_summary()
                for _ in range(8):
                    root.update()
                    time.sleep(.1)
                self.assertEqual(len(app.cards), 10)
                self.assertEqual(app.page, 'connections')
                deadline = time.time()+3
                while not app.current_connections and time.time() < deadline:
                    root.update()
                    time.sleep(.1)
                self.assertTrue(app.current_connections)
                self.assertTrue(any(c['anomaly'] for c in app.current_connections))
                # All 31 simulated connections must be reachable, ten at a time.
                all_ids = {c['id'] for c in app.current_connections}
                for index in range(1, 4):
                    app.next_page.invoke()
                    self.assertEqual(app.connection_page_index, index)
                    all_ids.update(c['id'] for c in app.current_connections)
                self.assertEqual(len(all_ids), 31)
                self.assertEqual(len(app.current_connections), 1)
                self.assertEqual(app.next_page.cget('state'), 'disabled')
                selected = app.current_connections[0]
                with patch('traffic_agent.ui.App.connection_details') as details:
                    app.open_index(0)
                    self.assertEqual(details.call_args.args[0]['id'], selected['id'])
                app.connection_search.set('TCP')
                self.assertEqual(app.connection_page_index, 0)
                app.connection_search.set('not-present.example')
                self.assertFalse(app.current_connections)
                app.connection_search.set('')
                root.update_idletasks()
                self.assertLess(app.next_page.winfo_rooty()+app.next_page.winfo_height(), root.winfo_rooty()+root.winfo_height())
                self.assertLessEqual(app.analysis_panel.winfo_rooty()+app.analysis_panel.winfo_height(),
                                     root.winfo_rooty()+root.winfo_height())
                from traffic_agent.connections import rank_connections
                from sample_data import course_csv
                app.store.import_csv(course_csv(self))
                app.set_source('csv')
                csv_data = rank_connections(app.store.read('csv', 300), set())
                csv_data['source'] = 'csv'
                app.render_snapshot({'revision': app.source_revision, 'data': csv_data,
                    'capture': app.collector.status(), 'budget': app.store.usage()})
                self.assertEqual(app.metrics['alerts'].cget('text'), '—')
                self.assertEqual(app.alert_filter.cget('state'), 'disabled')
                self.assertIn('无法评估', app.scope_label.cget('text'))
                # Explicit simulated proxy metadata: domain-only destinations and app details.
                from test_proxy import connection, resolver
                app.tracker.proxy.resolver = resolver()
                app.tracker.proxy.enabled = True
                app.tracker.proxy.update([connection(), connection(51002)])
                app.set_source('live')
                data = app.tracker.dashboard()
                app.render_snapshot({'revision': app.source_revision, 'data': data,
                    'capture': app.collector.status(), 'budget': app.store.usage()})
                self.assertTrue(app.snapshot['proxy'])
                self.assertEqual(app.metrics['alerts'].cget('text'), '—')
                self.assertIn('代理内应用', app.list_title.cget('text'))
                app.connection_details(app.current_connections[0])
                with patch.object(app, 'ask') as ask:
                    app.investigate(app.current_connections[0])
                    ask.assert_called_once()
                    self.assertNotIn('private.example', app.prompt.get('1.0', 'end'))
                app.toggle_connection_view()
                self.assertFalse(app.tracker.dashboard(wire=app.wire_view).get('proxy', False))
                # Stopping saves a session even without an API key, then can analyze it later.
                sid = app.store.start_session('test-interface')
                app.store.add([dict(source='live', session_id=sid, src='192.0.2.1', dst='198.51.100.2',
                                    protocol='TCP', sport=12345, dport=443, bytes=123, syn=1)])
                app.store.end_session(sid)
                app.latest_session_id = sid
                app.agent.api_key = ''
                app.analyze_session(auto=True)
                self.assertIn('API Key', app.analysis_var.get())
                class ReportModel:
                    def complete(self, config, key, body):
                        results = [json.loads(m['content']) for m in body['messages'] if m['role'] == 'tool']
                        if not results:
                            return response(calls=[call('session_summary', {})])
                        return response('会话保存并分析完成：需要进一步核实。证据 ' + results[-1]['evidence_id'])
                app.agent.config = Config(input_price=1, output_price=1)
                app.agent.transport = ReportModel()
                app.agent.api_key = 'scripted-test-key'
                app.analyze_session()
                deadline = time.time()+5
                while not app.report_answer and time.time() < deadline:
                    root.update()
                    time.sleep(.05)
                self.assertIn('会话保存并分析完成', app.report_answer)
                self.assertEqual(app.store.session_report(sid)['citation_valid'], 1)
            finally:
                app.close()
                deadline = time.time()+5
                while time.time() < deadline:
                    try:
                        root.update()
                        if not root.winfo_exists():
                            break
                    except tk.TclError:
                        break
                    time.sleep(.1)

    def test_capture_archive_ui_retains_selected_connections(self):
        import tkinter as tk
        from traffic_agent.ui import App
        with tempfile.TemporaryDirectory() as home:
            root = tk.Tk()
            root.withdraw()
            app = App(root, home)
            try:
                sid = app.store.start_session('test-interface')
                app.store.add([
                    dict(source='live', session_id=sid, src='192.0.2.1', dst='198.51.100.2',
                         protocol='TCP', sport=12345, dport=443, bytes=100),
                    dict(source='live', session_id=sid, src='192.0.2.1', dst='203.0.113.3',
                         protocol='TCP', sport=12346, dport=80, bytes=30),
                ])
                app.store.end_session(sid)
                app.store.save_session_report(sid, '旧分析', True)
                app.show_page('captures')
                root.update()
                self.assertEqual(app.capture_table.selection(), (sid,))
                self.assertIn('stopped', app.capture_table['columns'])
                self.assertIn('duration', app.capture_table['columns'])
                self.assertIn('application', app.archive_table['columns'])
                self.assertNotEqual(app.capture_table.set(sid, 'stopped'), '进行中')
                self.assertIn('持续', app.archive_info.get())
                self.assertEqual(app.store.session_connections(sid)['total'], 2)
                self.assertFalse(app.analyze_after_stop.get())
                keep = next(row['key'] for row in app.store.session_connections(sid)['connections'] if row['bp'] == 443)
                app.archive_keep.add(keep)
                app.refresh_capture_records()
                self.assertEqual(app.archive_keep, {keep})
                with patch('traffic_agent.ui.messagebox.askyesno', return_value=True):
                    app.retain_capture_connections()
                self.assertEqual(app.store.session_connections(sid)['total'], 1)
                self.assertEqual(app.store.session_summary(sid)['bytes'], 100)
                self.assertEqual(app.store.summary('live')['bytes'], 100)
                self.assertIsNone(app.store.session_report(sid))
                self.assertFalse(app.archive_keep)
                with patch('traffic_agent.ui.messagebox.askyesno', return_value=True):
                    app.delete_capture_record()
                self.assertFalse(app.store.list_sessions())
                self.assertEqual(app.store.summary('live')['bytes'], 0)
            finally:
                app.close()
                deadline = time.time()+5
                while time.time() < deadline:
                    try:
                        root.update()
                        if not root.winfo_exists():
                            break
                    except tk.TclError:
                        break
                    time.sleep(.1)

    def test_auto_select_current_network_from_routes(self):
        store = Store(':memory:')
        collector = Collector(store)
        try:
            selected = collector.auto_select()
            self.assertEqual(collector.interface, selected['id'])
            self.assertIn(selected['id'], {i['id'] for i in Collector.interfaces()})
            self.assertNotIn('Loopback', selected['id'])
            print('\n当前路由网卡自动识别：' + selected['name'])
        finally:
            collector.close()
            store.close()

    def test_agent_calls_real_capture_and_follows_evidence(self):
        class LiveModel:
            def complete(self, config, key, body):
                results = [json.loads(m["content"]) for m in body["messages"] if m["role"] == "tool"]
                if not results:
                    return response(calls=[call("capture_status", {})])
                if len(results) == 1:
                    return response(calls=[call("capture_traffic", {"seconds": 2})])
                if len(results) == 2:
                    return response(calls=[call("query_flows", {"protocol": "UDP"})])
                if len(results) == 3:
                    host = results[-1]["data"]["flows"][0]["src"]
                    return response(calls=[call("analyze_ip", {"host": host})])
                if len(results) == 4:
                    return response(calls=[call("query_history", {"host": results[-1]["data"]["host"]})])
                return response("[模拟模型 / 真实流量] 本机回环UDP测试流量，无足够证据判定攻击。" + results[2]["evidence_id"])
        loop = next(i for i in Collector.interfaces() if "Loopback" in i["id"])
        store = Store(":memory:")
        collector = Collector(store)
        stop = threading.Event()
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(.5)
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        def traffic():
            while not stop.wait(.1):
                if collector.status()["running"]:
                    sender.sendto(b"agent-owned-local-test", receiver.getsockname())
                    receiver.recvfrom(1024)
        worker = threading.Thread(target=traffic, daemon=True)
        worker.start()
        try:
            collector.select(loop["id"])
            config = Config(input_price=1, output_price=2)
            result = Agent(store, collector, config, "scripted-test", LiveModel()).run("分析当前流量")
            self.assertTrue(result["ok"], result)
            self.assertTrue(result["citation_valid"])
            self.assertEqual([t["name"] for t in result["trace"]],
                             ["capture_status", "capture_traffic", "query_flows", "analyze_ip", "query_history"])
            self.assertGreater(store.summary()["packets"], 0)
            self.assertFalse(collector.status()["running"], "Agent 临时抓包结束应停止自建采集")
            print(f"\nAgent 全链路测试：模拟模型自主工具序列，真实 Npcap 数据 {store.summary()['packets']} 包，5工具 / 6轮。")
        finally:
            stop.set()
            worker.join(timeout=2)
            sender.close()
            receiver.close()
            collector.close()
            store.close()


if __name__ == "__main__":
    unittest.main()
