"""Bounded, loopback-only experiments. Captures real packets with Npcap.

PCAP persistence is confined to this explicit lab command, not normal monitoring.
Labels describe the authored experiment; independent human review remains pending.
"""
from contextlib import ExitStack
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import socketserver
import threading
import time

from .capture import Collector
from .replay import Replay
from .evaluation import evaluate

SCENARIOS = {
    'web': (0, '本机HTTP请求，固定测试网页，不代表公网浏览器流量'),
    'dns': (0, '本机UDP DNS请求与响应，固定lab.invalid测试域名'),
    'ssh': (0, '本机真实SSH握手与加密会话，仅返回固定文本，不执行命令'),
    'file_transfer': (0, '本机HTTP下载1MiB固定测试内容'),
    'legitimate_polling': (0, '正常业务压力对照：32次合法HTTP轮询，检验短连接误报'),
    'syn_flood': (1, '有界SYN压力代理场景：48个SYN发往本机保留的未监听端口，无服务耗尽验证'),
    'port_scan': (1, '依次探测本机32个保留的未监听TCP端口'),
    'frequent_connections': (1, '32次快速建立并关闭本机TCP连接'),
    'abnormal_outbound': (1, '外联语义代理场景：向实验设定为未授权的本机接收端上传1MiB；非真实公网外联'),
}


class LocalTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def _serve(stack, server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    stack.callback(server.server_close)
    stack.callback(server.shutdown)
    return server.server_address[1]


def _scenario(stack, name):
    if name in ('web', 'file_transfer', 'legitimate_polling'):
        body = b'lab-file-data-' * 80660 if name == 'file_transfer' else b'<html>local lab</html>'
        class HTTPHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        port = _serve(stack, ThreadingHTTPServer(('127.0.0.1', 0), HTTPHandler))
        def run():
            for _ in range(32 if name == 'legitimate_polling' else 3 if name == 'web' else 1):
                client = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
                try:
                    client.request('GET', '/lab')
                    if client.getresponse().read() != body:
                        raise RuntimeError('HTTP内容校验失败')
                finally:
                    client.close()
                time.sleep(.01)
        return {port}, run
    if name == 'dns':
        from scapy.layers.dns import DNS, DNSQR, DNSRR
        class DNSHandler(socketserver.BaseRequestHandler):
            def handle(self):
                request, sock = self.request
                q = DNS(request)
                response = DNS(id=q.id, qr=1, aa=1, qd=q.qd,
                               an=DNSRR(rrname='lab.invalid', rdata='127.0.0.1', ttl=0))
                sock.sendto(bytes(response), self.client_address)
        port = _serve(stack, socketserver.ThreadingUDPServer(('127.0.0.1', 0), DNSHandler))
        def run():
            for i in range(3):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(3)
                    client.sendto(bytes(DNS(id=i + 1, qd=DNSQR(qname='lab.invalid'))), ('127.0.0.1', port))
                    answer = DNS(client.recv(2048))
                    if answer.id != i + 1 or not answer.qr:
                        raise RuntimeError('DNS响应校验失败')
        return {port}, run
    if name == 'ssh':
        import paramiko  # Optional lab-only dependency; no new Agent/model dependency.
        key = paramiko.RSAKey.generate(2048)
        class SSHPolicy(paramiko.ServerInterface):
            def check_auth_none(self, username):
                return paramiko.AUTH_SUCCESSFUL if username == 'local-lab' else paramiko.AUTH_FAILED
            def check_channel_request(self, kind, chanid):
                return paramiko.OPEN_SUCCEEDED if kind == 'session' else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        class SSHHandler(socketserver.BaseRequestHandler):
            def handle(self):
                with paramiko.Transport(self.request) as transport:
                    transport.add_server_key(key)
                    transport.start_server(server=SSHPolicy())
                    channel = transport.accept(3)
                    if channel is not None:
                        channel.sendall(b'local-ssh-lab')
                        channel.shutdown_write()
                        while channel.recv(1024):
                            pass
                        channel.close()
        port = _serve(stack, LocalTCPServer(('127.0.0.1', 0), SSHHandler))
        def run():
            with socket.create_connection(('127.0.0.1', port), timeout=3) as sock:
                with paramiko.Transport(sock) as transport:
                    transport.start_client(timeout=3)
                    transport.auth_none('local-lab')
                    channel = transport.open_session(timeout=3)
                    channel.settimeout(3)
                    data = b''
                    while True:
                        chunk = channel.recv(1024)
                        if not chunk:
                            break
                        data += chunk
                    if data != b'local-ssh-lab':
                        raise RuntimeError('SSH固定响应校验失败')
                    channel.shutdown_write()
                    time.sleep(.05)
                    channel.close()
        return {port}, run
    if name in ('syn_flood', 'port_scan'):
        # Reserve ports without listening, so no unrelated local service is probed.
        reserved = []
        for _ in range(32 if name == 'port_scan' else 1):
            sock = stack.enter_context(socket.socket())
            sock.bind(('127.0.0.1', 0))
            reserved.append(sock.getsockname()[1])
        def run():
            if name == 'syn_flood':
                from scapy.all import IP, TCP, send
                packets = [IP(src='127.0.0.1', dst='127.0.0.1') /
                           TCP(sport=48000+i, dport=reserved[0], flags='S', seq=100+i) for i in range(48)]
                send(packets, inter=.02, verbose=False)
            else:
                for port in reserved:
                    with socket.socket() as client:
                        client.settimeout(.3)
                        client.connect_ex(('127.0.0.1', port))
        return set(reserved), run
    class SinkHandler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            while self.request.recv(65536):
                pass
            self.request.sendall(b'lab-received')
    port = _serve(stack, LocalTCPServer(('127.0.0.1', 0), SinkHandler))
    def run():
        for _ in range(32 if name == 'frequent_connections' else 1):
            with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
                client.sendall(b'x' if name == 'frequent_connections' else b'x' * (1024 * 1024))
                client.shutdown(socket.SHUT_WR)
                while client.recv(1024):
                    pass
            time.sleep(.01)
    return {port}, run


def collect_dataset(output, repeats=3):
    if type(repeats) is not int or not 1 <= repeats <= 5:
        raise ValueError('实验重复次数必须在1–5之间')
    root = Path(output)
    if root.exists() and any(root.iterdir()):
        raise ValueError('实验输出目录非空；请指定新目录，避免覆盖已有PCAP和标签')
    root.mkdir(parents=True, exist_ok=True)
    # Fail before collecting a partial dataset if SSH dependency is missing.
    import paramiko
    from scapy.all import AsyncSniffer, PcapWriter, IP, TCP, UDP
    interface = next((i['id'] for i in Collector.interfaces() if 'Loopback' in i['id']), None)
    if interface is None:
        raise RuntimeError('需要Npcap回环网卡，本实验不支持对外部目标发包')
    records = []
    for name, (label, description) in SCENARIOS.items():
        for repeat in range(1, repeats + 1):
            directory = root / ('attack' if label else 'normal') / f'{name}-{repeat:02}'
            directory.mkdir(parents=True)
            pcap = directory / 'traffic.pcap'
            with ExitStack() as stack:
                ports, run = _scenario(stack, name)
                ready = threading.Event()
                def included(packet):
                    ip = packet.getlayer(IP)
                    return bool(ip and ip.src == ip.dst == '127.0.0.1' and
                                isinstance(ip.payload, (TCP, UDP)) and
                                (ip.payload.sport in ports or ip.payload.dport in ports))
                writer = PcapWriter(str(pcap), sync=True)
                sniffer = AsyncSniffer(iface=interface, store=False, promisc=False, lfilter=included,
                                       prn=writer.write, started_callback=ready.set)
                try:
                    sniffer.start()
                    if not ready.wait(5):
                        raise RuntimeError('Npcap未就绪，无法生成真实实验数据')
                    run()
                    time.sleep(.5)
                finally:
                    if sniffer.running:
                        sniffer.stop()
                    writer.close()
            with Replay(pcap) as replay:
                provenance = {'traffic_source': 'real_loopback_capture', 'generator': 'traffic_agent.lab',
                              'label_source': 'authored_scenario', 'human_reviewed': False,
                              'description': description, 'repeat': repeat,
                              'limitation': '实验设计标签待独立人工复核；受控本机通信不是公网攻击样本'}
                annotation = {'session_id': replay.session_id, 'pcap_sha256': replay.record['pcap_sha256'],
                              'label': label, 'scenario': name, 'provenance': provenance}
                record = {**replay.record, **annotation}
                (directory / 'session.json').write_text(json.dumps(replay.record, ensure_ascii=False, indent=2), encoding='utf-8')
                (directory / 'label.json').write_text(json.dumps(annotation, ensure_ascii=False, indent=2), encoding='utf-8')
                records.append(record)
                print(f'{name}-{repeat:02}: {replay.record["features"]["capture"]["pcap_packets"]} packets, score={replay.detection["anomaly_score"]}', flush=True)
    (root / 'dataset.jsonl').write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in records), encoding='utf-8')
    report = evaluate(records)
    (root / 'evaluation_report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    return report
