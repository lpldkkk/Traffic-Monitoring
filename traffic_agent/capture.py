"""Capture callback only extracts allowed metadata into a bounded queue."""
import queue
import threading
import time
from collections import OrderedDict
from .connection_instances import annotate


def packet_metadata(packet, session_id):
    """Shared live/replay decoder. Payload is measured transiently, never returned."""
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    layer = packet.getlayer(IP) or packet.getlayer(IPv6)
    if layer is None:
        return None
    # Do not retain a Packet object, payload bytes, MAC, DNS or HTTP fields.
    proto, sport, dport, syn, syn_ack, ack, fin, rst, payload_bytes = "OTHER", 0, 0, 0, 0, 0, 0, 0, 0
    transport = layer.payload
    # Do not attach an inner tunneled packet's ports to outer IP addresses.
    if isinstance(transport, TCP):
        p = transport
        proto, sport, dport = "TCP", int(p.sport), int(p.dport)
        flags = int(p.flags)
        syn = int(bool(flags & 2) and not bool(flags & 16))
        syn_ack = int(bool(flags & 2) and bool(flags & 16))
        ack, fin, rst = int(bool(flags & 16)), int(bool(flags & 1)), int(bool(flags & 4))
        payload_bytes = len(p.payload)
    elif isinstance(transport, UDP):
        p = transport
        proto, sport, dport = "UDP", int(p.sport), int(p.dport)
    elif isinstance(transport, ICMP):
        proto = "ICMP"
    elif IPv6 in layer and int(layer.nh) == 58:
        proto = "ICMPv6"
    return dict(timestamp=float(packet.time), source='live', session_id=session_id, src=layer.src,
        dst=layer.dst, protocol=proto, sport=sport, dport=dport, bytes=len(packet), syn=syn,
        syn_ack=syn_ack, ack=ack, fin=fin, rst=rst, payload_bytes=payload_bytes,
        **({'tcp_seq': int(transport.seq), 'tcp_ack': int(transport.ack)} if proto == 'TCP' else {}))


class TCPStateTracker:
    def __init__(self):
        self._tcp_states = OrderedDict()
        self._tcp_ordinal = 0
        self._tcp_state_lost = False

    def _annotate_tcp(self, row):
        annotate(self, row)

    def reset_tracking(self, lost=False):
        self._tcp_states.clear()
        self._tcp_state_lost = lost
        # Never reset the ordinal within a capture after eviction/write errors.


class Collector(TCPStateTracker):
    def __init__(self, store, connections=None):
        self.store = store
        self.connections = connections
        self.connection_error = None
        self.incident_error = None
        self.queue = queue.Queue(maxsize=10000)
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.sniffer = None
        self.interface = None
        self.session_id = None
        self.last_session_id = None
        self.error = None
        self.received = self.dropped = self.ignored = 0
        self.last_packet_at = None
        super().__init__()
        self.worker = threading.Thread(target=self._writer, daemon=True)
        self.worker.start()

    @staticmethod
    def interfaces():
        try:
            from scapy.all import conf
            conf.ifaces.reload()
            return [{"id": str(i.network_name), "name": i.description or i.name} for i in conf.ifaces.values()]
        except Exception as exc:
            raise RuntimeError("网卡枚举失败：请安装 Scapy、Npcap 并检查权限（" + type(exc).__name__ + "）") from None

    def select(self, interface):
        with self.lock:
            if self.sniffer and self.sniffer.running:
                raise ValueError("请先停止采集再切换网卡")
            if interface not in {i["id"] for i in self.interfaces()}:
                raise ValueError("所选网卡不存在")
            if self.interface != interface and self.connections:
                self.connections.reset()
            self.interface = interface

    def auto_select(self):
        """Use OS-derived routing information; no packets are sent to probe addresses."""
        from scapy.all import conf
        conf.ifaces.reload()
        conf.route.resync()
        routes = []
        for target in ('1.1.1.1', '8.8.8.8'):
            interface, source, _ = conf.route.route(target, verbose=0)
            if source and source != '0.0.0.0' and not source.startswith('127.'):
                routes.append(interface)
        if not routes:
            try:
                conf.route6.resync()
                interface, source, _ = conf.route6.route('2606:4700:4700::1111', verbose=0)
                if source not in ('::', '::1'):
                    routes.append(interface)
            except Exception:
                pass
        available = list(conf.ifaces.values())
        for route in routes:
            for interface in available:
                if route == interface or str(route) in (str(interface.network_name), str(interface.name)):
                    self.select(str(interface.network_name))
                    return {'id': self.interface, 'name': interface.description or interface.name}
        raise RuntimeError('未找到当前默认路由对应的可用网卡；请在设置中选择网卡，并检查网络/Npcap权限')

    def _packet(self, packet):
        try:
            row = packet_metadata(packet, self.session_id)
            if row is None:
                self.ignored += 1
                return
            self.queue.put_nowait(row)
            self.received += 1
            self.last_packet_at = row['timestamp']
        except queue.Full:
            self.dropped += 1
        except Exception:
            self.ignored += 1

    def _writer(self):
        last_prune = 0
        last_incident_check = 0
        while not self.stop_event.is_set() or not self.queue.empty():
            batch = []
            try:
                batch.append(self.queue.get(timeout=.2))
                while len(batch) < 500:
                    batch.append(self.queue.get_nowait())
            except queue.Empty:
                pass
            try:
                if batch:
                    for row in batch:
                        self._annotate_tcp(row)
                    if self.connections:
                        try:
                            self.connections.annotate(batch)
                        except Exception as exc:
                            # Identity is optional; its failure must never drop traffic.
                            for row in batch:
                                row['application_observations'], row['owner'] = [], None
                            self.connection_error = '应用身份匹配失败：' + type(exc).__name__
                    self.store.add(batch)
                    if self.connections:
                        try:
                            self.connections.ingest(batch)
                        except Exception as exc:
                            self.connection_error = '连接列表更新失败：' + type(exc).__name__
                if time.monotonic() - last_prune > 30:
                    self.store.prune()
                    last_prune = time.monotonic()
                if batch and time.monotonic()-last_incident_check >= 30:
                    for sid in sorted({r['session_id'] for r in batch if r.get('session_id')}):
                        self._update_incidents(sid)
                    last_incident_check = time.monotonic()
            except Exception as exc:
                self.error = "流量写入失败（" + type(exc).__name__ + "）"
                self.dropped += len(batch)
                # An unpersisted handshake must not establish later packets.
                self.reset_tracking(lost=True)
            finally:
                for _ in batch:
                    self.queue.task_done()

    def _update_incidents(self, session_id):
        try:
            self.store.process_incidents(session_id)
            self.incident_error = None
        except Exception as exc:
            # Flow storage already committed; incident failures are separate
            # and retryable, never count those saved packets as dropped.
            self.incident_error = '事件更新失败，可重试（'+type(exc).__name__+'）'

    def start(self):
        with self.lock:
            if self.sniffer and self.sniffer.running:
                return self.status()
            if not self.interface:
                raise ValueError("先在本地界面选择并授权一张网卡")
            try:
                from scapy.all import AsyncSniffer
                if self.connections:
                    self.connections.resolver.refresh()
                ready = threading.Event()
                self.error = None
                self.incident_error = None
                if self.session_id:
                    self.queue.join()
                    self.store.end_session(self.session_id, 'interrupted')
                    self.last_session_id = self.session_id
                if self.connections:
                    self.connections.reset()
                    self.connections.proxy.reset()
                self.received = self.dropped = self.ignored = 0
                self.reset_tracking()
                self.last_packet_at = None
                self.session_id = self.store.start_session(self.interface)
                self.sniffer = AsyncSniffer(iface=self.interface, store=False, promisc=False,
                                            prn=self._packet, started_callback=ready.set)
                self.sniffer.start()
                if not ready.wait(5):
                    raise RuntimeError("Npcap 未就绪")
                if self.connections:
                    self.connections.proxy.enabled = True
            except Exception as exc:
                self.error = "抓包启动失败：检查 Npcap、网卡和管理员权限（" + type(exc).__name__ + "）"
                try:
                    if self.sniffer and self.sniffer.running:
                        self.sniffer.stop(join=False)
                except Exception:
                    pass
                if self.session_id:
                    self.queue.join()
                    self.store.end_session(self.session_id, 'failed')
                    self.last_session_id, self.session_id = self.session_id, None
                raise RuntimeError(self.error) from None
            return self.status()

    def stop(self):
        if self.connections:
            self.connections.proxy.enabled = False
        with self.lock:
            try:
                if self.sniffer and self.sniffer.running:
                    self.sniffer.stop()
            except Exception as exc:
                self.error = "抓包已终止（" + type(exc).__name__ + "）"
        self.queue.join()
        ended_session_id = None
        with self.lock:
            if self.session_id:
                self.store.end_session(self.session_id)
                ended_session_id = self.session_id
                self.last_session_id, self.session_id = self.session_id, None
        if ended_session_id:
            self._update_incidents(ended_session_id)
        return {**self.status(), 'ended_session_id': ended_session_id}

    def observe(self, seconds):
        # A bounded Agent capture must not stop a collector started by the user.
        already_running = bool(self.sniffer and self.sniffer.running)
        self.start()
        try:
            self.stop_event.wait(seconds)
        finally:
            if not already_running:
                self.stop()
        return {"observation_seconds": seconds, "capture": self.status(),
                "summary": self.store.summary("live", max(60, seconds))}

    def status(self):
        sniffer_error = getattr(self.sniffer, "exception", None)
        return {"running": bool(self.sniffer and self.sniffer.running and not sniffer_error),
                "interface_selected": bool(self.interface), "accepted_packets": self.received,
                "queue_dropped_packets": self.dropped, "ignored_packets": self.ignored,
                "pending_packets": self.queue.qsize(),
                "last_packet_at": self.last_packet_at,
                "session_id": self.session_id, "last_session_id": self.last_session_id,
                "incident_error": self.incident_error,
                "error": "抓包线程异常，请检查驱动和权限" if sniffer_error else self.error,
                "scope": "所选网卡可见的本机流量，非混杂模式；驱动层丢包数未知"}

    def close(self):
        self.stop()
        self.stop_event.set()
        self.worker.join(timeout=5)


def seed_simulation(store):
    """Explicit synthetic fixture, never substituted for a failed live capture."""
    stamp = time.time()
    rows = [dict(source="simulation", timestamp=stamp, src="192.0.2.10", dst="198.51.100.20",
                 protocol="TCP", sport=50000+i, dport=i+1, bytes=60, syn=1) for i in range(30)]
    rows += [dict(source="simulation", timestamp=stamp, src="192.0.2.30", dst="203.0.113.40",
                  protocol="TCP", sport=55000, dport=443, bytes=2*1024*1024)]
    store.add(rows)
    return {"source": "simulation", "records": len(rows), "notice": "人工构造的模拟数据，不是真实抓包"}
