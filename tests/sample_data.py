"""Private loopback recordings are optional; the fallback is SYNTHETIC, never sent."""
from pathlib import Path
import tempfile

from scapy.all import IP, TCP, Loopback, wrpcap


ROOT = Path(__file__).resolve().parents[1]


def port_scan_pcap(test_case):
    """Reuse the original private regression sample if available.

    A source-only checkout instead exercises the same replay/incident/Agent
    assertions using deterministic, synthetic DLT_NULL packets. This is a
    decoder and workflow fixture, not a real attack effectiveness benchmark.
    """
    recorded = ROOT / 'datasets/attack/port_scan-01/traffic.pcap'
    if recorded.is_file():
        return recorded
    directory = tempfile.TemporaryDirectory(prefix='synthetic-loopback-')
    test_case.addCleanup(directory.cleanup)
    path = Path(directory.name) / 'synthetic-port-scan.pcap'
    packets = []
    for index in range(32):
        source, target, sequence = 40000 + index, 20000 + index, 100 + index
        syn = Loopback(type=2) / IP(src='127.0.0.1', dst='127.0.0.2') / TCP(
            sport=source, dport=target, flags='S', seq=sequence)
        reset = Loopback(type=2) / IP(src='127.0.0.2', dst='127.0.0.1') / TCP(
            sport=target, dport=source, flags='RA', seq=0, ack=sequence + 1)
        syn.time, reset.time = 1700000000 + index * .1, 1700000000 + index * .1 + .01
        packets.extend((syn, reset))
    wrpcap(str(path), packets)
    return path


def course_csv(test_case):
    """Keep private CSV regression coverage; provide synthetic data for clean clones."""
    original = ROOT / '2可执行程序/processed_data_balanced.csv'
    if original.is_file():
        return original
    directory = tempfile.TemporaryDirectory(prefix='synthetic-csv-')
    test_case.addCleanup(directory.cleanup)
    path = Path(directory.name) / 'synthetic.csv'
    path.write_text('Source,Destination,Protocol,SrcPort,DstPort,DataSize,Duration\n'
                    '192.0.2.1,198.51.100.2,6,40000,443,1024,2\n'
                    '198.51.100.2,192.0.2.1,6,443,40000,2048,2\n'
                    '192.0.2.1,203.0.113.3,17,50000,53,64,0.1\n', encoding='utf-8')
    return path
