"""Create a sample packet capture with normal traffic plus one port scan, for testing."""
import random
from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

random.seed(42)  # same "random" traffic every run, so results are repeatable
packets = []
start = 1_700_000_000.0  # a fixed start time, in seconds
# Normal traffic: a handful of devices opening connections to web ports 80 and 443
for i in range(60):
    pkt = IP(src=f"192.168.1.{random.randint(10, 20)}", dst="192.168.1.1") / TCP(
        sport=random.randint(40000, 60000), dport=random.choice([80, 443]), flags="S")
    pkt.time = start + i * 0.5
    packets.append(pkt)

# The port scan: one device tries ports 1-200 in about 4 seconds
for i, port in enumerate(range(1, 201)):
    pkt = IP(src="192.168.1.66", dst="192.168.1.1") / TCP(sport=55555, dport=port, flags="S")
    pkt.time = start + 5 + i * 0.02
    packets.append(pkt)

packets.sort(key=lambda p: p.time)
wrpcap("samples/sample_scan.pcap", packets)
print(f"Wrote {len(packets)} packets to samples/sample_scan.pcap")