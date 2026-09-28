"""
Parses an uploaded PCAP file (from a controlled lab capture or public
dataset) into flow records using the same fields our detection pipeline
already expects. No live capture involved - this only reads a file.
"""
from scapy.all import rdpcap, IP, TCP, UDP


def parse_pcap_to_flows(file_path: str) -> list[dict]:
    packets = rdpcap(file_path)
    flows = {}

    for pkt in packets:
        if IP not in pkt:
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = "OTHER"
        src_port = None
        dst_port = None

        if TCP in pkt:
            proto = "TCP"
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
        elif UDP in pkt:
            proto = "UDP"
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
        elif pkt.haslayer("ICMP"):
            proto = "ICMP"

        key = (src_ip, dst_ip, src_port, dst_port, proto)
        if key not in flows:
            flows[key] = {"packet_count": 0, "byte_count": 0}
        flows[key]["packet_count"] += 1
        flows[key]["byte_count"] += len(pkt)

    records = []
    for (src_ip, dst_ip, src_port, dst_port, proto), stats in flows.items():
        records.append({
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "source_port": src_port,
            "destination_port": dst_port,
            "protocol": proto,
            "packet_count": stats["packet_count"],
            "byte_count": stats["byte_count"],
        })
    return records