import time
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP
from scapy.layers.http import HTTPRequest

def parse_packet(pkt):
    data = {
        "timestamp": time.time(),
        "src_ip": None,
        "dst_ip": None,
        "protocol": None,
        "size": len(pkt),
        "info": {}
    }

    # -------------------------
    # IP Layer
    # -------------------------
    if IP in pkt:
        ip = pkt[IP]
        data["src_ip"] = ip.src
        data["dst_ip"] = ip.dst
        data["info"]["ttl"] = ip.ttl

    # -------------------------
    # ARP
    # -------------------------
    if ARP in pkt:
        arp = pkt[ARP]
        data["protocol"] = "ARP"
        data["info"]["op"] = arp.op
        data["info"]["psrc"] = arp.psrc
        data["info"]["pdst"] = arp.pdst
        return data

    # -------------------------
    # ICMP (robust detection)
    # -------------------------
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        data["protocol"] = "ICMP"
        data["info"]["type"] = icmp.type
        data["info"]["code"] = icmp.code
        return data

    # -------------------------
    # TCP
    # -------------------------
    if TCP in pkt:
        tcp = pkt[TCP]
        data["protocol"] = "TCP"
        data["info"]["sport"] = tcp.sport
        data["info"]["dport"] = tcp.dport
        data["info"]["flags"] = str(tcp.flags)

        # HTTP detection
        if HTTPRequest in pkt:
            http = pkt[HTTPRequest]
            data["protocol"] = "HTTP"
            data["info"]["method"] = http.Method.decode() if http.Method else None
            data["info"]["host"] = http.Host.decode() if http.Host else None
            data["info"]["path"] = http.Path.decode() if http.Path else None

        return data

    # -------------------------
    # UDP
    # -------------------------
    if UDP in pkt:
        udp = pkt[UDP]
        data["protocol"] = "UDP"
        data["info"]["sport"] = udp.sport
        data["info"]["dport"] = udp.dport

        # DNS detection
        if DNS in pkt:
            dns = pkt[DNS]
            data["protocol"] = "DNS"
            if dns.qd and dns.qd.qname:
                data["info"]["query"] = dns.qd.qname.decode()

        return data

    return data

