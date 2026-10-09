from collections import defaultdict, deque
import time

class StatsEngine:
    def __init__(self, window_seconds=10):
        self.window_seconds = window_seconds
        self.packets = deque()
        self.per_ip_ports = defaultdict(set)
        self.per_ip_counts = defaultdict(int)
        self.icmp_counts = deque()

    def add_packet(self, parsed):
        now = time.time()
        print("STATS ENGINE RECEIVED:", parsed.get("protocol"))
        self.packets.append((now, parsed))
        src = parsed.get("src_ip")
        proto = parsed.get("protocol")

        if proto in ("TCP", "UDP"):
            sport = parsed["info"].get("sport")
            dport = parsed["info"].get("dport")
            if src and dport:
                self.per_ip_ports[src].add(dport)
                self.per_ip_counts[src] += 1

        if proto == "ICMP":
            self.icmp_counts.append(now)

        self._cleanup(now)

    def _cleanup(self, now):
        while self.packets and now - self.packets[0][0] > self.window_seconds:
            self.packets.popleft()
        while self.icmp_counts and now - self.icmp_counts[0] > self.window_seconds:
            self.icmp_counts.popleft()

    def get_packet_rate(self):
        return len(self.packets) / self.window_seconds

    def get_icmp_rate(self):
        return len(self.icmp_counts) / self.window_seconds

    def get_port_scan_candidates(self, threshold_ports=20):
        suspects = []
        for ip, ports in self.per_ip_ports.items():
            if len(ports) >= threshold_ports:
                suspects.append(ip)
        return suspects
