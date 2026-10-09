from capture.sniffer import start_sniffer
from analysis.parser import parse_packet
from analysis.stats import StatsEngine
from analysis.rules import evaluate_rules
from storage.database import init_db, store_packet

stats_engine = StatsEngine()

def handle_packet(pkt):
    parsed = parse_packet(pkt)
    print("MAIN HANDLER:", parsed.get("protocol"))

    if not parsed.get("protocol"):
        return

    store_packet(parsed)
    stats_engine.add_packet(parsed)
    evaluate_rules(stats_engine, parsed)

if __name__ == "__main__":
    print("Starting Kali Guardian Sniffer...")
    init_db()
    start_sniffer("eth0", handler=handle_packet)

