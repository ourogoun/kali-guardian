from alerts.engine import raise_alert

def evaluate_rules(stats_engine, parsed):
    print("RULE ENGINE CHECK:", parsed.get("protocol"))

    proto = parsed.get("protocol")
    src = parsed.get("src_ip")

    # ICMP flood detection
    icmp_rate = stats_engine.get_icmp_rate()
    if icmp_rate > 50:
        raise_alert(
            src_ip=src,
            description=f"High ICMP rate detected: {icmp_rate:.2f} pkt/s",
            severity="HIGH",
            rule_id="ICMP_FLOOD"
        )

    # Port scan detection
    suspects = stats_engine.get_port_scan_candidates()
    for ip in suspects:
        raise_alert(
            src_ip=ip,
            description="Possible port scan detected",
            severity="HIGH",
            rule_id="PORT_SCAN"
        )

