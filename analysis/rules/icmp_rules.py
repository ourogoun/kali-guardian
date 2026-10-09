def check_icmp_flood(stats, create_alert):
    icmp_rate = stats.get("ICMP", 0)

    if icmp_rate > 120:
        severity = "CRITICAL"
    elif icmp_rate > 60:
        severity = "HIGH"
    elif icmp_rate > 30:
        severity = "MEDIUM"
    elif icmp_rate > 10:
        severity = "LOW"
    else:
        return

    create_alert(
        f"{severity} ICMP Flood",
        f"ICMP rate: {icmp_rate} pkt/s"
    )
def check_icmp_flood(stats, create_alert):
    icmp_rate = stats.get("ICMP", 0)

    if icmp_rate > 30:  # realistic threshold for VM
        create_alert(
            "ICMP Flood",
            f"High ICMP rate detected: {icmp_rate} packets per second"
        )
