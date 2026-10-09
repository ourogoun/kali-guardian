from analysis.rules.icmp_rules import check_icmp_flood

def evaluate_rules(stats, create_alert):
    check_icmp_flood(stats, create_alert)
