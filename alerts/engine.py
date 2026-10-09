import logging
from alerts.notify import desktop_notify, block_ip
from storage.database import store_alert

logging.basicConfig(
    filename="logs/alerts.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def raise_alert(src_ip, description, severity="MEDIUM", rule_id=None):
    alert_msg = f"[{severity}] {description} (src={src_ip}, rule={rule_id})"
    logging.info(alert_msg)

    desktop_notify("Kali Guardian Alert", alert_msg)

    store_alert(src_ip, severity, description, rule_id)

    if severity == "CRITICAL" and src_ip:
        block_ip(src_ip)
