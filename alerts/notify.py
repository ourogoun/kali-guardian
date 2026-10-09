import subprocess

def desktop_notify(title, message):
    try:
        subprocess.run(["notify-send", title, message])
    except:
        pass

def block_ip(ip):
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    except:
        pass
