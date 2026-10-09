from scapy.all import sniff

def start_sniffer(interface="eth0", handler=None):
    def _wrapper(pkt):
        if handler:
            handler(pkt)
        else:
            print(pkt.summary())

    sniff(iface=interface, prn=_wrapper, store=False)

