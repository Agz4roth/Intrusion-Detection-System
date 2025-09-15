import os
os.environ["SCAPY_NO_IPV6"] = "1"

import scapy.all as scapy
import time

class NetworkMonitor:
    def __init__(self, interface, event_q, bpf_filter="", debug_mode=False):
        self.interface = interface
        self.event_q = event_q
        self.bpf_filter = bpf_filter
        self.debug_mode = debug_mode

    def _debug(self, msg):
        if self.debug_mode:
            print(f"[DEBUG] {msg}")

    def _packet_cb(self, pkt):
        try:
            if pkt.haslayer(scapy.IP):
                ip = pkt[scapy.IP]
                event = {
                    "type": "network",
                    "ts": time.time(),
                    "src_ip": ip.src,
                    "dst_ip": ip.dst,
                    "proto": "IP",
                    "info": {}
                }

                # Add signature_hint based on destination port
                if pkt.haslayer(scapy.TCP):
                    tcp = pkt[scapy.TCP]
                    event["info"]["signature_hint"] = str(tcp.dport)
                elif pkt.haslayer(scapy.UDP):
                    udp = pkt[scapy.UDP]
                    event["info"]["signature_hint"] = str(udp.dport)

                self.event_q.put(event)
                #print("[TEST] Network event sent:", event)

                self._debug(f"Event queued: {event}")
        except Exception as e:
            print(f"[LOG] Network error: {e}")

    def run(self):
        self._debug(f"Network monitoring on {self.interface} filter='{self.bpf_filter}'")
        try:
            scapy.sniff(
                iface=self.interface,
                prn=self._packet_cb,
                store=False,
                filter=self.bpf_filter
            )
        except Exception as e:
            print(f"[LOG] Failed to start sniffing: {e}")
