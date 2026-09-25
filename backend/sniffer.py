import threading
import time
import binascii
from typing import Callable, Optional, List, Dict
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR
from detector import C2Detector

class PacketSniffer:
    def __init__(self, packet_callback: Callable[[dict], None], detector: Optional[C2Detector] = None):
        self.packet_callback = packet_callback
        self.detector = detector or C2Detector()
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.current_interface: Optional[str] = None
        self.packet_count = 0

    @staticmethod
    def get_interfaces() -> List[Dict[str, any]]:
        """
        Returns a prioritized list of available network interfaces with friendly names and IPs.
        The active Internet/Wi-Fi interface is sorted to the very top.
        """
        interfaces = []
        try:
            from scapy.all import IFACES, conf
            default_key = str(getattr(conf, 'iface', ''))

            for k, iface in IFACES.data.items():
                name = getattr(iface, 'name', '') or 'Network Adapter'
                desc = getattr(iface, 'description', '') or ''
                ip = getattr(iface, 'ip', '') or ''
                
                # Priority scoring
                priority = 0
                if ip and not ip.startswith('169.254.') and not ip.startswith('127.'):
                    priority += 100  # Has real LAN / Internet IP (e.g. 10.x.x.x, 192.168.x.x)
                if 'wi-fi' in name.lower() or 'wireless' in desc.lower() or 'ethernet' in name.lower():
                    priority += 30
                if k == default_key or str(iface) == default_key:
                    priority += 40
                if 'virtualbox' in desc.lower() or 'vmware' in desc.lower():
                    priority -= 50  # Lower virtual host-only adapters

                display_title = name
                if ip:
                    display_title += f" ({ip})"
                if desc and desc != name:
                    display_title += f" - {desc[:35]}"

                interfaces.append({
                    "id": str(k),
                    "name": display_title,
                    "ip": ip,
                    "desc": desc,
                    "priority": priority,
                    "is_default": (k == default_key)
                })

            # Sort highest priority first
            interfaces.sort(key=lambda x: x["priority"], reverse=True)

        except Exception as e:
            try:
                for iface in scapy.get_if_list():
                    interfaces.append({
                        "id": str(iface),
                        "name": str(iface),
                        "ip": "",
                        "desc": "",
                        "priority": 0,
                        "is_default": False
                    })
            except Exception:
                interfaces = [{
                    "id": "default",
                    "name": "Default Interface",
                    "ip": "",
                    "desc": "",
                    "priority": 0,
                    "is_default": True
                }]

        return interfaces

    def get_default_interface(self) -> str:
        """Returns the ID of the best active interface."""
        ifaces = self.get_interfaces()
        if ifaces:
            return ifaces[0]["id"]
        return "default"

    def start(self, interface: Optional[str] = None):
        if self.is_running:
            self.stop()
        
        if not interface or interface == "default":
            interface = self.get_default_interface()

        self.is_running = True
        self.current_interface = interface
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        print(f"[Sniffer] Started capturing on: {self.current_interface}")

    def stop(self):
        if not self.is_running:
            return
        self.is_running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None
        print("[Sniffer] Stopped capture.")

    def _sniff_loop(self):
        def _scapy_callback(pkt):
            if self._stop_event.is_set():
                return
            parsed = self._parse_packet(pkt)
            if parsed:
                self.packet_count += 1
                # Run through C2 detection engine
                severity, score, reasons = self.detector.analyze_packet(parsed)
                parsed["threat_level"] = severity
                parsed["threat_score"] = score
                parsed["threat_reasons"] = reasons
                parsed["id"] = self.packet_count
                
                try:
                    self.packet_callback(parsed)
                except Exception:
                    pass

        try:
            kwargs = {
                "prn": _scapy_callback,
                "store": False,
                "stop_filter": lambda p: self._stop_event.is_set()
            }
            if self.current_interface and self.current_interface != "default":
                kwargs["iface"] = self.current_interface

            scapy.sniff(**kwargs)
        except Exception as e:
            print(f"[Sniffer] Live capture error on {self.current_interface}: {e}")
            self.is_running = False

    def _parse_packet(self, pkt) -> Optional[dict]:
        length = len(pkt)
        timestamp = float(pkt.time if hasattr(pkt, "time") else time.time())
        proto_str = "OTHER"
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        src_port = 0
        dst_port = 0
        flags = ""
        dns_query = ""
        payload_bytes = b""

        # 1. IP Layer (IPv4 or IPv6 or ARP)
        if pkt.haslayer(IP):
            ip_layer = pkt.getlayer(IP)
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
        elif pkt.haslayer(IPv6):
            ipv6_layer = pkt.getlayer(IPv6)
            src_ip = ipv6_layer.src
            dst_ip = ipv6_layer.dst
            proto_str = "IPv6"
        elif pkt.haslayer(ARP):
            arp_layer = pkt.getlayer(ARP)
            src_ip = arp_layer.psrc
            dst_ip = arp_layer.pdst
            proto_str = "ARP"
            op = "who-has" if arp_layer.op == 1 else "is-at"
            return {
                "timestamp": round(timestamp, 3),
                "time_str": time.strftime("%H:%M:%S", time.localtime(timestamp)),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": 0,
                "dst_port": 0,
                "protocol": "ARP",
                "length": length,
                "flags": "",
                "dns_query": "",
                "payload_len": 28,
                "payload_preview": f"ARP {op} {dst_ip} tell {src_ip}",
                "hex_preview": binascii.hexlify(bytes(arp_layer)[:32]).decode("ascii")
            }
        else:
            # Non-IP / unknown layer
            return None

        # 2. Transport & Application Layer
        if pkt.haslayer(TCP):
            tcp_layer = pkt.getlayer(TCP)
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            flags = str(tcp_layer.flags)
            if dst_port == 80 or src_port == 80:
                proto_str = "HTTP"
            elif dst_port == 443 or src_port == 443:
                proto_str = "TLS/HTTPS"
            else:
                proto_str = "TCP"
            payload_bytes = bytes(tcp_layer.payload)
        elif pkt.haslayer(UDP):
            udp_layer = pkt.getlayer(UDP)
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            proto_str = "UDP"
            payload_bytes = bytes(udp_layer.payload)

            if pkt.haslayer(DNS):
                proto_str = "DNS"
                dns_layer = pkt.getlayer(DNS)
                if dns_layer.qd and isinstance(dns_layer.qd, DNSQR):
                    try:
                        qname = dns_layer.qd.qname
                        dns_query = qname.decode("utf-8", errors="ignore") if isinstance(qname, bytes) else str(qname)
                    except Exception:
                        pass
            elif dst_port == 5353 or src_port == 5353:
                proto_str = "mDNS"
        elif pkt.haslayer(ICMP):
            proto_str = "ICMP"
            payload_bytes = bytes(pkt.getlayer(ICMP).payload)

        # Snippet preview for the inspector
        payload_preview = ""
        hex_preview = ""
        if payload_bytes:
            # Printable ASCII representation
            payload_preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in payload_bytes[:128])
            hex_preview = binascii.hexlify(payload_bytes[:64]).decode("ascii")

        return {
            "timestamp": round(timestamp, 3),
            "time_str": time.strftime("%H:%M:%S", time.localtime(timestamp)),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto_str,
            "length": length,
            "flags": flags,
            "dns_query": dns_query,
            "payload_len": len(payload_bytes),
            "payload_preview": payload_preview,
            "hex_preview": hex_preview
        }
