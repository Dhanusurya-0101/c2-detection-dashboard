import threading
import time
import random
import binascii
from typing import Callable, Optional
from detector import C2Detector

class TrafficSimulator:
    def __init__(self, packet_callback: Callable[[dict], None], detector: C2Detector):
        self.packet_callback = packet_callback
        self.detector = detector
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.sim_count = 0

    def start(self):
        if self.is_running:
            return
        self.is_running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._simulate_loop, daemon=True)
        self._thread.start()

    def stop(self):
        if not self.is_running:
            return
        self.is_running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None

    def _simulate_loop(self):
        # We simulate multiple realistic traffic streams:
        # 1. Cobalt Strike Beacon: periodic HTTP to 198.51.100.80 every ~2.5s with slight jitter
        # 2. DNS Tunneling: periodic base64 encoded high-entropy subdomain requests
        # 3. Metasploit Reverse Shell: traffic on port 4444
        # 4. Normal benign traffic: HTTPS, DNS, API calls
        
        last_beacon_time = 0.0
        beacon_interval = 2.0  # 2 seconds periodic heartbeat
        
        last_dns_tunnel_time = 0.0
        dns_tunnel_interval = 4.0

        while not self._stop_event.is_set():
            now = time.time()
            packets_to_emit = []

            # 1. Cobalt Strike / C2 Beacon Heartbeat
            if now - last_beacon_time >= beacon_interval + random.uniform(-0.15, 0.15):
                last_beacon_time = now
                p_c2 = {
                    "timestamp": round(now, 3),
                    "time_str": time.strftime("%H:%M:%S", time.localtime(now)),
                    "src_ip": "192.168.1.105",
                    "dst_ip": "198.51.100.80",
                    "src_port": 49152 + random.randint(1, 100),
                    "dst_port": 80,
                    "protocol": "HTTP",
                    "length": 84,
                    "flags": "PA",
                    "dns_query": "",
                    "payload_len": 18,
                    "payload_preview": "GET /api/v1/ping HTTP/1.1..Host: c2-node.net",
                    "hex_preview": binascii.hexlify(b"GET /api/v1/ping HTTP/1.1\r\n").decode("ascii")
                }
                packets_to_emit.append(p_c2)

            # 2. DNS Tunneling Exfiltration
            if now - last_dns_tunnel_time >= dns_tunnel_interval + random.uniform(-0.5, 0.5):
                last_dns_tunnel_time = now
                # Generate pseudo high-entropy base64/hex chunk
                random_hex = "".join(random.choices("0123456789abcdef", k=32))
                tunnel_q = f"{random_hex}.exfil-stage2.darkc2.com."
                p_dns = {
                    "timestamp": round(now, 3),
                    "time_str": time.strftime("%H:%M:%S", time.localtime(now)),
                    "src_ip": "192.168.1.105",
                    "dst_ip": "8.8.8.8",
                    "src_port": 53124,
                    "dst_port": 53,
                    "protocol": "DNS",
                    "length": 112,
                    "flags": "",
                    "dns_query": tunnel_q,
                    "payload_len": len(tunnel_q),
                    "payload_preview": f"DNS Standard query 0x12a4 A {tunnel_q}",
                    "hex_preview": binascii.hexlify(tunnel_q.encode()).decode("ascii")
                }
                packets_to_emit.append(p_dns)

            # 3. Occasional Metasploit reverse shell pulse
            if random.random() < 0.15:
                p_shell = {
                    "timestamp": round(now, 3),
                    "time_str": time.strftime("%H:%M:%S", time.localtime(now)),
                    "src_ip": "192.168.1.105",
                    "dst_ip": "203.0.113.44",
                    "src_port": 54321,
                    "dst_port": 4444,
                    "protocol": "TCP",
                    "length": 128,
                    "flags": "PA",
                    "dns_query": "",
                    "payload_len": 48,
                    "payload_preview": "sh-5.1$ whoami; id; uname -a..",
                    "hex_preview": binascii.hexlify(b"sh-5.1$ whoami; id; uname -a").decode("ascii")
                }
                packets_to_emit.append(p_shell)

            # 4. Normal benign background traffic
            for _ in range(random.randint(1, 3)):
                dst = random.choice(["142.250.190.46", "104.244.42.1", "151.101.65.140", "13.107.4.52"])
                port = random.choice([443, 443, 443, 80])
                proto = "TLS/HTTPS" if port == 443 else "HTTP"
                p_benign = {
                    "timestamp": round(now, 3),
                    "time_str": time.strftime("%H:%M:%S", time.localtime(now)),
                    "src_ip": "192.168.1.105",
                    "dst_ip": dst,
                    "src_port": random.randint(50000, 60000),
                    "dst_port": port,
                    "protocol": proto,
                    "length": random.randint(120, 1420),
                    "flags": "A",
                    "dns_query": "",
                    "payload_len": random.randint(64, 1024),
                    "payload_preview": "Application Data / Encrypted TLS Record",
                    "hex_preview": "17030300" + "".join(random.choices("0123456789abcdef", k=32))
                }
                packets_to_emit.append(p_benign)

            # Emit parsed packets
            for p in packets_to_emit:
                p["simulated"] = True
                self.sim_count += 1
                severity, score, reasons = self.detector.analyze_packet(p)
                p["threat_level"] = severity
                p["threat_score"] = score
                p["threat_reasons"] = reasons
                p["id"] = self.sim_count
                try:
                    self.packet_callback(p)
                except Exception:
                    pass

            time.sleep(random.uniform(0.3, 0.7))
