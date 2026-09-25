import math
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple

class ThreatSeverity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = defaultdict(int)
    for char in data:
        frequencies[char] += 1
    for count in frequencies.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 3)

class C2Detector:
    def __init__(self):
        # Tracking flows for beaconing: key = (src_ip, dst_ip, dst_port, protocol)
        # value = deque of timestamps (max 30)
        self.flows: Dict[Tuple[str, str, int, str], deque] = defaultdict(lambda: deque(maxlen=30))
        self.flow_stats: Dict[Tuple[str, str, int, str], dict] = {}
        
        # Known common C2 / Suspicious ports
        self.suspicious_ports = {
            4444: ("Metasploit Default C2 / Reverse Shell", ThreatSeverity.CRITICAL),
            1337: ("Generic Hacker / C2 Default Port", ThreatSeverity.HIGH),
            8080: ("Common Alternative HTTP C2 Listener", ThreatSeverity.LOW),
            8443: ("Alternative HTTPS C2 Listener", ThreatSeverity.LOW),
            5555: ("Sliver C2 / Empire Default Listener", ThreatSeverity.HIGH),
            9001: ("Tor / Generic Reverse Shell Port", ThreatSeverity.HIGH),
            6667: ("IRC Botnet C2 Port", ThreatSeverity.HIGH),
            31337: ("Back Orifice / Legacy C2 Trojan Port", ThreatSeverity.CRITICAL),
        }
        
        # Whitelisted internal / standard services for beaconing check
        self.whitelisted_domains = {
            "google.com", "microsoft.com", "apple.com", "github.com",
            "cloudflare.com", "amazon.com", "windowsupdate.com"
        }

    def analyze_packet(self, packet_info: dict) -> Tuple[str, int, List[str]]:
        """
        Analyzes a single packet and returns:
        (threat_level, threat_score: 0-100, list_of_reasons)
        """
        reasons = []
        score = 0
        src_ip = packet_info.get("src_ip", "")
        dst_ip = packet_info.get("dst_ip", "")
        dst_port = packet_info.get("dst_port", 0)
        protocol = packet_info.get("protocol", "")
        dns_query = packet_info.get("dns_query", "")
        payload_len = packet_info.get("payload_len", 0)
        timestamp = packet_info.get("timestamp", time.time())

        # 1. Suspicious Port Check
        if dst_port in self.suspicious_ports:
            desc, severity = self.suspicious_ports[dst_port]
            if severity == ThreatSeverity.CRITICAL:
                score += 65
            elif severity == ThreatSeverity.HIGH:
                score += 45
            else:
                score += 25
            reasons.append(f"Known suspicious destination port {dst_port} ({desc})")

        # 2. DNS Tunneling & Exfiltration Detection
        if dns_query:
            query_clean = dns_query.rstrip(".").lower()
            subdomain_parts = query_clean.split(".")
            
            # Check length of the primary subdomain label
            first_label = subdomain_parts[0] if subdomain_parts else ""
            entropy = calculate_shannon_entropy(first_label)
            packet_info["dns_entropy"] = entropy

            if len(first_label) > 25 and entropy > 3.6:
                score += 60
                reasons.append(
                    f"Suspicious DNS query (Length: {len(first_label)}, High Shannon Entropy: {entropy}) - Potential DNS Tunneling"
                )
            elif len(first_label) > 40:
                score += 40
                reasons.append(
                    f"Anomalously long DNS query label ({len(first_label)} chars) - Potential Exfiltration"
                )
            elif entropy > 4.2 and len(first_label) > 15:
                score += 50
                reasons.append(
                    f"High entropy string in DNS label ({entropy}) - Potential Encoded C2 Payload"
                )

        # 3. Beaconing Detection (Inter-Arrival Time Periodicity)
        if src_ip and dst_ip and dst_port > 0 and protocol in ("TCP", "HTTP", "HTTPS", "TLS"):
            flow_key = (src_ip, dst_ip, dst_port, protocol)
            times = self.flows[flow_key]
            times.append(timestamp)

            if len(times) >= 6:
                intervals = [times[i] - times[i - 1] for i in range(1, len(times))]
                # Filter out rapid bursts (< 0.05s) to avoid TCP handshakes
                valid_intervals = [dt for dt in intervals if dt > 0.1]
                
                if len(valid_intervals) >= 4:
                    mean_interval = sum(valid_intervals) / len(valid_intervals)
                    variance = sum((dt - mean_interval) ** 2 for dt in valid_intervals) / len(valid_intervals)
                    std_dev = math.sqrt(variance)
                    jitter = (std_dev / mean_interval) if mean_interval > 0 else 1.0

                    self.flow_stats[flow_key] = {
                        "mean_interval": round(mean_interval, 2),
                        "std_dev": round(std_dev, 2),
                        "jitter": round(jitter, 3),
                        "count": len(times)
                    }

                    # Low jitter indicates automated beaconing (e.g. heartbeat every N seconds)
                    # Typical C2 like Cobalt Strike has default jitter 0% or up to 20-30%
                    if 0.5 <= mean_interval <= 60.0 and jitter < 0.20:
                        score += 55
                        reasons.append(
                            f"Periodic C2 Beaconing pattern: Mean Interval ~{mean_interval:.1f}s, Jitter {jitter*100:.1f}% (Flow: {src_ip} -> {dst_ip}:{dst_port})"
                        )
                    elif 0.5 <= mean_interval <= 60.0 and jitter < 0.35:
                        score += 30
                        reasons.append(
                            f"Potential C2 Beaconing with jitter: Interval ~{mean_interval:.1f}s, Jitter {jitter*100:.1f}%"
                        )

        # 4. Small payload persistent outbound egress (typical of sleep/heartbeat pulses)
        if payload_len > 0 and payload_len < 32 and protocol == "TCP" and dst_port in (80, 443, 8080):
            score += 10
            reasons.append(f"Small heartbeat packet size ({payload_len} bytes)")

        # Determine Severity Level
        score = min(score, 100)
        if score >= 75:
            severity = ThreatSeverity.CRITICAL
        elif score >= 50:
            severity = ThreatSeverity.HIGH
        elif score >= 25:
            severity = ThreatSeverity.MEDIUM
        elif score > 0:
            severity = ThreatSeverity.LOW
        else:
            severity = ThreatSeverity.INFO

        return severity, score, reasons

    def get_flow_stats(self):
        return [
            {
                "flow": f"{k[0]} -> {k[1]}:{k[2]} ({k[3]})",
                "mean_interval": v["mean_interval"],
                "std_dev": v["std_dev"],
                "jitter": v["jitter"],
                "count": v["count"]
            }
            for k, v in list(self.flow_stats.items())[-10:]
        ]
