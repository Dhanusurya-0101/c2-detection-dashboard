import subprocess
import time
import ctypes
import os
import ipaddress
from typing import Dict, List, Optional

class C2Blocker:
    def __init__(self):
        self.blocked_ips: Dict[str, dict] = {}
        self.auto_block_enabled = True
        self.is_admin = self._check_admin()

    @staticmethod
    def _check_admin() -> bool:
        """Checks if the Python process has Windows Administrator privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def is_safe_ip(self, ip: str) -> bool:
        """Ensures we never accidentally block localhost, local gateways, or essential DNS."""
        if not ip or ip in ("127.0.0.1", "0.0.0.0", "localhost", "::1"):
            return False
        # Do not block essential DNS resolvers to keep host Internet working
        if ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"):
            return False
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Don't block loopback or link-local
            if ip_obj.is_loopback or ip_obj.is_link_local:
                return False
        except ValueError:
            return False
        return True

    def block_ip(self, ip: str, reason: str = "Manual Block", trigger_type: str = "MANUAL") -> dict:
        """Blocks an IP address using Windows Firewall and software drop-table."""
        if not self.is_safe_ip(ip):
            return {
                "success": False,
                "ip": ip,
                "error": "Cannot block loopback or invalid address."
            }

        rule_name = f"C2_BLOCK_{ip.replace(':', '_')}"
        admin_applied = False
        cmd_output = ""

        # 1. Attempt Windows Firewall kernel-level block
        if self.is_admin:
            try:
                cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip="{ip}"'
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                if res.returncode == 0:
                    admin_applied = True
                    cmd_output = "Windows Firewall outbound rule created successfully."
                else:
                    cmd_output = res.stderr.strip() or res.stdout.strip()
            except Exception as e:
                cmd_output = f"Firewall command error: {str(e)}"
        else:
            cmd_output = "Software-level block applied. Run Python as Administrator for kernel-level Windows Firewall enforcement."

        # 2. Record in Active Block Registry
        now = time.time()
        record = {
            "ip": ip,
            "rule_name": rule_name,
            "reason": reason,
            "trigger_type": trigger_type,
            "timestamp": round(now, 2),
            "time_str": time.strftime("%H:%M:%S", time.localtime(now)),
            "admin_applied": admin_applied,
            "status_message": cmd_output,
            "hit_count": self.blocked_ips.get(ip, {}).get("hit_count", 0) + 1
        }
        self.blocked_ips[ip] = record
        print(f"[Blocker] Blocked C2 IP: {ip} | {reason} | Admin Firewall: {admin_applied}")
        return {"success": True, "record": record}

    def unblock_ip(self, ip: str) -> dict:
        """Removes the Windows Firewall rule and removes IP from blocklist."""
        rule_name = f"C2_BLOCK_{ip.replace(':', '_')}"
        cmd_output = ""

        if self.is_admin:
            try:
                cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                cmd_output = res.stdout.strip() or res.stderr.strip()
            except Exception as e:
                cmd_output = f"Firewall delete error: {str(e)}"

        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
            print(f"[Blocker] Unblocked C2 IP: {ip}")
            return {"success": True, "ip": ip, "message": cmd_output or "Unblocked successfully."}

        return {"success": False, "ip": ip, "error": "IP was not in active block list."}

    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

    def get_blocked_list(self) -> List[dict]:
        return list(self.blocked_ips.values())

    def toggle_auto_block(self) -> bool:
        self.auto_block_enabled = not self.auto_block_enabled
        print(f"[Blocker] Auto-Block mode set to: {self.auto_block_enabled}")
        return self.auto_block_enabled
