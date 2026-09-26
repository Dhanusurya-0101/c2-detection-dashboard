"""
C2 Sentinel - Enforcement Audit Logger.
Maintains an immutable, structured audit log of all firewall and quarantine actions.
"""

import os
import json
import time
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

LOGS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "logs"))
AUDIT_LOG_FILE = os.path.join(LOGS_DIR, "enforcement.log")

_lock = threading.Lock()


def ensure_log_dir():
    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR, exist_ok=True)


class EnforcementAuditLogger:
    """Structured audit logger writing JSON lines to backend/logs/enforcement.log."""

    def __init__(self, log_path: str = AUDIT_LOG_FILE):
        self.log_path = log_path
        ensure_log_dir()

    def log_event(
        self,
        action: str,
        target_ip: str,
        rule_name: str,
        status: str,
        trigger_type: str = "MANUAL",
        reason: str = "",
        admin_privilege: bool = False,
        verified: bool = False,
        details: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Appends a structured event record to the enforcement audit log."""
        now = time.time()
        iso_time = datetime.now(timezone.utc).isoformat()

        event = {
            "timestamp": iso_time,
            "epoch": round(now, 3),
            "action": action.upper(),
            "target_ip": target_ip,
            "rule_name": rule_name,
            "trigger_type": trigger_type.upper(),
            "status": status.upper(),
            "admin_privilege": admin_privilege,
            "verified": verified,
            "reason": reason,
            "details": details or "",
        }
        if extra:
            event["extra"] = extra

        # ASCII status indicator safe for all Windows encodings
        status_marker = "[OK]" if status in ("ENFORCED", "SIMULATED") else ("[DEL]" if status == "REMOVED" else "[FAIL]")
        try:
            print(
                f"[AUDIT] {status_marker} [{event['action']}] IP: {target_ip} | Rule: {rule_name} | "
                f"Status: {status} | Trigger: {trigger_type} | Admin: {admin_privilege} | Reason: {reason}"
            )
        except Exception:
            pass

        # Thread-safe write to log file
        with _lock:
            try:
                ensure_log_dir()
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event) + "\n")
            except Exception as e:
                print(f"[AUDIT ERROR] Failed to write to {self.log_path}: {e}")

        return event

    def get_recent_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Reads recent audit records in reverse chronological order."""
        if not os.path.exists(self.log_path):
            return []

        events = []
        with _lock:
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                events.append(json.loads(line))
                            except Exception:
                                continue
            except Exception as e:
                print(f"[AUDIT ERROR] Failed to read {self.log_path}: {e}")

        # Return latest entries first
        return events[-limit:][::-1]


audit_logger = EnforcementAuditLogger()
