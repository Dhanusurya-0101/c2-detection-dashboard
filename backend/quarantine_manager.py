"""
C2 Sentinel - Quarantine & Policy Management Engine.
Coordinates threat detection alerts with firewall enforcement, state machine transitions,
and audit logging.
Maintains ONE authoritative source of truth for active blocked IPs.
"""

import time
import threading
from typing import Dict, List, Optional, Any, Tuple

try:
    from backend.ip_validator import validate_ip, check_block_policy
    from backend.firewall_adapter import (
        FirewallAdapter,
        WindowsFirewallAdapter,
        MockFirewallAdapter,
        FirewallResult,
        sanitize_rule_name,
        is_admin_user,
    )
    from backend.audit_logger import audit_logger
except ImportError:
    from ip_validator import validate_ip, check_block_policy
    from firewall_adapter import (
        FirewallAdapter,
        WindowsFirewallAdapter,
        MockFirewallAdapter,
        FirewallResult,
        sanitize_rule_name,
        is_admin_user,
    )
    from audit_logger import audit_logger


class QuarantineManager:
    """
    Manages quarantine lifecycle, threat auto-blocking, manual quarantine,
    state reconciliation, and audit logging.
    Maintains one authoritative collection of active unique blocked IPs.
    """

    def __init__(
        self,
        firewall_adapter: Optional[FirewallAdapter] = None,
        simulation_mode: bool = False,
        auto_block_enabled: bool = True,
        auto_block_score_threshold: int = 70,
    ):
        self._lock = threading.RLock()
        self.simulation_mode = simulation_mode
        self.auto_block_enabled = auto_block_enabled
        self.auto_block_score_threshold = auto_block_score_threshold

        self.windows_adapter = WindowsFirewallAdapter()
        self.mock_adapter = MockFirewallAdapter()

        # Initialize firewall adapter
        if firewall_adapter is not None:
            self.adapter = firewall_adapter
        else:
            self.adapter = self.mock_adapter if self.simulation_mode else self.windows_adapter

        # Authoritative In-Memory Registry of Quarantined IPs:
        # Keyed strictly by normalized IP address (guarantees uniqueness)
        self.quarantine_registry: Dict[str, Dict[str, Any]] = {}

        # Initial reconciliation with active firewall rules
        self.sync_with_firewall()

    def set_simulation_mode(self, enabled: bool):
        with self._lock:
            self.simulation_mode = enabled
            self.adapter = self.mock_adapter if enabled else self.windows_adapter
            audit_logger.log_event(
                action="CONFIG_CHANGE",
                target_ip="*",
                rule_name="*",
                status="CONFIGURED",
                reason=f"Simulation mode set to {enabled}",
                admin_privilege=is_admin_user(),
            )

    def is_admin(self) -> bool:
        return is_admin_user()

    def get_active_blocked_ips(self) -> List[Dict[str, Any]]:
        """
        The ONE authoritative collection of currently active blocked IPs.
        Returns unique active blocked IP records.
        In real enforcement mode, only ENFORCED blocks are counted.
        In simulation mode, SIMULATED (and ENFORCED) blocks are counted.
        """
        with self._lock:
            if not self.simulation_mode:
                return [
                    rec
                    for rec in self.quarantine_registry.values()
                    if rec.get("status") == "ENFORCED"
                ]
            else:
                return [
                    rec
                    for rec in self.quarantine_registry.values()
                    if rec.get("status") in ("ENFORCED", "SIMULATED")
                ]

    @property
    def active_blocked_count(self) -> int:
        """Total number of currently active blocked IPs from the authoritative collection."""
        return len(self.get_active_blocked_ips())

    def is_quarantined(self, ip: str) -> bool:
        with self._lock:
            meta = validate_ip(ip)
            normalized = meta["ip"] if meta["valid"] else ip.strip()

            # Check registry first
            if normalized in self.quarantine_registry:
                rec = self.quarantine_registry[normalized]
                if not self.simulation_mode:
                    if rec.get("status") == "ENFORCED":
                        return True
                else:
                    if rec.get("status") in ("ENFORCED", "SIMULATED"):
                        return True

            # Also check underlying adapters
            if not self.simulation_mode:
                return self.adapter.is_blocked(normalized)
            else:
                return self.adapter.is_blocked(normalized) or self.mock_adapter.is_blocked(normalized)

    def get_quarantined_list(self) -> List[Dict[str, Any]]:
        """Returns the authoritative active blocked list."""
        return self.get_active_blocked_ips()

    def get_failed_list(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                rec
                for rec in self.quarantine_registry.values()
                if rec.get("status") == "BLOCK_FAILED"
            ]

    def block_ip(
        self,
        target_ip: str,
        reason: str = "Manual Quarantine",
        trigger_type: str = "MANUAL",
        direction: str = "out",
        force_simulation: bool = False,
    ) -> Dict[str, Any]:
        """
        Executes quarantine flow for a target IP address.
        Guarantees idempotency and maintains single source of truth for active blocked count.
        """
        with self._lock:
            # 1. IP Validation and Policy Check
            allowed, policy_msg, meta = check_block_policy(target_ip)
            if not allowed:
                audit_logger.log_event(
                    action="POLICY_REJECT",
                    target_ip=target_ip,
                    rule_name="",
                    status="FAILED",
                    trigger_type=trigger_type,
                    reason=policy_msg,
                    admin_privilege=is_admin_user(),
                    details=meta.get("error"),
                )
                return {
                    "success": False,
                    "ip": target_ip,
                    "status": "BLOCK_FAILED",
                    "error": policy_msg,
                    "code": "POLICY_REJECTED",
                    "validation": meta,
                    "active_blocked_count": self.active_blocked_count,
                }

            normalized_ip = meta["ip"]
            rule_name = sanitize_rule_name(normalized_ip)
            admin_present = is_admin_user()
            use_simulation = self.simulation_mode or force_simulation

            # 2. Idempotency Check: if already actively blocked, do not duplicate or re-execute command
            if normalized_ip in self.quarantine_registry:
                existing_rec = self.quarantine_registry[normalized_ip]
                current_status = existing_rec.get("status")
                if (not use_simulation and current_status == "ENFORCED") or (use_simulation and current_status in ("ENFORCED", "SIMULATED")):
                    existing_rec["hit_count"] = existing_rec.get("hit_count", 1) + 1
                    existing_rec["timestamp"] = round(time.time(), 2)
                    existing_rec["time_str"] = time.strftime("%H:%M:%S", time.localtime())
                    return {
                        "success": True,
                        "record": existing_rec,
                        "already_blocked": True,
                        "active_blocked_count": self.active_blocked_count,
                    }

            # 3. Check Administrator Privileges if Real Enforcement is Requested
            if not use_simulation and not admin_present:
                err_msg = (
                    "Administrator privileges are required to modify Windows Firewall rules. "
                    "Please launch Python as Administrator, or enable Simulation Mode in Sentinel settings."
                )
                record = {
                    "ip": normalized_ip,
                    "rule_name": rule_name,
                    "reason": reason,
                    "trigger_type": trigger_type,
                    "status": "BLOCK_FAILED",
                    "verified": False,
                    "admin_applied": False,
                    "error": err_msg,
                    "code": "ELEVATION_REQUIRED",
                    "timestamp": round(time.time(), 2),
                    "time_str": time.strftime("%H:%M:%S", time.localtime()),
                    "hit_count": self.quarantine_registry.get(normalized_ip, {}).get("hit_count", 0),
                }
                self.quarantine_registry[normalized_ip] = record

                audit_logger.log_event(
                    action="BLOCK",
                    target_ip=normalized_ip,
                    rule_name=rule_name,
                    status="FAILED",
                    trigger_type=trigger_type,
                    reason=reason,
                    admin_privilege=False,
                    verified=False,
                    details=err_msg,
                )

                return {
                    "success": False,
                    "ip": normalized_ip,
                    "status": "BLOCK_FAILED",
                    "error": err_msg,
                    "code": "ELEVATION_REQUIRED",
                    "requires_elevation": True,
                    "record": record,
                    "active_blocked_count": self.active_blocked_count,
                }

            # 4. Invoke Firewall Adapter
            adapter_to_use = self.mock_adapter if use_simulation else self.adapter
            result: FirewallResult = adapter_to_use.block_ip(normalized_ip, direction=direction)

            # 5. Process Outcome & Update State
            if result.success and result.verified:
                final_status = "SIMULATED" if use_simulation else "ENFORCED"
                existing_hits = self.quarantine_registry.get(normalized_ip, {}).get("hit_count", 0)
                record = {
                    "ip": normalized_ip,
                    "rule_name": rule_name,
                    "reason": reason,
                    "trigger_type": trigger_type,
                    "status": final_status,
                    "verified": True,
                    "admin_applied": not use_simulation,
                    "status_message": result.output or "Rule verified in firewall.",
                    "timestamp": round(time.time(), 2),
                    "time_str": time.strftime("%H:%M:%S", time.localtime()),
                    "hit_count": existing_hits + 1,
                }
                self.quarantine_registry[normalized_ip] = record
                current_active_count = self.active_blocked_count

                # Requirement 16: Structured logging
                print(f"BLOCK ADD:\nIP={normalized_ip}\nactive_count={current_active_count}")

                audit_logger.log_event(
                    action="BLOCK",
                    target_ip=normalized_ip,
                    rule_name=rule_name,
                    status=final_status,
                    trigger_type=trigger_type,
                    reason=reason,
                    admin_privilege=admin_present,
                    verified=True,
                    details=result.output,
                )

                return {
                    "success": True,
                    "record": record,
                    "active_blocked_count": current_active_count,
                }
            else:
                err_msg = result.error or "Firewall rule creation or verification failed."
                existing_hits = self.quarantine_registry.get(normalized_ip, {}).get("hit_count", 0)
                record = {
                    "ip": normalized_ip,
                    "rule_name": rule_name,
                    "reason": reason,
                    "trigger_type": trigger_type,
                    "status": "BLOCK_FAILED",
                    "verified": False,
                    "admin_applied": False,
                    "error": err_msg,
                    "timestamp": round(time.time(), 2),
                    "time_str": time.strftime("%H:%M:%S", time.localtime()),
                    "hit_count": existing_hits,
                }
                self.quarantine_registry[normalized_ip] = record

                audit_logger.log_event(
                    action="BLOCK",
                    target_ip=normalized_ip,
                    rule_name=rule_name,
                    status="FAILED",
                    trigger_type=trigger_type,
                    reason=reason,
                    admin_privilege=admin_present,
                    verified=False,
                    details=err_msg,
                )

                return {
                    "success": False,
                    "ip": normalized_ip,
                    "status": "BLOCK_FAILED",
                    "error": err_msg,
                    "record": record,
                    "active_blocked_count": self.active_blocked_count,
                }

    def unblock_ip(self, target_ip: str) -> Dict[str, Any]:
        """
        Removes firewall blocking rules for an IP and updates quarantine state.
        Immediately decrements the active blocked count.
        """
        with self._lock:
            meta = validate_ip(target_ip)
            normalized_ip = meta["ip"] if meta["valid"] else target_ip.strip()
            rule_name = sanitize_rule_name(normalized_ip)

            # Determine which adapter holds the rule
            is_in_mock = rule_name in getattr(self.mock_adapter, "mock_rules", {})
            adapter_to_use = self.mock_adapter if (is_in_mock or self.simulation_mode) else self.adapter

            # Check admin if modifying real Windows Firewall
            if adapter_to_use is not self.mock_adapter and not is_admin_user():
                err_msg = "Administrator privileges are required to remove Windows Firewall rules."
                audit_logger.log_event(
                    action="UNBLOCK",
                    target_ip=normalized_ip,
                    rule_name=rule_name,
                    status="FAILED",
                    reason="Non-admin attempt to delete rule.",
                    admin_privilege=False,
                    details=err_msg,
                )
                return {
                    "success": False,
                    "ip": normalized_ip,
                    "error": err_msg,
                    "code": "ELEVATION_REQUIRED",
                    "active_blocked_count": self.active_blocked_count,
                }

            result: FirewallResult = adapter_to_use.unblock_ip(normalized_ip)

            if result.success:
                # Remove from active quarantine registry
                if normalized_ip in self.quarantine_registry:
                    del self.quarantine_registry[normalized_ip]

                current_active_count = self.active_blocked_count

                # Requirement 16: Structured logging
                print(f"BLOCK REMOVE:\nIP={normalized_ip}\nactive_count={current_active_count}")

                audit_logger.log_event(
                    action="UNBLOCK",
                    target_ip=normalized_ip,
                    rule_name=rule_name,
                    status="REMOVED",
                    reason="Manual unblock requested.",
                    admin_privilege=is_admin_user(),
                    verified=True,
                    details=result.output,
                )
                return {
                    "success": True,
                    "ip": normalized_ip,
                    "message": result.output or f"IP {normalized_ip} successfully unblocked.",
                    "active_blocked_count": current_active_count,
                }
            else:
                audit_logger.log_event(
                    action="UNBLOCK",
                    target_ip=normalized_ip,
                    rule_name=rule_name,
                    status="FAILED",
                    reason=result.error or "Failed to remove firewall rule.",
                    admin_privilege=is_admin_user(),
                    verified=False,
                    details=result.error,
                )
                return {
                    "success": False,
                    "ip": normalized_ip,
                    "error": result.error or "Failed to remove firewall rule.",
                    "active_blocked_count": self.active_blocked_count,
                }

    def evaluate_and_auto_block(self, packet_data: dict) -> Optional[Dict[str, Any]]:
        """
        Evaluates a packet and automatically quarantines malicious C2 endpoints
        if auto-blocking is active and threat threshold is reached.
        Simulator-generated events do NOT increase real firewall blocked count.
        """
        if not self.auto_block_enabled:
            return None

        # Requirement 14: Simulator-generated events must NOT increase real active firewall-block count
        if packet_data.get("simulated") and not self.simulation_mode:
            return None

        sev = packet_data.get("threat_level", "INFO")
        score = packet_data.get("threat_score", 0)

        # Trigger auto-block for CRITICAL or HIGH threats, or score >= threshold
        if sev not in ("CRITICAL", "HIGH") and score < self.auto_block_score_threshold:
            return None

        dst_ip = packet_data.get("dst_ip", "")
        src_ip = packet_data.get("src_ip", "")

        # Target selection: prioritize dst_ip, fallback to src_ip
        allowed_dst, _, _ = check_block_policy(dst_ip)
        allowed_src, _, _ = check_block_policy(src_ip)

        target_ip = dst_ip if allowed_dst else (src_ip if allowed_src else None)
        if not target_ip:
            return None

        # Requirement 15: Check if already quarantined to prevent duplicate operations
        if self.is_quarantined(target_ip):
            return None

        first_reason = (packet_data.get("threat_reasons") or [f"Automated {sev} C2 Threat"])[0]
        block_reason = f"Auto-Block ({sev} - Score {score}): {first_reason}"

        admin_present = is_admin_user()
        use_sim = self.simulation_mode

        res = self.block_ip(
            target_ip,
            reason=block_reason,
            trigger_type="AUTO",
            force_simulation=use_sim,
        )
        return res

    def toggle_auto_block(self) -> bool:
        with self._lock:
            self.auto_block_enabled = not self.auto_block_enabled
            audit_logger.log_event(
                action="CONFIG_CHANGE",
                target_ip="*",
                rule_name="*",
                status="CONFIGURED",
                reason=f"Auto-block toggled to {self.auto_block_enabled}",
                admin_privilege=is_admin_user(),
            )
            return self.auto_block_enabled

    def sync_with_firewall(self) -> Dict[str, Any]:
        """Reconciles internal state with physical Windows Firewall rules."""
        with self._lock:
            try:
                active_rules = self.adapter.list_sentinel_rules()
                for rule in active_rules:
                    remote_ip = rule.get("remote_ip") or rule.get("ip")
                    rule_name = rule.get("rule_name", "")
                    if remote_ip and remote_ip not in self.quarantine_registry:
                        now = time.time()
                        self.quarantine_registry[remote_ip] = {
                            "ip": remote_ip,
                            "rule_name": rule_name,
                            "reason": "Discovered from active Windows Firewall rule",
                            "trigger_type": "SYNC",
                            "status": "ENFORCED" if not rule.get("mock") else "SIMULATED",
                            "verified": True,
                            "admin_applied": True,
                            "timestamp": round(now, 2),
                            "time_str": time.strftime("%H:%M:%S", time.localtime(now)),
                            "hit_count": 1,
                        }
                return {
                    "success": True,
                    "synced_count": len(active_rules),
                    "active_rules": active_rules,
                    "active_blocked_count": self.active_blocked_count,
                }
            except Exception as e:
                return {"success": False, "error": str(e), "active_blocked_count": self.active_blocked_count}
