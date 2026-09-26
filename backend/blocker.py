"""
C2 Sentinel - Legacy Blocker Wrapper delegating to QuarantineManager.
Preserves backwards compatibility while providing production-grade security,
validation, and firewall adapter abstraction.
"""

from typing import Dict, List, Optional, Any

try:
    from backend.quarantine_manager import QuarantineManager
    from backend.ip_validator import validate_ip, check_block_policy
    from backend.firewall_adapter import is_admin_user
except ImportError:
    from quarantine_manager import QuarantineManager
    from ip_validator import validate_ip, check_block_policy
    from firewall_adapter import is_admin_user


class C2Blocker:
    """Compatibility wrapper delegating to QuarantineManager."""

    def __init__(self, simulation_mode: bool = False, firewall_adapter: Optional[Any] = None):
        self.manager = QuarantineManager(simulation_mode=simulation_mode, firewall_adapter=firewall_adapter)

    @property
    def auto_block_enabled(self) -> bool:
        return self.manager.auto_block_enabled

    @auto_block_enabled.setter
    def auto_block_enabled(self, val: bool):
        self.manager.auto_block_enabled = bool(val)

    @property
    def is_admin(self) -> bool:
        return self.manager.is_admin()

    @property
    def blocked_ips(self) -> Dict[str, dict]:
        return self.manager.quarantine_registry

    @property
    def active_blocked_count(self) -> int:
        return self.manager.active_blocked_count

    @property
    def simulation_mode(self) -> bool:
        return self.manager.simulation_mode

    @simulation_mode.setter
    def simulation_mode(self, val: bool):
        self.manager.set_simulation_mode(val)

    def is_safe_ip(self, ip: str) -> bool:
        """
        Policy check for whether an IP can safely be blocked.
        Replaces hardcoded DNS bans with structured policy engine.
        8.8.8.8 and other public C2 targets return True.
        Loopback (127.0.0.1) and 0.0.0.0 return False.
        """
        allowed, _, _ = check_block_policy(ip)
        return allowed

    def block_ip(
        self,
        ip: str,
        reason: str = "Manual Block",
        trigger_type: str = "MANUAL",
        force_simulation: bool = False,
    ) -> dict:
        return self.manager.block_ip(
            target_ip=ip,
            reason=reason,
            trigger_type=trigger_type,
            force_simulation=force_simulation,
        )

    def unblock_ip(self, ip: str) -> dict:
        return self.manager.unblock_ip(ip)

    def is_blocked(self, ip: str) -> bool:
        return self.manager.is_quarantined(ip)

    def is_quarantined(self, ip: str) -> bool:
        return self.manager.is_quarantined(ip)

    def get_blocked_list(self) -> List[dict]:
        return self.manager.get_active_blocked_ips()

    def toggle_auto_block(self) -> bool:
        return self.manager.toggle_auto_block()

    def sync(self) -> dict:
        return self.manager.sync_with_firewall()
