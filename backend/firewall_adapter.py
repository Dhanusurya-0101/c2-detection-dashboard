"""
C2 Sentinel - Production Firewall Enforcement Adapters.
Provides hardened Windows Firewall integration via netsh and an in-memory Mock adapter for testing.
"""

import abc
import ctypes
import os
import subprocess
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any


def is_admin_user() -> bool:
    """Checks if the current Python process holds elevated Windows Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def sanitize_rule_name(ip: str) -> str:
    """Creates a deterministic, safe Windows Firewall rule name with the C2 Sentinel prefix."""
    # Replace dots, colons, brackets, slashes with underscores
    clean = (
        ip.replace(".", "_")
        .replace(":", "_")
        .replace("[", "")
        .replace("]", "")
        .replace("/", "_")
        .strip()
    )
    return f"C2_SENTINEL_BLOCK_{clean}"


@dataclass
class FirewallResult:
    success: bool
    ip: str
    rule_name: str
    action: str  # "BLOCK", "UNBLOCK", "VERIFY"
    verified: bool
    status: str  # "ENFORCED", "SIMULATED", "FAILED", "REMOVED"
    error: Optional[str] = None
    output: Optional[str] = None
    execution_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FirewallAdapter(abc.ABC):
    """Abstract base class for C2 Sentinel firewall enforcement."""

    @abc.abstractmethod
    def block_ip(self, ip: str, direction: str = "out") -> FirewallResult:
        """Blocks an IP address at the firewall layer."""
        pass

    @abc.abstractmethod
    def unblock_ip(self, ip: str) -> FirewallResult:
        """Removes the firewall blocking rule for the given IP."""
        pass

    @abc.abstractmethod
    def verify_rule(self, rule_name: str) -> bool:
        """Verifies if the specified rule physically exists in the firewall."""
        pass

    @abc.abstractmethod
    def is_blocked(self, ip: str) -> bool:
        """Checks if the given IP is actively blocked in the firewall."""
        pass

    @abc.abstractmethod
    def list_sentinel_rules(self) -> List[Dict[str, Any]]:
        """Lists all active C2 Sentinel rules."""
        pass


class WindowsFirewallAdapter(FirewallAdapter):
    """
    Production Windows Firewall adapter utilizing netsh.exe with strictly parameterized argument lists.
    Guarantees no shell=True usage and enforces strict post-execution rule verification.
    """

    NETSH_EXE = "netsh.exe"

    def __init__(self):
        self.is_admin = is_admin_user()

    def block_ip(self, ip: str, direction: str = "out") -> FirewallResult:
        rule_name = sanitize_rule_name(ip)

        # 1. Enforce Administrator privilege check
        if not is_admin_user():
            return FirewallResult(
                success=False,
                ip=ip,
                rule_name=rule_name,
                action="BLOCK",
                verified=False,
                status="FAILED",
                error="Administrator privileges are required to modify Windows Firewall rules. Please run Python as Administrator.",
            )

        # 2. Check if rule already exists (idempotency)
        if self.verify_rule(rule_name):
            return FirewallResult(
                success=True,
                ip=ip,
                rule_name=rule_name,
                action="BLOCK",
                verified=True,
                status="ENFORCED",
                output=f"Windows Firewall rule '{rule_name}' already exists and is active.",
            )

        # 3. Execute netsh add rule without shell=True
        # Command: netsh advfirewall firewall add rule name="<rule>" dir=<direction> action=block remoteip=<ip>
        args = [
            self.NETSH_EXE,
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            f"dir={direction}",
            "action=block",
            f"remoteip={ip}",
        ]

        try:
            res = subprocess.run(
                args,
                shell=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            raw_output = (res.stdout or "") + (res.stderr or "")

            if res.returncode != 0:
                return FirewallResult(
                    success=False,
                    ip=ip,
                    rule_name=rule_name,
                    action="BLOCK",
                    verified=False,
                    status="FAILED",
                    error=f"Firewall command failed (code {res.returncode}): {raw_output.strip()}",
                    output=raw_output.strip(),
                )

            # 4. Mandatory post-execution verification
            is_verified = self.verify_rule(rule_name)
            if not is_verified:
                return FirewallResult(
                    success=False,
                    ip=ip,
                    rule_name=rule_name,
                    action="BLOCK",
                    verified=False,
                    status="FAILED",
                    error="Command succeeded but firewall rule could not be verified in netsh query.",
                    output=raw_output.strip(),
                )

            return FirewallResult(
                success=True,
                ip=ip,
                rule_name=rule_name,
                action="BLOCK",
                verified=True,
                status="ENFORCED",
                output=raw_output.strip() or "Rule added and verified successfully.",
            )

        except subprocess.TimeoutExpired:
            return FirewallResult(
                success=False,
                ip=ip,
                rule_name=rule_name,
                action="BLOCK",
                verified=False,
                status="FAILED",
                error="Timed out executing netsh command.",
            )
        except Exception as e:
            return FirewallResult(
                success=False,
                ip=ip,
                rule_name=rule_name,
                action="BLOCK",
                verified=False,
                status="FAILED",
                error=f"Unexpected error executing netsh: {str(e)}",
            )

    def unblock_ip(self, ip: str) -> FirewallResult:
        rule_name = sanitize_rule_name(ip)

        # Safety check: enforce rule naming prefix to never delete non-Sentinel rules
        if not rule_name.startswith("C2_SENTINEL_BLOCK_"):
            return FirewallResult(
                success=False,
                ip=ip,
                rule_name=rule_name,
                action="UNBLOCK",
                verified=False,
                status="FAILED",
                error="Refusing to delete rule without C2_SENTINEL_BLOCK_ prefix.",
            )

        if not is_admin_user():
            return FirewallResult(
                success=False,
                ip=ip,
                rule_name=rule_name,
                action="UNBLOCK",
                verified=False,
                status="FAILED",
                error="Administrator privileges are required to delete Windows Firewall rules.",
            )

        args = [
            self.NETSH_EXE,
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            f"name={rule_name}",
        ]

        try:
            res = subprocess.run(
                args,
                shell=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            raw_output = (res.stdout or "") + (res.stderr or "")

            # Verify deletion
            still_exists = self.verify_rule(rule_name)
            if still_exists:
                return FirewallResult(
                    success=False,
                    ip=ip,
                    rule_name=rule_name,
                    action="UNBLOCK",
                    verified=False,
                    status="FAILED",
                    error="Rule still exists after delete command executed.",
                    output=raw_output.strip(),
                )

            return FirewallResult(
                success=True,
                ip=ip,
                rule_name=rule_name,
                action="UNBLOCK",
                verified=True,
                status="REMOVED",
                output=raw_output.strip() or "Rule deleted successfully.",
            )

        except subprocess.TimeoutExpired:
            return FirewallResult(
                success=False,
                ip=ip,
                rule_name=rule_name,
                action="UNBLOCK",
                verified=False,
                status="FAILED",
                error="Timed out executing netsh delete command.",
            )
        except Exception as e:
            return FirewallResult(
                success=False,
                ip=ip,
                rule_name=rule_name,
                action="UNBLOCK",
                verified=False,
                status="FAILED",
                error=f"Unexpected error deleting netsh rule: {str(e)}",
            )

    def verify_rule(self, rule_name: str) -> bool:
        """Runs 'netsh advfirewall firewall show rule name=...' and checks existence."""
        args = [
            self.NETSH_EXE,
            "advfirewall",
            "firewall",
            "show",
            "rule",
            f"name={rule_name}",
        ]
        try:
            res = subprocess.run(
                args,
                shell=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if res.returncode != 0:
                return False

            out = res.stdout.lower()
            if "no rules match" in out or "rule name:" not in out:
                return False

            return True
        except Exception:
            return False

    def is_blocked(self, ip: str) -> bool:
        rule_name = sanitize_rule_name(ip)
        return self.verify_rule(rule_name)

    def list_sentinel_rules(self) -> List[Dict[str, Any]]:
        """Parses all active rules created with the C2_SENTINEL_BLOCK_ prefix."""
        args = [
            self.NETSH_EXE,
            "advfirewall",
            "firewall",
            "show",
            "rule",
            "name=all",
        ]
        results = []
        try:
            res = subprocess.run(
                args,
                shell=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if res.returncode != 0:
                return []

            current_rule: Dict[str, Any] = {}
            for line in res.stdout.splitlines():
                line = line.strip()
                if not line:
                    if current_rule and current_rule.get("rule_name", "").startswith("C2_SENTINEL_BLOCK_"):
                        results.append(current_rule)
                    current_rule = {}
                    continue

                if ":" in line:
                    k, v = line.split(":", 1)
                    k = k.strip().lower()
                    v = v.strip()
                    if k in ("rule name", "name"):
                        current_rule["rule_name"] = v
                    elif k in ("remoteip", "remote ip"):
                        current_rule["remote_ip"] = v
                    elif k in ("direction", "dir"):
                        current_rule["direction"] = v
                    elif k in ("action",):
                        current_rule["action"] = v
                    elif k in ("enabled",):
                        current_rule["enabled"] = v

            if current_rule and current_rule.get("rule_name", "").startswith("C2_SENTINEL_BLOCK_"):
                results.append(current_rule)

        except Exception:
            pass
        return results


class MockFirewallAdapter(FirewallAdapter):
    """
    In-memory mock firewall adapter for unit testing, non-admin environments, and simulation mode.
    Maintains an in-memory rule dictionary and allows controlled failure injection.
    """

    def __init__(self, simulate_failure: bool = False, failure_message: str = "Simulated firewall error"):
        self.mock_rules: Dict[str, Dict[str, Any]] = {}
        self.simulate_failure = simulate_failure
        self.failure_message = failure_message

    def block_ip(self, ip: str, direction: str = "out") -> FirewallResult:
        rule_name = sanitize_rule_name(ip)

        if self.simulate_failure:
            return FirewallResult(
                success=False,
                ip=ip,
                rule_name=rule_name,
                action="BLOCK",
                verified=False,
                status="FAILED",
                error=self.failure_message,
            )

        self.mock_rules[rule_name] = {
            "rule_name": rule_name,
            "ip": ip,
            "direction": direction,
            "action": "block",
            "enabled": True,
            "mock": True,
        }

        return FirewallResult(
            success=True,
            ip=ip,
            rule_name=rule_name,
            action="BLOCK",
            verified=True,
            status="SIMULATED",
            output=f"Mock rule '{rule_name}' applied in simulation mode.",
        )

    def unblock_ip(self, ip: str) -> FirewallResult:
        rule_name = sanitize_rule_name(ip)

        if self.simulate_failure:
            return FirewallResult(
                success=False,
                ip=ip,
                rule_name=rule_name,
                action="UNBLOCK",
                verified=False,
                status="FAILED",
                error=self.failure_message,
            )

        if rule_name in self.mock_rules:
            del self.mock_rules[rule_name]
            return FirewallResult(
                success=True,
                ip=ip,
                rule_name=rule_name,
                action="UNBLOCK",
                verified=True,
                status="REMOVED",
                output=f"Mock rule '{rule_name}' deleted.",
            )

        return FirewallResult(
            success=False,
            ip=ip,
            rule_name=rule_name,
            action="UNBLOCK",
            verified=False,
            status="FAILED",
            error=f"Mock rule '{rule_name}' not found.",
        )

    def verify_rule(self, rule_name: str) -> bool:
        return rule_name in self.mock_rules

    def is_blocked(self, ip: str) -> bool:
        rule_name = sanitize_rule_name(ip)
        return rule_name in self.mock_rules

    def list_sentinel_rules(self) -> List[Dict[str, Any]]:
        return list(self.mock_rules.values())
