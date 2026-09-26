"""
C2 Sentinel - Automated Test Suite for Blocking & Quarantine Architecture.
Covers all 20 required validation, adapter, quarantine manager, audit logging,
and security enforcement scenarios without modifying external infrastructure.
"""

import os
import sys
import unittest
import json
import tempfile
import io
from contextlib import redirect_stdout
from unittest.mock import patch, MagicMock

# Add project root and backend to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from backend.ip_validator import parse_target, validate_ip, check_block_policy
from backend.firewall_adapter import (
    FirewallAdapter,
    WindowsFirewallAdapter,
    MockFirewallAdapter,
    FirewallResult,
    sanitize_rule_name,
    is_admin_user,
)
from backend.quarantine_manager import QuarantineManager
from backend.audit_logger import EnforcementAuditLogger
from backend.blocker import C2Blocker


class TestIPValidationAndPolicy(unittest.TestCase):
    """Test Scenarios 1 - 10: IP Validation & Security Policies"""

    def test_01_ipv4_validation_public(self):
        """Scenario 1: Valid public IPv4 classification and policy acceptance."""
        res = validate_ip("93.184.216.34")
        self.assertTrue(res["valid"])
        self.assertEqual(res["ip"], "93.184.216.34")
        self.assertEqual(res["version"], 4)
        self.assertTrue(res["is_global"])
        self.assertFalse(res["is_loopback"])
        self.assertIsNone(res["error"])

        allowed, msg, _ = check_block_policy("93.184.216.34")
        self.assertTrue(allowed)
        self.assertIn("passed", msg.lower())

    def test_02_8_8_8_8_specifically_not_rejected(self):
        """Scenario 2: 8.8.8.8 is a valid public IPv4 and NOT rejected as loopback or invalid."""
        res = validate_ip("8.8.8.8")
        self.assertTrue(res["valid"])
        self.assertEqual(res["ip"], "8.8.8.8")
        self.assertFalse(res["is_loopback"])
        self.assertTrue(res["is_global"])

        allowed, msg, meta = check_block_policy("8.8.8.8")
        self.assertTrue(allowed, f"8.8.8.8 was unexpectedly rejected: {msg}")
        self.assertFalse(meta["is_loopback"])
        self.assertNotIn("loopback", msg.lower())

    def test_03_ipv4_with_port_extraction(self):
        """Scenario 3: IPv4 with port correctly extracts port and normalizes IP."""
        ip, port = parse_target("192.168.1.50:8080")
        self.assertEqual(ip, "192.168.1.50")
        self.assertEqual(port, 8080)

        meta = validate_ip("192.168.1.50:8080")
        self.assertTrue(meta["valid"])
        self.assertEqual(meta["ip"], "192.168.1.50")
        self.assertEqual(meta["port"], 8080)

        allowed, _, _ = check_block_policy("192.168.1.50:8080")
        self.assertTrue(allowed)

    def test_04_ipv6_validation(self):
        """Scenario 4: Valid IPv6 address parsing and classification."""
        meta = validate_ip("2001:db8::1")
        self.assertTrue(meta["valid"])
        self.assertEqual(meta["ip"], "2001:db8::1")
        self.assertEqual(meta["version"], 6)
        self.assertFalse(meta["is_loopback"])

        allowed, msg, _ = check_block_policy("2001:db8::1")
        self.assertTrue(allowed)

    def test_05_ipv6_bracketed_with_port(self):
        """Scenario 5: Bracketed IPv6 with port [2001:db8::1]:8080."""
        ip, port = parse_target("[2001:db8::1]:8080")
        self.assertEqual(ip, "2001:db8::1")
        self.assertEqual(port, 8080)

        meta = validate_ip("[2001:db8::1]:8080")
        self.assertTrue(meta["valid"])
        self.assertEqual(meta["ip"], "2001:db8::1")
        self.assertEqual(meta["port"], 8080)

    def test_06_loopback_prohibited_by_policy(self):
        """Scenario 6: Loopback (127.0.0.1 and ::1) must be rejected with clear safety message."""
        for target in ("127.0.0.1", "127.0.0.50", "::1", "localhost", "127.0.0.1:8000"):
            allowed, msg, meta = check_block_policy(target)
            self.assertFalse(allowed, f"Loopback target {target} was incorrectly allowed")
            self.assertTrue(meta["is_loopback"])
            self.assertIn("loopback", msg.lower())

    def test_07_unspecified_address_prohibited(self):
        """Scenario 7: 0.0.0.0 and :: are rejected by policy."""
        for target in ("0.0.0.0", "::", "0.0.0.0:80"):
            allowed, msg, meta = check_block_policy(target)
            self.assertFalse(allowed, f"Unspecified target {target} was incorrectly allowed")
            self.assertTrue(meta["is_unspecified"])
            self.assertIn("unspecified", msg.lower())

    def test_08_multicast_address_prohibited(self):
        """Scenario 8: Multicast addresses (224.0.0.1, ff02::1) are rejected."""
        for target in ("224.0.0.1", "239.255.255.250", "ff02::1"):
            allowed, msg, meta = check_block_policy(target)
            self.assertFalse(allowed, f"Multicast target {target} was incorrectly allowed")
            self.assertTrue(meta["is_multicast"])
            self.assertIn("multicast", msg.lower())

    def test_09_link_local_address_prohibited(self):
        """Scenario 9: Link-local addresses (169.254.1.1, fe80::1) are rejected."""
        for target in ("169.254.1.1", "fe80::1"):
            allowed, msg, meta = check_block_policy(target)
            self.assertFalse(allowed, f"Link-local target {target} was incorrectly allowed")
            self.assertTrue(meta["is_link_local"])
            self.assertIn("link-local", msg.lower())

    def test_10_invalid_ip_format(self):
        """Scenario 10: Malformed IP strings are rejected cleanly."""
        for bad in ("invalid_ip", "999.999.999.999", "1.2.3.4.5", "http://c2.com", ""):
            meta = validate_ip(bad)
            self.assertFalse(meta["valid"])
            allowed, msg, _ = check_block_policy(bad)
            self.assertFalse(allowed)
            self.assertIn("invalid", msg.lower())


class TestFirewallAdapters(unittest.TestCase):
    """Test Scenarios 11 - 16: Firewall Adapter Implementations"""

    def test_11_rule_naming_convention(self):
        """Scenario 11: Rule names adhere strictly to C2_SENTINEL_BLOCK_<clean_ip>."""
        self.assertEqual(sanitize_rule_name("203.0.113.88"), "C2_SENTINEL_BLOCK_203_0_113_88")
        self.assertEqual(sanitize_rule_name("8.8.8.8"), "C2_SENTINEL_BLOCK_8_8_8_8")
        self.assertEqual(sanitize_rule_name("2001:db8::1"), "C2_SENTINEL_BLOCK_2001_db8__1")
        self.assertTrue(sanitize_rule_name("10.0.0.1").startswith("C2_SENTINEL_BLOCK_"))

    def test_12_mock_firewall_adapter_block_and_verify(self):
        """Scenario 12: MockFirewallAdapter blocks, verifies, and reports SIMULATED status."""
        adapter = MockFirewallAdapter()
        res = adapter.block_ip("203.0.113.88")

        self.assertTrue(res.success)
        self.assertTrue(res.verified)
        self.assertEqual(res.status, "SIMULATED")
        self.assertEqual(res.rule_name, "C2_SENTINEL_BLOCK_203_0_113_88")
        self.assertTrue(adapter.verify_rule("C2_SENTINEL_BLOCK_203_0_113_88"))
        self.assertTrue(adapter.is_blocked("203.0.113.88"))

    def test_13_mock_firewall_adapter_unblock(self):
        """Scenario 13: MockFirewallAdapter unblocks and removes rule from registry."""
        adapter = MockFirewallAdapter()
        adapter.block_ip("203.0.113.88")
        self.assertTrue(adapter.is_blocked("203.0.113.88"))

        unblock_res = adapter.unblock_ip("203.0.113.88")
        self.assertTrue(unblock_res.success)
        self.assertEqual(unblock_res.status, "REMOVED")
        self.assertFalse(adapter.verify_rule("C2_SENTINEL_BLOCK_203_0_113_88"))
        self.assertFalse(adapter.is_blocked("203.0.113.88"))

    def test_14_mock_firewall_failure_injection(self):
        """Scenario 14: MockFirewallAdapter injects failure and returns structured error."""
        adapter = MockFirewallAdapter(simulate_failure=True, failure_message="Simulated netsh timeout")
        res = adapter.block_ip("203.0.113.88")

        self.assertFalse(res.success)
        self.assertFalse(res.verified)
        self.assertEqual(res.status, "FAILED")
        self.assertIn("Simulated netsh timeout", res.error)

    @patch("subprocess.run")
    @patch("backend.firewall_adapter.is_admin_user", return_value=True)
    def test_15_windows_firewall_command_no_shell_true(self, mock_admin, mock_subproc):
        """Scenario 15: WindowsFirewallAdapter uses argument lists and never shell=True."""
        # Mock successful subprocess execution
        mock_subproc.return_value = MagicMock(returncode=0, stdout="Rule Name: C2_SENTINEL_BLOCK_8_8_8_8\nOk.", stderr="")

        adapter = WindowsFirewallAdapter()
        res = adapter.block_ip("8.8.8.8")

        # Verify subprocess.run calls
        self.assertGreaterEqual(mock_subproc.call_count, 1)
        for call_args, call_kwargs in mock_subproc.call_args_list:
            # Must NOT use shell=True
            self.assertFalse(call_kwargs.get("shell", False), "WindowsFirewallAdapter used shell=True!")
            # Arguments must be a list
            args = call_args[0]
            self.assertIsInstance(args, list, "Command arguments must be passed as an array/list")
            self.assertEqual(args[0], "netsh.exe")
            self.assertIn("advfirewall", args)
            self.assertIn("firewall", args)

    @patch("backend.firewall_adapter.is_admin_user", return_value=False)
    def test_16_non_admin_elevation_error(self, mock_admin):
        """Scenario 16: Non-admin run returns clear elevation required error and fails cleanly."""
        adapter = WindowsFirewallAdapter()
        res = adapter.block_ip("8.8.8.8")

        self.assertFalse(res.success)
        self.assertEqual(res.status, "FAILED")
        self.assertFalse(res.verified)
        self.assertIn("Administrator privileges are required", res.error)


class TestQuarantineManagerAndState(unittest.TestCase):
    """Test Scenarios 17 - 20: Quarantine Lifecycle, Auto-block, Idempotency, and Audit Logs"""

    def test_17_quarantine_manager_state_transitions(self):
        """Scenario 17: Quarantine state machine transitions PENDING_BLOCK -> SIMULATED -> UNBLOCKED."""
        mock_adapter = MockFirewallAdapter()
        manager = QuarantineManager(firewall_adapter=mock_adapter, simulation_mode=True)

        # 1. Block
        res = manager.block_ip("203.0.113.88", reason="C2 Beacon Test", trigger_type="MANUAL")
        self.assertTrue(res["success"])
        record = res["record"]
        self.assertEqual(record["status"], "SIMULATED")
        self.assertEqual(record["ip"], "203.0.113.88")
        self.assertTrue(manager.is_quarantined("203.0.113.88"))

        # Verify in quarantined list
        q_list = manager.get_quarantined_list()
        self.assertEqual(len(q_list), 1)
        self.assertEqual(q_list[0]["ip"], "203.0.113.88")

        # 2. Unblock
        un_res = manager.unblock_ip("203.0.113.88")
        self.assertTrue(un_res["success"])
        self.assertFalse(manager.is_quarantined("203.0.113.88"))
        self.assertEqual(len(manager.get_quarantined_list()), 0)

    def test_18_quarantine_manager_auto_block(self):
        """Scenario 18: Auto-block triggers on CRITICAL/HIGH threats and ignores benign traffic."""
        mock_adapter = MockFirewallAdapter()
        manager = QuarantineManager(firewall_adapter=mock_adapter, simulation_mode=True, auto_block_enabled=True)

        # Benign packet: should NOT be blocked
        benign_pkt = {
            "src_ip": "192.168.1.100",
            "dst_ip": "93.184.216.34",
            "threat_level": "INFO",
            "threat_score": 10,
        }
        res_benign = manager.evaluate_and_auto_block(benign_pkt)
        self.assertIsNone(res_benign)
        self.assertFalse(manager.is_quarantined("93.184.216.34"))

        # Critical threat packet: SHOULD be automatically quarantined
        crit_pkt = {
            "src_ip": "192.168.1.100",
            "dst_ip": "198.51.100.99",
            "threat_level": "CRITICAL",
            "threat_score": 95,
            "threat_reasons": ["Direct IP HTTP Beaconing", "Low Jitter Beacon"],
        }
        res_crit = manager.evaluate_and_auto_block(crit_pkt)
        self.assertIsNotNone(res_crit)
        self.assertTrue(res_crit["success"])
        self.assertTrue(manager.is_quarantined("198.51.100.99"))
        self.assertEqual(res_crit["record"]["trigger_type"], "AUTO")

    def test_19_quarantine_manager_idempotency(self):
        """Scenario 19: Blocking an already quarantined IP succeeds idempotently without corruption."""
        mock_adapter = MockFirewallAdapter()
        manager = QuarantineManager(firewall_adapter=mock_adapter, simulation_mode=True)

        # First block
        res1 = manager.block_ip("203.0.113.50", reason="Initial Block")
        self.assertTrue(res1["success"])
        self.assertEqual(res1["record"]["hit_count"], 1)

        # Second block for same IP
        res2 = manager.block_ip("203.0.113.50", reason="Second Block")
        self.assertTrue(res2["success"])
        self.assertEqual(res2["record"]["hit_count"], 2)

        # Total quarantined entries must remain 1
        q_list = manager.get_quarantined_list()
        self.assertEqual(len(q_list), 1)

    def test_20_audit_logger_records_enforcement(self):
        """Scenario 20: Audit logger writes structured JSON records for all actions."""
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".log") as tmp_file:
            tmp_log_path = tmp_file.name

        try:
            logger = EnforcementAuditLogger(log_path=tmp_log_path)

            # Log a BLOCK event
            logger.log_event(
                action="BLOCK",
                target_ip="8.8.8.8",
                rule_name="C2_SENTINEL_BLOCK_8_8_8_8",
                status="ENFORCED",
                trigger_type="MANUAL",
                reason="Malicious C2 DNS Beaconing",
                admin_privilege=True,
                verified=True,
            )

            # Log an UNBLOCK event
            logger.log_event(
                action="UNBLOCK",
                target_ip="8.8.8.8",
                rule_name="C2_SENTINEL_BLOCK_8_8_8_8",
                status="REMOVED",
                trigger_type="MANUAL",
                reason="Analyst triage complete",
                admin_privilege=True,
                verified=True,
            )

            # Verify contents of log file
            recent = logger.get_recent_logs(10)
            self.assertEqual(len(recent), 2)

            unblock_entry = recent[0]
            self.assertEqual(unblock_entry["action"], "UNBLOCK")
            self.assertEqual(unblock_entry["target_ip"], "8.8.8.8")
            self.assertEqual(unblock_entry["status"], "REMOVED")

            block_entry = recent[1]
            self.assertEqual(block_entry["action"], "BLOCK")
            self.assertEqual(block_entry["target_ip"], "8.8.8.8")
            self.assertEqual(block_entry["status"], "ENFORCED")
            self.assertTrue(block_entry["verified"])
            self.assertTrue(block_entry["admin_privilege"])

        finally:
            if os.path.exists(tmp_log_path):
                os.remove(tmp_log_path)


class TestAuthoritativeBlockedCountSynchronization(unittest.TestCase):
    """
    Test Scenarios 21 - 29: Authoritative Single-Source-of-Truth Blocked Count Synchronization.
    Verifies user-specified tests:
    - Test 1: Block IP A -> count becomes 1
    - Test 2: Block IP A again -> count stays 1 (idempotency, hit_count increments)
    - Test 3: Block IP B -> count becomes 2
    - Test 4: Unblock IP A -> count becomes 1
    - Test 5: Refresh dashboard -> count remains 1
    - Test 6: Simulator detections do not increase real active firewall blocked count
    - Port stripping & IP normalization preserves single count
    - Failed blocks do not increment active blocked count
    - Structured logging BLOCK ADD and BLOCK REMOVE
    """

    def setUp(self):
        self.mock_adapter = MockFirewallAdapter()
        # Initialize blocker in simulation mode for deterministic testing without elevation
        self.blocker = C2Blocker(firewall_adapter=self.mock_adapter, simulation_mode=True)

    def test_21_scenario_1_block_a(self):
        """Test 1: Block IP A -> count becomes 1."""
        res = self.blocker.block_ip("198.51.100.10", reason="Test C2 beacon")
        self.assertTrue(res["success"])
        self.assertEqual(self.blocker.active_blocked_count, 1)
        self.assertEqual(len(self.blocker.get_blocked_list()), 1)
        self.assertEqual(self.blocker.get_blocked_list()[0]["ip"], "198.51.100.10")

    def test_22_scenario_2_block_a_again_idempotent(self):
        """Test 2: Block IP A again -> count stays 1 (duplicate block never increments count)."""
        res1 = self.blocker.block_ip("198.51.100.10", reason="First Detection")
        self.assertTrue(res1["success"])
        self.assertEqual(self.blocker.active_blocked_count, 1)

        # Block same IP again
        res2 = self.blocker.block_ip("198.51.100.10", reason="Second Detection")
        self.assertTrue(res2["success"])
        self.assertEqual(self.blocker.active_blocked_count, 1)
        self.assertEqual(len(self.blocker.get_blocked_list()), 1)
        # Verify hit count incremented
        self.assertEqual(res2["record"]["hit_count"], 2)

    def test_23_scenario_3_block_b_increments(self):
        """Test 3: Block IP B -> count becomes 2."""
        self.blocker.block_ip("198.51.100.10", reason="C2 host A")
        self.assertEqual(self.blocker.active_blocked_count, 1)

        res_b = self.blocker.block_ip("198.51.100.20", reason="C2 host B")
        self.assertTrue(res_b["success"])
        self.assertEqual(self.blocker.active_blocked_count, 2)
        self.assertEqual(len(self.blocker.get_blocked_list()), 2)

    def test_24_scenario_4_unblock_a_decrements(self):
        """Test 4: Unblock IP A -> count becomes 1."""
        self.blocker.block_ip("198.51.100.10", reason="C2 host A")
        self.blocker.block_ip("198.51.100.20", reason="C2 host B")
        self.assertEqual(self.blocker.active_blocked_count, 2)

        res_unblock = self.blocker.unblock_ip("198.51.100.10")
        self.assertTrue(res_unblock["success"])
        self.assertEqual(self.blocker.active_blocked_count, 1)
        active_list = self.blocker.get_blocked_list()
        self.assertEqual(len(active_list), 1)
        self.assertEqual(active_list[0]["ip"], "198.51.100.20")

    def test_25_scenario_5_refresh_dashboard_state(self):
        """Test 5: Refresh dashboard -> count remains 1 from authoritative backend."""
        self.blocker.block_ip("198.51.100.10", reason="C2 host A")
        self.blocker.block_ip("198.51.100.20", reason="C2 host B")
        self.blocker.unblock_ip("198.51.100.10")

        # Simulate fresh API / dashboard reload calls
        count_from_property = self.blocker.active_blocked_count
        list_from_manager = self.blocker.get_blocked_list()
        count_from_list = len(list_from_manager)

        self.assertEqual(count_from_property, 1)
        self.assertEqual(count_from_list, 1)
        self.assertEqual(list_from_manager[0]["ip"], "198.51.100.20")

    def test_26_scenario_6_simulator_isolation_real_firewall_mode(self):
        """Test 6: Simulator detections do not increase real active firewall blocked count."""
        # Real firewall mode without admin
        real_blocker = C2Blocker(simulation_mode=False)
        self.assertEqual(real_blocker.active_blocked_count, 0)

        # Simulated packet with high threat score
        sim_packet = {
            "src_ip": "192.168.1.100",
            "dst_ip": "198.51.100.99",
            "threat_level": "CRITICAL",
            "threat_score": 99,
            "threat_reasons": ["Simulated Cobalt Strike Beacon"],
            "simulated": True,  # Generated by simulator.py
        }

        # Auto-block evaluation in real mode must reject/ignore simulated packet
        auto_res = real_blocker.manager.evaluate_and_auto_block(sim_packet)
        self.assertIsNone(auto_res, "Simulator-generated packet was not ignored in real mode!")
        self.assertEqual(real_blocker.active_blocked_count, 0)
        self.assertFalse(real_blocker.is_quarantined("198.51.100.99"))

    def test_27_ip_normalization_with_port(self):
        """Normalization: 192.168.1.50 and 192.168.1.50:443 must not count as two different IPs."""
        res1 = self.blocker.block_ip("192.168.1.50")
        self.assertTrue(res1["success"])
        self.assertEqual(self.blocker.active_blocked_count, 1)

        res2 = self.blocker.block_ip("192.168.1.50:443")
        self.assertTrue(res2["success"])
        self.assertEqual(self.blocker.active_blocked_count, 1)
        self.assertEqual(len(self.blocker.get_blocked_list()), 1)
        self.assertEqual(res2["record"]["ip"], "192.168.1.50")

    def test_28_failed_block_does_not_increment_active_count(self):
        """Policy rejection or failed block does not increment active_blocked_count."""
        # Loopback is rejected by policy
        res = self.blocker.block_ip("127.0.0.1")
        self.assertFalse(res["success"])
        self.assertEqual(res["code"], "POLICY_REJECTED")
        self.assertEqual(self.blocker.active_blocked_count, 0)

    def test_29_structured_logging_output(self):
        """Structured logging output on block add and remove."""
        stdout_buf = io.StringIO()
        with redirect_stdout(stdout_buf):
            self.blocker.block_ip("198.51.100.77", reason="Test Log")
            self.blocker.unblock_ip("198.51.100.77")

        output = stdout_buf.getvalue()
        self.assertIn("BLOCK ADD:\nIP=198.51.100.77\nactive_count=1", output)
        self.assertIn("BLOCK REMOVE:\nIP=198.51.100.77\nactive_count=0", output)


if __name__ == "__main__":
    unittest.main()
