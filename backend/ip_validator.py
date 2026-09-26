"""
C2 Sentinel - IP Address Validation & Enforcement Policy Engine.
Validates, extracts, normalizes, and classifies IPv4 and IPv6 network targets.
"""

import ipaddress
import re
from typing import Optional, Tuple, Dict, Any


def parse_target(target: str) -> Tuple[str, Optional[int]]:
    """
    Extracts clean IP address and optional port from input target strings.
    Handles:
      - Plain IPv4: "192.168.1.50" -> ("192.168.1.50", None)
      - IPv4 with Port: "192.168.1.50:8080" -> ("192.168.1.50", 8080)
      - Plain IPv6: "2001:db8::1" -> ("2001:db8::1", None)
      - Bracketed IPv6 with Port: "[2001:db8::1]:8080" -> ("2001:db8::1", 8080)
      - Bracketed IPv6: "[2001:db8::1]" -> ("2001:db8::1", None)
      - Hostnames / special: "localhost" -> ("127.0.0.1", None)
    """
    if not target or not isinstance(target, str):
        return ("", None)

    cleaned = target.strip()

    # Handle localhost alias
    if cleaned.lower() in ("localhost", "localhost:80", "localhost:8000"):
        parts = cleaned.split(":")
        port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        return ("127.0.0.1", port)

    # 1. Bracketed IPv6: [2001:db8::1]:port or [2001:db8::1]
    bracket_match = re.match(r"^\[([a-fA-F0-9:]+)\](?::(\d{1,5}))?$", cleaned)
    if bracket_match:
        ip_part = bracket_match.group(1)
        port_part = bracket_match.group(2)
        port = int(port_part) if port_part and (0 < int(port_part) <= 65535) else None
        return (ip_part, port)

    # 2. IPv4 with port: 1.2.3.4:8080
    if ":" in cleaned:
        colon_count = cleaned.count(":")
        if colon_count == 1:
            parts = cleaned.rsplit(":", 1)
            if parts[1].isdigit() and (0 < int(parts[1]) <= 65535):
                return (parts[0], int(parts[1]))
            return (parts[0], None)
        # Multiple colons without brackets -> likely plain IPv6
        return (cleaned, None)

    return (cleaned, None)


def validate_ip(raw_target: str) -> Dict[str, Any]:
    """
    Validates and classifies an IP target string.
    Returns structured metadata including normalized IP, version, and address scopes.
    """
    ip_str, port = parse_target(raw_target)

    if not ip_str:
        return {
            "valid": False,
            "ip": "",
            "port": None,
            "version": None,
            "is_loopback": False,
            "is_private": False,
            "is_global": False,
            "is_multicast": False,
            "is_link_local": False,
            "is_unspecified": False,
            "is_reserved": False,
            "error": "Target IP string is empty or invalid.",
        }

    try:
        ip_obj = ipaddress.ip_address(ip_str)
        normalized_ip = str(ip_obj)

        return {
            "valid": True,
            "ip": normalized_ip,
            "port": port,
            "version": ip_obj.version,
            "is_loopback": ip_obj.is_loopback,
            "is_private": ip_obj.is_private,
            "is_global": ip_obj.is_global,
            "is_multicast": ip_obj.is_multicast,
            "is_link_local": ip_obj.is_link_local,
            "is_unspecified": ip_obj.is_unspecified,
            "is_reserved": ip_obj.is_reserved,
            "error": None,
        }
    except ValueError as e:
        return {
            "valid": False,
            "ip": ip_str,
            "port": port,
            "version": None,
            "is_loopback": False,
            "is_private": False,
            "is_global": False,
            "is_multicast": False,
            "is_link_local": False,
            "is_unspecified": False,
            "is_reserved": False,
            "error": f"Invalid IP address syntax: '{ip_str}' ({str(e)})",
        }


def check_block_policy(raw_target: str, protected_dns: bool = False) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Applies Sentinel firewall safety policies before any rule creation.
    Returns:
      (allowed: bool, reason_or_error: str, validation_meta: dict)

    Rules:
      1. Must be a syntactically valid IPv4 or IPv6 address.
      2. Loopback (127.0.0.0/8, ::1) is BLOCKED from quarantine (safety policy).
      3. Unspecified (0.0.0.0, ::) is BLOCKED from quarantine.
      4. Multicast & Link-local are BLOCKED from quarantine.
      5. Public IPs (e.g. 8.8.8.8, 203.0.113.88) are VALID targets.
      6. Private IPs (10.x, 192.168.x, 172.16-31.x) are VALID targets (internal rogue C2 beaconing).
    """
    meta = validate_ip(raw_target)

    if not meta["valid"]:
        return (False, meta["error"] or f"Invalid IP address format: '{raw_target}'", meta)

    ip = meta["ip"]

    if meta["is_loopback"]:
        return (
            False,
            f"Blocking loopback address '{ip}' is disabled by safety policy to prevent host deadlock.",
            meta,
        )

    if meta["is_unspecified"]:
        return (
            False,
            f"Blocking unspecified address '{ip}' (0.0.0.0 / ::) is prohibited by policy.",
            meta,
        )

    if meta["is_multicast"]:
        return (
            False,
            f"Blocking multicast address '{ip}' is prohibited by policy.",
            meta,
        )

    if meta["is_link_local"]:
        return (
            False,
            f"Blocking link-local address '{ip}' is prohibited by policy.",
            meta,
        )

    if protected_dns and ip in ("8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"):
        return (
            False,
            f"IP '{ip}' is protected by optional DNS infrastructure whitelist policy.",
            meta,
        )

    return (True, "Target IP passed all safety and format checks.", meta)
