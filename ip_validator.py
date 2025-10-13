#!/usr/bin/env python3
"""
Secure IP Validation Module

This module provides a secure IP validation implementation using the standard
ipaddress library instead of cidr_man. It includes all the security fixes
and can be used as a drop-in replacement.

Migration from cidr_man to ipaddress standard library.
"""

import ipaddress
from typing import Union, Optional

def validate_ip_secure(ip_str: str) -> bool:
    """
    Validate IP address and block all dangerous ranges.

    This is a secure replacement for cidr_man based validation.
    Uses Python's standard ipaddress library with additional security checks.

    Blocks:
    - Unspecified addresses (0.0.0.0, ::)
    - Private addresses (RFC 1918, fc00::/7)
    - Loopback (127.0.0.0/8, ::1)
    - Link-local (169.254.0.0/16, fe80::/10)
    - Multicast (224.0.0.0/4, ff00::/8)
    - Reserved addresses
    - CIDR notation (not single hosts)

    Args:
        ip_str: IP address string to validate

    Returns:
        True if IP is safe for external connections, False otherwise
    """
    # Reject empty or None
    if not ip_str:
        return False

    # Reject CIDR notation
    if "/" in str(ip_str):
        return False

    try:
        # Parse IP address
        ip_obj = ipaddress.ip_address(ip_str)

        # CRITICAL: Explicitly block unspecified addresses
        # These represent "no particular address" and must be blocked
        if ip_obj == ipaddress.IPv4Address('0.0.0.0'):
            return False
        if ip_obj == ipaddress.IPv6Address('::'):
            return False

        # Block all dangerous address types
        if ip_obj.is_private:
            return False
        if ip_obj.is_loopback:
            return False
        if ip_obj.is_link_local:
            return False
        if ip_obj.is_multicast:
            return False
        if ip_obj.is_reserved:
            return False

        # Block carrier-grade NAT (100.64.0.0/10)
        # ipaddress doesn't have a specific method for this
        if isinstance(ip_obj, ipaddress.IPv4Address):
            cgn_network = ipaddress.IPv4Network('100.64.0.0/10')
            if ip_obj in cgn_network:
                return False

        # Block documentation addresses
        doc_networks = [
            ipaddress.IPv4Network('192.0.2.0/24'),     # TEST-NET-1
            ipaddress.IPv4Network('198.51.100.0/24'),  # TEST-NET-2
            ipaddress.IPv4Network('203.0.113.0/24'),   # TEST-NET-3
            ipaddress.IPv6Network('2001:db8::/32'),    # IPv6 documentation
        ]

        for network in doc_networks:
            if ip_obj in network:
                return False

        # Block broadcast addresses
        if isinstance(ip_obj, ipaddress.IPv4Address):
            if ip_obj == ipaddress.IPv4Address('255.255.255.255'):
                return False

        # Block IPv4-mapped IPv6 addresses (security risk)
        if isinstance(ip_obj, ipaddress.IPv6Address):
            if ip_obj.ipv4_mapped:
                return False

        # If we got here, the IP passed all security checks
        return True

    except (ipaddress.AddressValueError, ValueError):
        # Invalid IP format
        return False


def validate_ip_with_logging(ip_str: str) -> tuple[bool, str]:
    """
    Validate IP with detailed reason for blocking.

    Useful for debugging and security auditing.

    Args:
        ip_str: IP address string to validate

    Returns:
        (is_valid, reason) tuple
    """
    if not ip_str:
        return False, "Empty or None IP address"

    if "/" in str(ip_str):
        return False, "CIDR notation not allowed for single host validation"

    try:
        ip_obj = ipaddress.ip_address(ip_str)

        # Check unspecified
        if ip_obj == ipaddress.IPv4Address('0.0.0.0'):
            return False, "Blocked: IPv4 unspecified address (0.0.0.0)"
        if ip_obj == ipaddress.IPv6Address('::'):
            return False, "Blocked: IPv6 unspecified address (::)"

        # Check other dangerous ranges
        if ip_obj.is_private:
            return False, f"Blocked: Private address ({ip_str})"
        if ip_obj.is_loopback:
            return False, f"Blocked: Loopback address ({ip_str})"
        if ip_obj.is_link_local:
            return False, f"Blocked: Link-local address ({ip_str})"
        if ip_obj.is_multicast:
            return False, f"Blocked: Multicast address ({ip_str})"
        if ip_obj.is_reserved:
            return False, f"Blocked: Reserved address ({ip_str})"

        # Check CGN
        if isinstance(ip_obj, ipaddress.IPv4Address):
            cgn_network = ipaddress.IPv4Network('100.64.0.0/10')
            if ip_obj in cgn_network:
                return False, f"Blocked: Carrier-grade NAT address ({ip_str})"

        # Check documentation ranges
        doc_ranges = {
            ipaddress.IPv4Network('192.0.2.0/24'): "TEST-NET-1",
            ipaddress.IPv4Network('198.51.100.0/24'): "TEST-NET-2",
            ipaddress.IPv4Network('203.0.113.0/24'): "TEST-NET-3",
            ipaddress.IPv6Network('2001:db8::/32'): "IPv6 documentation",
        }

        for network, name in doc_ranges.items():
            if ip_obj in network:
                return False, f"Blocked: {name} address ({ip_str})"

        # Check broadcast
        if isinstance(ip_obj, ipaddress.IPv4Address):
            if ip_obj == ipaddress.IPv4Address('255.255.255.255'):
                return False, f"Blocked: Broadcast address ({ip_str})"

        # Check IPv4-mapped
        if isinstance(ip_obj, ipaddress.IPv6Address):
            if ip_obj.ipv4_mapped:
                return False, f"Blocked: IPv4-mapped IPv6 address ({ip_str})"

        return True, f"Valid public IP: {ip_str}"

    except (ipaddress.AddressValueError, ValueError) as e:
        return False, f"Invalid IP format: {str(e)}"


def migrate_from_cidr_man(old_validate_func):
    """
    Decorator to migrate from cidr_man to ipaddress-based validation.

    Usage:
        @migrate_from_cidr_man
        def validate_ip(ip: str) -> bool:
            # Old cidr_man based code
            ...

    This will replace the function with the secure ipaddress-based version.
    """
    def wrapper(ip_str: str) -> bool:
        return validate_ip_secure(ip_str)
    return wrapper


# Compatibility layer for gradual migration
class IPValidator:
    """
    Class-based validator for more complex use cases.
    """

    def __init__(self,
                 allow_private: bool = False,
                 allow_loopback: bool = False,
                 allow_multicast: bool = False,
                 custom_blocked_ranges: Optional[list] = None):
        """
        Initialize validator with custom rules.

        Args:
            allow_private: Allow private IP ranges (DANGEROUS - off by default)
            allow_loopback: Allow loopback addresses (DANGEROUS - off by default)
            allow_multicast: Allow multicast addresses (usually not needed)
            custom_blocked_ranges: Additional IP ranges to block
        """
        self.allow_private = allow_private
        self.allow_loopback = allow_loopback
        self.allow_multicast = allow_multicast
        self.custom_blocked_ranges = custom_blocked_ranges or []

    def validate(self, ip_str: str) -> bool:
        """Validate IP with custom rules."""
        if not ip_str or "/" in str(ip_str):
            return False

        try:
            ip_obj = ipaddress.ip_address(ip_str)

            # Always block unspecified
            if ip_obj in [ipaddress.IPv4Address('0.0.0.0'), ipaddress.IPv6Address('::')]:
                return False

            # Check configurable blocks
            if not self.allow_private and ip_obj.is_private:
                return False
            if not self.allow_loopback and ip_obj.is_loopback:
                return False
            if not self.allow_multicast and ip_obj.is_multicast:
                return False

            # Always block these regardless of config
            if ip_obj.is_reserved or ip_obj.is_link_local:
                return False

            # Check custom blocked ranges
            for range_str in self.custom_blocked_ranges:
                try:
                    network = ipaddress.ip_network(range_str, strict=False)
                    if ip_obj in network:
                        return False
                except:
                    continue

            return True

        except:
            return False


def test_migration():
    """Test that the migration preserves security properties."""
    print("Testing IP Validation Migration")
    print("=" * 40)

    # Critical test cases
    test_cases = [
        ("0.0.0.0", False, "IPv4 unspecified"),
        ("::", False, "IPv6 unspecified"),
        ("127.0.0.1", False, "Loopback"),
        ("10.0.0.1", False, "Private"),
        ("169.254.1.1", False, "Link-local"),
        ("224.0.0.1", False, "Multicast"),
        ("100.64.0.1", False, "CGN"),
        ("192.0.2.1", False, "TEST-NET"),
        ("8.8.8.8", True, "Public DNS"),
        ("1.1.1.1", True, "Public DNS"),
    ]

    passed = 0
    failed = 0

    for ip, expected, description in test_cases:
        result = validate_ip_secure(ip)
        if result == expected:
            print(f"✅ {description}: {ip}")
            passed += 1
        else:
            print(f"❌ {description}: {ip} (expected {expected}, got {result})")
            failed += 1

    print()
    print(f"Results: {passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    # Run tests
    import sys
    success = test_migration()
    if not success:
        print("\n❌ Migration test failed! Security regression detected.")
        sys.exit(1)
    else:
        print("\n✅ All migration tests passed. Safe to migrate.")
        sys.exit(0)