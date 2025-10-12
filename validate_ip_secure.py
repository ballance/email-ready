#!/usr/bin/env python3
"""
Secure IP validation function that properly blocks all dangerous IP addresses.
This fixes the security vulnerability where cidr_man doesn't properly handle unspecified addresses.
"""

from cidr_man import CIDR


def validate_ip_secure(ip: str) -> bool:
    """
    Validate IP address and block all dangerous ranges.

    Blocks:
    - Unspecified addresses (0.0.0.0, ::)
    - Private addresses (RFC 1918, FC00::/7)
    - Loopback (127.0.0.0/8, ::1)
    - Link-local (169.254.0.0/16, FE80::/10)
    - Multicast (224.0.0.0/4, FF00::/8)
    - Reserved addresses
    - CIDR notation (not single hosts)

    Args:
        ip: IP address string to validate

    Returns:
        True if IP is safe for external connections, False otherwise
    """
    try:
        addr = CIDR(ip)

        # Ensure caller gave a single host address, not a network
        if "/" in str(ip):
            return False

        # Get the compressed representation for comparison
        compressed = addr.compressed

        # CRITICAL: Explicitly block unspecified addresses
        # cidr_man doesn't properly flag these as reserved
        if compressed in ('0.0.0.0', '::'):
            return False

        # Block all dangerous address ranges
        if (addr.is_private or
            addr.is_loopback or
            addr.is_link_local or
            addr.is_multicast or
            addr.is_reserved):
            return False

        return True

    except Exception:
        return False


def validate_ip_with_logging(ip: str) -> tuple[bool, str]:
    """
    Validate IP with detailed reason for blocking.
    Useful for debugging and security auditing.
    """
    try:
        addr = CIDR(ip)

        # Check for CIDR notation
        if "/" in str(ip):
            return False, "CIDR notation not allowed"

        compressed = addr.compressed

        # Check unspecified addresses first (highest priority)
        if compressed in ('0.0.0.0', '::'):
            return False, f"Unspecified address blocked: {compressed}"

        # Check other dangerous ranges
        if addr.is_private:
            return False, f"Private address blocked: {compressed}"
        if addr.is_loopback:
            return False, f"Loopback address blocked: {compressed}"
        if addr.is_link_local:
            return False, f"Link-local address blocked: {compressed}"
        if addr.is_multicast:
            return False, f"Multicast address blocked: {compressed}"
        if addr.is_reserved:
            return False, f"Reserved address blocked: {compressed}"

        return True, f"Valid public IP: {compressed}"

    except Exception as e:
        return False, f"Invalid IP format: {str(e)}"


# Test the fix
if __name__ == "__main__":
    # Critical test cases
    test_ips = [
        ("0.0.0.0", False, "IPv4 unspecified"),
        ("::", False, "IPv6 unspecified"),
        ("127.0.0.1", False, "Loopback"),
        ("10.0.0.1", False, "Private"),
        ("169.254.1.1", False, "Link-local"),
        ("224.0.0.1", False, "Multicast"),
        ("8.8.8.8", True, "Google DNS - public"),
        ("1.1.1.1", True, "Cloudflare DNS - public"),
    ]

    print("Testing secure IP validation:")
    print("=" * 60)

    for ip, expected, description in test_ips:
        result = validate_ip_secure(ip)
        status = "✓" if result == expected else "✗ FAIL"
        valid, reason = validate_ip_with_logging(ip)

        print(f"{status} {ip:20} {description:25}")
        print(f"   Result: {result}, Expected: {expected}")
        print(f"   Reason: {reason}")
        print()