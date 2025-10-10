#!/usr/bin/env python3
"""
Security test comparing ipaddress (stdlib) vs cidr_man for validate_ip() function.
This test ensures that replacing ipaddress with cidr_man doesn't introduce security vulnerabilities.
"""

import ipaddress
from cidr_man import CIDR

# Test cases covering all security-critical scenarios
TEST_CASES = [
    # Loopback addresses - MUST BE BLOCKED
    ("127.0.0.1", False, "IPv4 loopback"),
    ("127.0.0.2", False, "IPv4 loopback range"),
    ("127.255.255.255", False, "IPv4 loopback end"),
    ("::1", False, "IPv6 loopback"),

    # Private addresses - MUST BE BLOCKED
    ("10.0.0.1", False, "IPv4 private 10/8"),
    ("10.255.255.255", False, "IPv4 private 10/8 end"),
    ("172.16.0.1", False, "IPv4 private 172.16/12"),
    ("172.31.255.255", False, "IPv4 private 172.16/12 end"),
    ("192.168.0.1", False, "IPv4 private 192.168/16"),
    ("192.168.255.255", False, "IPv4 private 192.168/16 end"),
    ("fc00::1", False, "IPv6 unique local"),
    ("fd00::1", False, "IPv6 unique local"),

    # Link-local - MUST BE BLOCKED
    ("169.254.1.1", False, "IPv4 link-local"),
    ("169.254.254.254", False, "IPv4 link-local end"),
    ("fe80::1", False, "IPv6 link-local"),
    ("fe80::ffff:ffff:ffff:ffff", False, "IPv6 link-local end"),

    # Multicast - MUST BE BLOCKED
    ("224.0.0.1", False, "IPv4 multicast"),
    ("239.255.255.255", False, "IPv4 multicast end"),
    ("ff00::1", False, "IPv6 multicast"),
    ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", False, "IPv6 multicast end"),

    # Reserved - MUST BE BLOCKED
    ("240.0.0.1", False, "IPv4 reserved 240/4"),
    ("255.255.255.255", False, "IPv4 broadcast"),
    ("0.0.0.0", False, "IPv4 unspecified"),
    ("::", False, "IPv6 unspecified"),
    ("::ffff:192.0.2.1", False, "IPv4-mapped IPv6"),

    # Documentation/test ranges - MUST BE BLOCKED
    ("192.0.2.1", False, "TEST-NET-1"),
    ("198.51.100.1", False, "TEST-NET-2"),
    ("203.0.113.1", False, "TEST-NET-3"),
    ("2001:db8::1", False, "IPv6 documentation"),

    # Carrier-grade NAT - MUST BE BLOCKED
    ("100.64.0.1", False, "Carrier-grade NAT"),
    ("100.127.255.255", False, "Carrier-grade NAT end"),

    # Public addresses - SHOULD BE ALLOWED
    ("8.8.8.8", True, "Google DNS"),
    ("1.1.1.1", True, "Cloudflare DNS"),
    ("208.67.222.222", True, "OpenDNS"),
    ("2001:4860:4860::8888", True, "Google DNS IPv6"),
    ("2606:4700:4700::1111", True, "Cloudflare DNS IPv6"),
    ("93.184.216.34", True, "example.com"),

    # CIDR notation - MUST BE BLOCKED (not a single host)
    ("192.0.2.0/24", False, "CIDR notation"),
    ("10.0.0.0/8", False, "CIDR notation private"),
    ("2001:db8::/32", False, "CIDR notation IPv6"),

    # Edge cases
    ("1.2.3.4.5", False, "Invalid IP"),
    ("256.1.1.1", False, "Invalid octet"),
    ("not-an-ip", False, "Garbage input"),
    ("", False, "Empty string"),
]


def validate_ip_ipaddress(ip: str) -> bool:
    """Original implementation using ipaddress."""
    try:
        ip_obj = ipaddress.ip_address(ip)

        # Block private, loopback, link-local, multicast
        if (ip_obj.is_private or ip_obj.is_loopback or
            ip_obj.is_link_local or ip_obj.is_multicast or
            ip_obj.is_reserved):
            return False

        return True
    except ValueError:
        return False


def validate_ip_cidr_man(ip: str) -> bool:
    """New implementation using cidr_man."""
    try:
        addr = CIDR(ip)

        # Ensure caller gave a single host address, not a network like "1.2.3.0/24"
        is_host = "/" not in addr.compressed  # hosts render without a /prefix

        # Block private, loopback, link-local, multicast, reserved
        blocked = (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        )
        return is_host and not blocked
    except Exception:
        return False


def run_tests():
    """Run comprehensive security tests."""
    print("=" * 80)
    print("SECURITY TEST: ipaddress vs cidr_man")
    print("=" * 80)
    print()

    mismatches = []
    passed = 0
    failed = 0

    for ip, expected, description in TEST_CASES:
        result_ipaddress = validate_ip_ipaddress(ip)
        result_cidr_man = validate_ip_cidr_man(ip)

        # Check if both implementations agree
        match = result_ipaddress == result_cidr_man

        # Check if result matches expected
        correct_ipaddress = result_ipaddress == expected
        correct_cidr_man = result_cidr_man == expected

        status = "✓" if (match and correct_cidr_man) else "✗"

        if not match or not correct_cidr_man:
            failed += 1
            mismatches.append({
                "ip": ip,
                "description": description,
                "expected": expected,
                "ipaddress": result_ipaddress,
                "cidr_man": result_cidr_man,
                "match": match
            })
            print(f"{status} {ip:40} {description:30}")
            print(f"   Expected: {expected}, ipaddress: {result_ipaddress}, cidr_man: {result_cidr_man}")
        else:
            passed += 1

    print()
    print("=" * 80)
    print("RESULTS")
    print("=" * 80)
    print(f"Passed: {passed}/{len(TEST_CASES)}")
    print(f"Failed: {failed}/{len(TEST_CASES)}")
    print()

    if mismatches:
        print("⚠️  SECURITY ISSUES DETECTED ⚠️")
        print()
        print("Behavioral differences that could lead to SSRF vulnerabilities:")
        print()

        for m in mismatches:
            print(f"IP: {m['ip']}")
            print(f"  Description: {m['description']}")
            print(f"  Expected (secure): {m['expected']}")
            print(f"  ipaddress result: {m['ipaddress']}")
            print(f"  cidr_man result: {m['cidr_man']}")

            if m['cidr_man'] and not m['expected']:
                print("  🚨 CRITICAL: cidr_man ALLOWS a dangerous IP that should be blocked!")
            elif not m['cidr_man'] and m['expected']:
                print("  ⚠️  WARNING: cidr_man BLOCKS a safe IP (overly restrictive)")

            if not m['match']:
                print("  ⚠️  MISMATCH: Different behavior between libraries")
            print()

        return False
    else:
        print("✅ All tests passed! cidr_man is behaviorally equivalent to ipaddress.")
        print()
        return True


if __name__ == "__main__":
    import sys
    success = run_tests()
    sys.exit(0 if success else 1)
