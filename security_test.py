#!/usr/bin/env python3
"""
Security Test Suite for Email-Ready Codebase

Tests for common security vulnerabilities and validates patches.
Run this regularly to ensure security controls remain effective.
"""

import sys
import re
from typing import List, Tuple
from cidr_man import CIDR

# Import our modules to test
from blacklist_checker import BlacklistChecker
from check_secure import validate_ip, validate_domain


class SecurityTester:
    """Security testing framework."""

    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests_run = 0

    def test(self, name: str, condition: bool, failure_msg: str = ""):
        """Run a single test."""
        self.tests_run += 1
        if condition:
            self.passed += 1
            print(f"✅ PASS: {name}")
        else:
            self.failed += 1
            print(f"❌ FAIL: {name}")
            if failure_msg:
                print(f"   {failure_msg}")

    def test_ip_validation(self):
        """Test IP address validation security."""
        print("\n[IP ADDRESS VALIDATION TESTS]")
        print("-" * 40)

        # Critical: Unspecified addresses must be blocked
        dangerous_ips = [
            ("0.0.0.0", "IPv4 unspecified"),
            ("::", "IPv6 unspecified"),
            ("127.0.0.1", "Loopback"),
            ("10.0.0.1", "Private range"),
            ("169.254.1.1", "Link-local"),
            ("224.0.0.1", "Multicast"),
            ("::1", "IPv6 loopback"),
            ("fc00::1", "IPv6 unique local"),
            ("fe80::1", "IPv6 link-local"),
            ("ff00::1", "IPv6 multicast"),
            ("192.168.1.1", "Private range"),
            ("172.16.0.1", "Private range"),
            ("100.64.0.1", "Carrier-grade NAT"),
            ("240.0.0.1", "Reserved"),
            ("255.255.255.255", "Broadcast"),
            ("192.0.2.1", "TEST-NET-1"),
            ("10.0.0.0/24", "CIDR notation"),
        ]

        for ip, description in dangerous_ips:
            result = validate_ip(ip)
            self.test(
                f"Block {description}: {ip}",
                not result,
                f"SECURITY: {ip} should be blocked but was allowed!"
            )

        # Valid public IPs should be allowed
        valid_ips = [
            ("8.8.8.8", "Google DNS"),
            ("1.1.1.1", "Cloudflare DNS"),
            ("93.184.216.34", "example.com"),
            ("2001:4860:4860::8888", "Google DNS IPv6"),
        ]

        for ip, description in valid_ips:
            result = validate_ip(ip)
            self.test(
                f"Allow {description}: {ip}",
                result,
                f"Valid IP {ip} was incorrectly blocked"
            )

    def test_domain_validation(self):
        """Test domain validation security."""
        print("\n[DOMAIN VALIDATION TESTS]")
        print("-" * 40)

        # Dangerous domains
        dangerous_domains = [
            ("localhost", "Localhost"),
            ("127.0.0.1", "IP as domain"),
            ("0.0.0.0", "Unspecified IP"),
            ("::1", "IPv6 localhost"),
            ("example..com", "Double dot"),
            ("-example.com", "Leading dash"),
            ("example-.com", "Trailing dash"),
            ("", "Empty string"),
            ("a" * 254, "Too long"),
            ("test..", "Trailing dots"),
            ("test com", "Space in domain"),
            ("test@evil.com", "Email format"),
            ("http://test.com", "URL format"),
            ("../../../etc/passwd", "Path traversal"),
            ("test.com/path", "Path included"),
            ("test.com:8080", "Port included"),
        ]

        for domain, description in dangerous_domains:
            result = validate_domain(domain)
            self.test(
                f"Block {description}: {domain[:50]}",
                not result,
                f"Dangerous domain should be blocked"
            )

        # Valid domains
        valid_domains = [
            "example.com",
            "sub.example.com",
            "example.co.uk",
            "test-domain.org",
            "123.example.com",
            "a.b.c.d.example.com",
        ]

        for domain in valid_domains:
            result = validate_domain(domain)
            self.test(
                f"Allow valid domain: {domain}",
                result,
                f"Valid domain was incorrectly blocked"
            )

    def test_regex_dos(self):
        """Test for ReDoS vulnerabilities."""
        print("\n[REGEX DENIAL OF SERVICE TESTS]")
        print("-" * 40)

        # Test potentially vulnerable regex patterns
        patterns = [
            (r'^[a-zA-Z0-9.-]+$', 'a' * 100 + '!' + 'a' * 100),
            (r'^[a-zA-Z0-9._-]+$', '-' * 1000),
        ]

        import time
        for pattern, test_string in patterns:
            start = time.time()
            try:
                re.match(pattern, test_string)
                elapsed = time.time() - start
                self.test(
                    f"ReDoS protection for pattern {pattern[:30]}",
                    elapsed < 0.1,
                    f"Pattern took {elapsed:.3f}s (potential ReDoS)"
                )
            except Exception as e:
                self.test(
                    f"ReDoS pattern safety",
                    False,
                    f"Pattern caused exception: {e}"
                )

    def test_ssrf_protection(self):
        """Test SSRF protection mechanisms."""
        print("\n[SSRF PROTECTION TESTS]")
        print("-" * 40)

        # Test blacklist checker
        checker = BlacklistChecker()

        # These IPs should be rejected before any network operation
        ssrf_targets = [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "169.254.169.254",  # AWS metadata
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
        ]

        for ip in ssrf_targets:
            result = checker._validate_ip(ip)
            self.test(
                f"SSRF: Block {ip}",
                not result,
                f"SSRF vector {ip} not blocked!"
            )

    def test_rate_limiting(self):
        """Test rate limiting controls."""
        print("\n[RATE LIMITING TESTS]")
        print("-" * 40)

        from check_secure import (
            MAX_DNS_QUERIES_PER_RUN,
            MAX_SMTP_CONNECTIONS,
            MAX_MX_RECORDS,
            MAX_DKIM_SELECTORS,
        )

        # Verify limits are reasonable
        self.test(
            "DNS query limit reasonable",
            10 <= MAX_DNS_QUERIES_PER_RUN <= 100,
            f"Limit {MAX_DNS_QUERIES_PER_RUN} may be too high/low"
        )

        self.test(
            "SMTP connection limit reasonable",
            1 <= MAX_SMTP_CONNECTIONS <= 10,
            f"Limit {MAX_SMTP_CONNECTIONS} may be too high/low"
        )

        self.test(
            "MX record limit reasonable",
            1 <= MAX_MX_RECORDS <= 20,
            f"Limit {MAX_MX_RECORDS} may be too high/low"
        )

        self.test(
            "DKIM selector limit reasonable",
            1 <= MAX_DKIM_SELECTORS <= 50,
            f"Limit {MAX_DKIM_SELECTORS} may be too high/low"
        )

    def test_injection_prevention(self):
        """Test injection attack prevention."""
        print("\n[INJECTION PREVENTION TESTS]")
        print("-" * 40)

        # DNS injection attempts
        injection_attempts = [
            "example.com\r\n",
            "example.com; cat /etc/passwd",
            "example.com`whoami`",
            "example.com$(whoami)",
            "example.com|whoami",
            "example.com&whoami",
            "example.com';DROP TABLE;--",
            "../../etc/passwd",
            "example.com\x00.evil.com",
            "example.com\nSet-Cookie: admin=true",
        ]

        for attempt in injection_attempts:
            result = validate_domain(attempt)
            self.test(
                f"Block injection: {attempt[:30]}",
                not result,
                f"Injection attempt not blocked"
            )

    def test_error_handling(self):
        """Test secure error handling."""
        print("\n[ERROR HANDLING TESTS]")
        print("-" * 40)

        # Test that errors don't leak information
        checker = BlacklistChecker()

        # These should fail gracefully
        test_cases = [
            None,
            "",
            "🎭",  # Unicode
            "\x00",  # Null byte
            "a" * 1000,  # Very long input
            {"not": "a string"},  # Wrong type
        ]

        for test_input in test_cases:
            try:
                if isinstance(test_input, str):
                    result = checker._validate_ip(test_input)
                    self.test(
                        f"Handle invalid input: {str(test_input)[:20]}",
                        not result,
                        "Should return False for invalid input"
                    )
            except Exception as e:
                self.test(
                    f"No exception for: {str(test_input)[:20]}",
                    False,
                    f"Exception leaked: {str(e)[:50]}"
                )

    def run_all_tests(self):
        """Run all security tests."""
        print("=" * 50)
        print("SECURITY TEST SUITE FOR EMAIL-READY")
        print("=" * 50)

        self.test_ip_validation()
        self.test_domain_validation()
        self.test_regex_dos()
        self.test_ssrf_protection()
        self.test_rate_limiting()
        self.test_injection_prevention()
        self.test_error_handling()

        print("\n" + "=" * 50)
        print("SECURITY TEST RESULTS")
        print("=" * 50)
        print(f"Tests Run: {self.tests_run}")
        print(f"Passed: {self.passed}")
        print(f"Failed: {self.failed}")

        if self.failed == 0:
            print("\n✅ ALL SECURITY TESTS PASSED")
            print("Your security controls are working correctly.")
        else:
            print(f"\n❌ {self.failed} SECURITY TESTS FAILED")
            print("CRITICAL: Fix failed tests immediately!")

        return self.failed == 0


def main():
    """Run security tests."""
    tester = SecurityTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()