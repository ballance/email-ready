#!/usr/bin/env python3
"""
Email Compliance Checker Module

Checks email configuration against major providers' requirements:
- Google (Gmail) sender requirements (2024)
- Yahoo sender requirements (2024)
- Microsoft/Outlook.com requirements
- Apple Mail requirements

References:
- https://support.google.com/mail/answer/81126
- https://senders.yahooinc.com/
"""

import re
import dns.resolver
from typing import Dict, List, Optional, Tuple
from datetime import datetime


class ComplianceChecker:
    """Check email configuration compliance with major providers."""

    def __init__(self):
        """Initialize compliance checker."""
        self.dns_cache = {}

    def _safe_dns_query(self, domain: str, record_type: str, timeout: int = 3) -> List:
        """Perform cached DNS query."""
        cache_key = f"{domain}:{record_type}"
        if cache_key in self.dns_cache:
            return self.dns_cache[cache_key]

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            answers = resolver.resolve(domain, record_type)
            result = list(answers)
            self.dns_cache[cache_key] = result
            return result
        except:
            self.dns_cache[cache_key] = []
            return []

    def _get_txt_records(self, domain: str) -> List[str]:
        """Get TXT records for a domain."""
        records = self._safe_dns_query(domain, "TXT")
        return [b"".join(r.strings).decode("utf-8", errors="ignore") for r in records]

    def check_google_requirements(self, domain: str, is_bulk_sender: bool = False) -> Dict:
        """
        Check compliance with Google's email sender requirements.

        Google requirements (effective Feb 2024):
        - SPF or DKIM required
        - DMARC required for bulk senders (>5000 msgs/day)
        - Valid forward and reverse DNS (PTR)
        - TLS connection for sending
        - One-click unsubscribe for bulk senders
        - Keep spam rate below 0.10% (ideally below 0.30%)
        """
        results = {
            'compliant': False,
            'score': 0,
            'max_score': 100,
            'requirements': {},
            'issues': [],
            'recommendations': [],
            'details': {}
        }

        # 1. SPF Authentication (Required)
        spf_records = [t for t in self._get_txt_records(domain)
                       if t.lower().startswith("v=spf1")]

        if spf_records:
            results['requirements']['spf'] = True
            results['score'] += 15
            results['details']['spf'] = spf_records[0]

            # Check SPF alignment
            if "-all" in spf_records[0]:
                results['score'] += 5
                results['details']['spf_strict'] = True
            elif "~all" in spf_records[0]:
                results['score'] += 3
                results['details']['spf_soft_fail'] = True
            else:
                results['recommendations'].append(
                    "SPF should end with -all (reject) or ~all (soft fail) for better protection"
                )
        else:
            results['requirements']['spf'] = False
            results['issues'].append("SPF record is REQUIRED by Google")

        # 2. DKIM Authentication (Required if no SPF)
        # Note: Can't fully verify DKIM without actual message, checking for selectors
        common_selectors = ['google', 'default', 'selector1', 's1', 'k1']
        dkim_found = False

        for selector in common_selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            dkim_records = self._get_txt_records(dkim_domain)
            if any("v=DKIM1" in r or "p=" in r for r in dkim_records):
                dkim_found = True
                results['details']['dkim_selector'] = selector
                break

        results['requirements']['dkim'] = dkim_found
        if dkim_found:
            results['score'] += 15
        elif not spf_records:
            results['issues'].append(
                "Either SPF or DKIM is REQUIRED by Google (neither found)"
            )

        # 3. DMARC Policy (Required for bulk senders)
        dmarc_records = self._get_txt_records(f"_dmarc.{domain}")
        dmarc_record = next((r for r in dmarc_records if r.lower().startswith("v=dmarc1")), None)

        if dmarc_record:
            results['requirements']['dmarc'] = True
            results['score'] += 20
            results['details']['dmarc'] = dmarc_record

            # Check DMARC policy strength
            if "p=reject" in dmarc_record.lower():
                results['score'] += 10
                results['details']['dmarc_policy'] = 'reject'
            elif "p=quarantine" in dmarc_record.lower():
                results['score'] += 5
                results['details']['dmarc_policy'] = 'quarantine'
            else:
                results['details']['dmarc_policy'] = 'none'
                if is_bulk_sender:
                    results['recommendations'].append(
                        "Bulk senders should use p=quarantine or p=reject"
                    )

            # Check for reporting
            if "rua=" in dmarc_record or "ruf=" in dmarc_record:
                results['score'] += 5
                results['details']['dmarc_reporting'] = True
        else:
            results['requirements']['dmarc'] = False
            if is_bulk_sender:
                results['issues'].append(
                    "DMARC is REQUIRED by Google for bulk senders (>5000 emails/day)"
                )
            else:
                results['recommendations'].append(
                    "DMARC is recommended and will be required if you become a bulk sender"
                )

        # 4. MX Records and Mail Server Check
        mx_records = self._safe_dns_query(domain, "MX")
        if mx_records:
            results['requirements']['mx_records'] = True
            results['score'] += 10
            results['details']['mx_count'] = len(mx_records)

            # Check PTR records for MX hosts
            ptr_valid = 0
            for mx in mx_records[:3]:  # Check first 3 MX records
                mx_host = str(mx.exchange).rstrip(".")
                try:
                    # Get IPs for MX host
                    a_records = self._safe_dns_query(mx_host, "A")
                    for a_record in a_records[:2]:  # Check first 2 IPs
                        ip = str(a_record)
                        # Check PTR
                        rev = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'
                        ptr_records = self._safe_dns_query(rev, "PTR")
                        if ptr_records:
                            ptr_valid += 1
                except:
                    pass

            if ptr_valid > 0:
                results['requirements']['ptr_records'] = True
                results['score'] += 10
                results['details']['ptr_valid_count'] = ptr_valid
            else:
                results['requirements']['ptr_records'] = False
                results['issues'].append(
                    "Valid PTR records are REQUIRED by Google"
                )
        else:
            results['requirements']['mx_records'] = False
            results['issues'].append("No MX records found")

        # 5. TLS Support (Required)
        # This would need actual SMTP testing, marking as recommendation
        results['requirements']['tls'] = None  # Can't verify without SMTP test
        results['recommendations'].append(
            "Ensure SMTP servers support TLS encryption (STARTTLS on port 25 or TLS on port 465)"
        )

        # 6. Bulk Sender Specific Requirements
        if is_bulk_sender:
            # One-click unsubscribe
            results['requirements']['one_click_unsubscribe'] = None
            results['recommendations'].append(
                "Bulk senders MUST include one-click unsubscribe headers (List-Unsubscribe-Post)"
            )

            # Spam rate monitoring
            results['recommendations'].append(
                "Keep spam complaint rate below 0.10% (monitor via Google Postmaster Tools)"
            )

            # Message format
            results['recommendations'].append(
                "Use consistent 'From' addresses and avoid misleading subject lines"
            )

        # Calculate final compliance
        critical_requirements = ['spf', 'dmarc'] if is_bulk_sender else ['spf']
        all_met = all(
            results['requirements'].get(req, False)
            for req in critical_requirements
        )

        # Additional scoring for best practices
        # Check for BIMI
        bimi_records = self._get_txt_records(f"default._bimi.{domain}")
        if any(r.lower().startswith("v=bimi1") for r in bimi_records):
            results['score'] += 5
            results['details']['bimi'] = True

        # Check for MTA-STS
        mta_sts_records = self._get_txt_records(f"_mta-sts.{domain}")
        if mta_sts_records:
            results['score'] += 5
            results['details']['mta_sts'] = True

        results['compliant'] = all_met and len(results['issues']) == 0
        results['grade'] = self._calculate_grade(results['score'])

        return results

    def check_yahoo_requirements(self, domain: str, is_bulk_sender: bool = False) -> Dict:
        """
        Check compliance with Yahoo's email sender requirements.

        Yahoo requirements (effective Feb 2024):
        - SPF or DKIM required
        - DMARC required for bulk senders
        - Complaint rate below 0.3%
        - Valid PTR records
        """
        results = {
            'compliant': False,
            'score': 0,
            'max_score': 100,
            'requirements': {},
            'issues': [],
            'recommendations': [],
            'details': {}
        }

        # Similar checks to Google with Yahoo-specific thresholds
        # SPF Check
        spf_records = [t for t in self._get_txt_records(domain)
                       if t.lower().startswith("v=spf1")]

        if spf_records:
            results['requirements']['spf'] = True
            results['score'] += 20
            results['details']['spf'] = spf_records[0]
        else:
            results['requirements']['spf'] = False
            results['issues'].append("SPF record is REQUIRED by Yahoo")

        # DKIM Check
        common_selectors = ['yahoo', 's1024', 's2048', 'default', 'selector1', 'k1']
        dkim_found = False

        for selector in common_selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            dkim_records = self._get_txt_records(dkim_domain)
            if any("v=DKIM1" in r or "p=" in r for r in dkim_records):
                dkim_found = True
                results['details']['dkim_selector'] = selector
                break

        results['requirements']['dkim'] = dkim_found
        if dkim_found:
            results['score'] += 20

        # DMARC Check
        dmarc_records = self._get_txt_records(f"_dmarc.{domain}")
        dmarc_record = next((r for r in dmarc_records if r.lower().startswith("v=dmarc1")), None)

        if dmarc_record:
            results['requirements']['dmarc'] = True
            results['score'] += 25
            results['details']['dmarc'] = dmarc_record

            # Yahoo prefers stronger policies
            if "p=reject" in dmarc_record.lower():
                results['score'] += 10
            elif "p=quarantine" in dmarc_record.lower():
                results['score'] += 5
        else:
            results['requirements']['dmarc'] = False
            if is_bulk_sender:
                results['issues'].append(
                    "DMARC is REQUIRED by Yahoo for bulk senders"
                )

        # Check authentication alignment
        if spf_records or dkim_found:
            results['requirements']['authentication'] = True
            results['score'] += 15
        else:
            results['requirements']['authentication'] = False
            results['issues'].append(
                "At least one authentication method (SPF or DKIM) is REQUIRED"
            )

        # PTR Records
        mx_records = self._safe_dns_query(domain, "MX")
        if mx_records:
            results['requirements']['mx_records'] = True
            results['score'] += 10
        else:
            results['issues'].append("No MX records found")

        # Bulk sender specific
        if is_bulk_sender:
            results['recommendations'].append(
                "Keep complaint rate below 0.3% (Yahoo's threshold)"
            )
            results['recommendations'].append(
                "Implement List-Unsubscribe headers for easy unsubscription"
            )
            results['recommendations'].append(
                "Maintain consistent sending patterns and volume"
            )

        # Calculate compliance
        critical_requirements = ['authentication', 'dmarc'] if is_bulk_sender else ['authentication']
        results['compliant'] = all(
            results['requirements'].get(req, False)
            for req in critical_requirements
        )

        results['grade'] = self._calculate_grade(results['score'])

        return results

    def check_microsoft_requirements(self, domain: str) -> Dict:
        """
        Check compliance with Microsoft/Outlook.com requirements.
        """
        results = {
            'compliant': False,
            'score': 0,
            'max_score': 100,
            'requirements': {},
            'issues': [],
            'recommendations': [],
            'details': {}
        }

        # Microsoft emphasizes SPF, DKIM, and DMARC
        # SPF Check
        spf_records = [t for t in self._get_txt_records(domain)
                       if t.lower().startswith("v=spf1")]

        if spf_records:
            results['requirements']['spf'] = True
            results['score'] += 25

            # Check for Microsoft's own include
            if "include:spf.protection.outlook.com" in spf_records[0]:
                results['score'] += 5
                results['details']['microsoft_spf'] = True
        else:
            results['requirements']['spf'] = False
            results['issues'].append("SPF is strongly recommended by Microsoft")

        # DKIM Check
        ms_selectors = ['selector1', 'selector2', 'default']
        dkim_found = False

        for selector in ms_selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            dkim_records = self._get_txt_records(dkim_domain)
            if any("v=DKIM1" in r or "p=" in r for r in dkim_records):
                dkim_found = True
                results['score'] += 25
                break

        results['requirements']['dkim'] = dkim_found
        if not dkim_found:
            results['recommendations'].append(
                "DKIM signing is recommended by Microsoft for better deliverability"
            )

        # DMARC Check
        dmarc_records = self._get_txt_records(f"_dmarc.{domain}")
        dmarc_record = next((r for r in dmarc_records if r.lower().startswith("v=dmarc1")), None)

        if dmarc_record:
            results['requirements']['dmarc'] = True
            results['score'] += 30

            # Check for reporting
            if "ruf=mailto:" in dmarc_record and "@outlook.com" in dmarc_record:
                results['details']['reports_to_microsoft'] = True
        else:
            results['requirements']['dmarc'] = False
            results['recommendations'].append(
                "DMARC helps Microsoft identify legitimate email from your domain"
            )

        # Microsoft-specific recommendations
        results['recommendations'].extend([
            "Register with Microsoft's SNDS (Smart Network Data Services)",
            "Monitor your sender reputation via SNDS",
            "Avoid URL shorteners in emails to Outlook users",
            "Use Microsoft's Junk Email Reporting Program (JMRP)"
        ])

        # Check MX for Office 365
        mx_records = self._safe_dns_query(domain, "MX")
        if any("protection.outlook.com" in str(mx.exchange) for mx in mx_records):
            results['details']['uses_office365'] = True
            results['score'] += 10

        results['compliant'] = results['score'] >= 60
        results['grade'] = self._calculate_grade(results['score'])

        return results

    def check_apple_requirements(self, domain: str) -> Dict:
        """
        Check compliance with Apple Mail requirements.
        """
        results = {
            'compliant': False,
            'score': 0,
            'max_score': 100,
            'requirements': {},
            'issues': [],
            'recommendations': [],
            'details': {}
        }

        # Apple Mail focuses on privacy and security
        # Basic authentication checks
        spf_records = [t for t in self._get_txt_records(domain)
                       if t.lower().startswith("v=spf1")]
        if spf_records:
            results['requirements']['spf'] = True
            results['score'] += 30

        # DKIM
        dkim_found = False
        for selector in ['default', 'apple', 'selector1']:
            dkim_domain = f"{selector}._domainkey.{domain}"
            dkim_records = self._get_txt_records(dkim_domain)
            if any("v=DKIM1" in r or "p=" in r for r in dkim_records):
                dkim_found = True
                results['score'] += 30
                break

        results['requirements']['dkim'] = dkim_found

        # DMARC
        dmarc_records = self._get_txt_records(f"_dmarc.{domain}")
        if any(r.lower().startswith("v=dmarc1") for r in dmarc_records):
            results['requirements']['dmarc'] = True
            results['score'] += 30

        # Apple specific: Privacy focus
        results['recommendations'].extend([
            "Use Mail Privacy Protection compliant tracking",
            "Avoid invisible tracking pixels",
            "Include clear unsubscribe options",
            "Use HTTPS for all linked content"
        ])

        # BIMI support (Apple supports it)
        bimi_records = self._get_txt_records(f"default._bimi.{domain}")
        if any(r.lower().startswith("v=bimi1") for r in bimi_records):
            results['score'] += 10
            results['details']['bimi'] = True
            results['recommendations'].append(
                "BIMI configured - your logo may appear in Apple Mail"
            )

        results['compliant'] = results['score'] >= 60
        results['grade'] = self._calculate_grade(results['score'])

        return results

    def check_all_providers(self, domain: str, is_bulk_sender: bool = False) -> Dict:
        """
        Check compliance with all major email providers.
        """
        results = {
            'domain': domain,
            'is_bulk_sender': is_bulk_sender,
            'timestamp': datetime.utcnow().isoformat(),
            'providers': {},
            'overall_score': 0,
            'overall_grade': 'F',
            'critical_issues': [],
            'recommendations': [],
            'summary': {}
        }

        # Check each provider
        providers = [
            ('google', self.check_google_requirements),
            ('yahoo', self.check_yahoo_requirements),
            ('microsoft', self.check_microsoft_requirements),
            ('apple', self.check_apple_requirements)
        ]

        total_score = 0
        compliant_count = 0

        for provider_name, check_func in providers:
            if provider_name in ['google', 'yahoo']:
                provider_results = check_func(domain, is_bulk_sender)
            else:
                provider_results = check_func(domain)

            results['providers'][provider_name] = provider_results
            total_score += provider_results['score']

            if provider_results['compliant']:
                compliant_count += 1

            # Aggregate critical issues
            for issue in provider_results['issues']:
                issue_with_provider = f"{provider_name.title()}: {issue}"
                if issue_with_provider not in results['critical_issues']:
                    results['critical_issues'].append(issue_with_provider)

        # Calculate overall score
        results['overall_score'] = total_score // len(providers)
        results['overall_grade'] = self._calculate_grade(results['overall_score'])
        results['compliant_providers'] = compliant_count
        results['total_providers'] = len(providers)

        # Generate summary
        results['summary'] = {
            'fully_compliant': compliant_count == len(providers),
            'partially_compliant': compliant_count > 0,
            'compliance_rate': f"{compliant_count}/{len(providers)}",
            'primary_issues': results['critical_issues'][:3],  # Top 3 issues
            'action_required': len(results['critical_issues']) > 0
        }

        # Aggregate recommendations (unique)
        all_recommendations = set()
        for provider_results in results['providers'].values():
            all_recommendations.update(provider_results['recommendations'])
        results['recommendations'] = sorted(list(all_recommendations))

        return results

    def _calculate_grade(self, score: int) -> str:
        """Calculate letter grade from score."""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'

    def generate_compliance_report(self, results: Dict) -> str:
        """Generate a human-readable compliance report."""
        report = []
        report.append("=" * 60)
        report.append("EMAIL COMPLIANCE REPORT")
        report.append("=" * 60)
        report.append(f"\nDomain: {results['domain']}")
        report.append(f"Type: {'Bulk Sender' if results['is_bulk_sender'] else 'Regular Sender'}")
        report.append(f"Overall Score: {results['overall_score']}/100 (Grade: {results['overall_grade']})")
        report.append(f"Compliant Providers: {results['compliance_rate']}")

        if results['summary']['fully_compliant']:
            report.append("\n✓ FULLY COMPLIANT with all major providers")
        elif results['summary']['partially_compliant']:
            report.append(f"\n⚠ PARTIALLY COMPLIANT ({results['compliant_providers']}/{results['total_providers']} providers)")
        else:
            report.append("\n✗ NOT COMPLIANT with major provider requirements")

        # Provider breakdown
        report.append("\nPROVIDER COMPLIANCE:")
        report.append("-" * 30)
        for provider, data in results['providers'].items():
            status = "✓" if data['compliant'] else "✗"
            report.append(f"{provider.title():12} {status} Score: {data['score']}/100 (Grade: {data['grade']})")

        # Critical issues
        if results['critical_issues']:
            report.append("\nCRITICAL ISSUES (Must Fix):")
            report.append("-" * 30)
            for i, issue in enumerate(results['critical_issues'], 1):
                report.append(f"{i}. {issue}")

        # Recommendations
        if results['recommendations']:
            report.append("\nRECOMMENDATIONS:")
            report.append("-" * 30)
            for i, rec in enumerate(results['recommendations'][:10], 1):
                report.append(f"{i}. {rec}")

        report.append("\n" + "=" * 60)

        return "\n".join(report)


def main():
    """Example usage."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python compliance_checker.py <domain> [--bulk-sender]")
        sys.exit(1)

    domain = sys.argv[1]
    is_bulk = "--bulk-sender" in sys.argv

    checker = ComplianceChecker()

    print("Checking email compliance...")
    print(f"Domain: {domain}")
    print(f"Bulk Sender: {is_bulk}")
    print()

    # Run compliance check
    results = checker.check_all_providers(domain, is_bulk)

    # Generate and print report
    report = checker.generate_compliance_report(results)
    print(report)

    # Exit with appropriate code
    if results['summary']['fully_compliant']:
        sys.exit(0)
    elif results['summary']['partially_compliant']:
        sys.exit(1)
    else:
        sys.exit(2)


if __name__ == "__main__":
    main()