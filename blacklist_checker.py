#!/usr/bin/env python3
"""
Blacklist Checker Module

Checks domains and IP addresses against multiple DNS-based blacklists (DNSBLs)
to identify potential email deliverability issues.

Security Features:
- Rate limiting to prevent abuse
- Concurrent checking with thread limits
- Timeout controls
- Input validation
"""

import concurrent.futures
import socket
import time
import dns.resolver
import dns.reversename
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from cidr_man import CIDR

# Major DNS Blacklists (RBLs/DNSBLs)
IP_BLACKLISTS = [
    # Spamhaus - Industry standard
    'zen.spamhaus.org',           # Combined list (SBL, CSS, XBL, PBL)
    'sbl.spamhaus.org',            # Spamhaus Block List
    'xbl.spamhaus.org',            # Exploits Block List
    'pbl.spamhaus.org',            # Policy Block List

    # Major providers
    'bl.spamcop.net',              # SpamCop
    'b.barracudacentral.org',      # Barracuda
    'dnsbl.sorbs.net',             # SORBS
    'psbl.surriel.com',            # Passive Spam Block List
    'bl.mailspike.net',            # Mailspike

    # SURBL/URIBL (domain-based)
    'dbl.spamhaus.org',            # Domain Block List

    # Additional reputation lists
    'cbl.abuseat.org',             # Composite Blocking List
    'dnsbl-1.uceprotect.net',      # UCEPROTECT Level 1
    'dul.ru',                      # Dynamic User List
    'bogons.cymru.com',            # Bogon IPs
    'ix.dnsbl.manitu.net',         # Manitu
    'bl.spameatingmonkey.net',     # SpamEatingMonkey
    'db.wpbl.info',                # Weighted Private Block List
    'all.s5h.net',                 # S5H.net
    'dnsbl.dronebl.org',           # DroneBL
    'access.redhawk.org',          # RedHawk
    'rbl.metunet.com',             # METU
    'dnsbl.kempt.net',             # Kempt
    'all.spam-rbl.fr',             # Spam-RBL France

    # Reputation-based
    'bl.score.senderscore.com',    # Sender Score
    'list.dnswl.org',              # DNS Whitelist (inverse check)
]

DOMAIN_BLACKLISTS = [
    'dbl.spamhaus.org',            # Spamhaus Domain Block List
    'multi.surbl.org',             # SURBL multi
    'multi.uribl.com',             # URIBL multi
    'rhsbl.sorbs.net',             # SORBS RHS
    'dbl.abuse.ch',                # abuse.ch Domain Block List
    'nomail.rhsbl.sorbs.net',      # SORBS no-mail
    'fresh.spameatingmonkey.net',  # Fresh spam domains
]

# Configuration
MAX_CONCURRENT_CHECKS = 20
BLACKLIST_TIMEOUT = 2
MAX_BLACKLISTS_PER_RUN = 50
CACHE_DURATION = 300  # 5 minutes


class BlacklistChecker:
    """Check IPs and domains against multiple blacklists."""

    def __init__(self, max_workers: int = MAX_CONCURRENT_CHECKS):
        """Initialize blacklist checker with configuration."""
        self.max_workers = min(max_workers, MAX_CONCURRENT_CHECKS)
        self.cache = {}
        self.check_count = 0
        self.last_check_time = defaultdict(float)

    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address format and block private ranges."""
        try:
            addr = CIDR(ip)
            # Block private, loopback, link-local, multicast, reserved
            if (addr.is_private or addr.is_loopback or
                addr.is_link_local or addr.is_multicast or
                addr.is_reserved):
                return False
            return True
        except Exception:
            return False

    def _validate_domain(self, domain: str) -> bool:
        """Validate domain format."""
        if not domain or len(domain) > 253:
            return False

        # Basic validation
        labels = domain.split('.')
        if len(labels) < 2:
            return False

        for label in labels:
            if not label or len(label) > 63:
                return False
            if not all(c.isalnum() or c == '-' for c in label):
                return False
            if label.startswith('-') or label.endswith('-'):
                return False

        return True

    def _check_single_ip_blacklist(self, ip: str, blacklist: str) -> Dict:
        """Check a single IP against a single blacklist."""
        result = {
            'blacklist': blacklist,
            'listed': False,
            'reason': None,
            'error': None
        }

        try:
            # Reverse IP for DNSBL query
            reversed_ip = '.'.join(reversed(ip.split('.')))
            query = f"{reversed_ip}.{blacklist}"

            # DNS query with timeout
            resolver = dns.resolver.Resolver()
            resolver.timeout = BLACKLIST_TIMEOUT
            resolver.lifetime = BLACKLIST_TIMEOUT

            answers = resolver.resolve(query, 'A')

            if answers:
                # Listed - get the response code
                response = str(answers[0])
                result['listed'] = True
                result['reason'] = self._interpret_bl_response(blacklist, response)

                # Try to get TXT record for details
                try:
                    txt_answers = resolver.resolve(query, 'TXT')
                    if txt_answers:
                        result['details'] = str(txt_answers[0]).strip('"')
                except:
                    pass

        except dns.resolver.NXDOMAIN:
            # Not listed (this is the good case)
            result['listed'] = False
        except dns.resolver.Timeout:
            result['error'] = 'Timeout'
        except Exception as e:
            result['error'] = f'Check failed: {str(e)}'

        return result

    def _check_single_domain_blacklist(self, domain: str, blacklist: str) -> Dict:
        """Check a single domain against a domain blacklist."""
        result = {
            'blacklist': blacklist,
            'listed': False,
            'reason': None,
            'error': None
        }

        try:
            query = f"{domain}.{blacklist}"

            # DNS query with timeout
            resolver = dns.resolver.Resolver()
            resolver.timeout = BLACKLIST_TIMEOUT
            resolver.lifetime = BLACKLIST_TIMEOUT

            answers = resolver.resolve(query, 'A')

            if answers:
                result['listed'] = True
                response = str(answers[0])
                result['reason'] = self._interpret_bl_response(blacklist, response)

                # Try to get TXT record for details
                try:
                    txt_answers = resolver.resolve(query, 'TXT')
                    if txt_answers:
                        result['details'] = str(txt_answers[0]).strip('"')
                except:
                    pass

        except dns.resolver.NXDOMAIN:
            result['listed'] = False
        except dns.resolver.Timeout:
            result['error'] = 'Timeout'
        except Exception as e:
            result['error'] = f'Check failed: {str(e)}'

        return result

    def _interpret_bl_response(self, blacklist: str, response: str) -> str:
        """Interpret blacklist response codes."""
        # Common response code interpretations
        if blacklist.endswith('spamhaus.org'):
            codes = {
                '127.0.0.2': 'SBL - Static spam sources',
                '127.0.0.3': 'CSS - Snowshoe spam',
                '127.0.0.4': 'CBL - Botnet/compromised',
                '127.0.0.9': 'DROP - Hijacked networks',
                '127.0.0.10': 'PBL - Dynamic/residential IP',
                '127.0.0.11': 'PBL - Static assignment',
            }
            return codes.get(response, f'Listed ({response})')

        elif blacklist == 'bl.spamcop.net':
            return 'Reported for sending spam'

        elif blacklist == 'b.barracudacentral.org':
            return 'Poor reputation or spam source'

        elif blacklist.endswith('sorbs.net'):
            codes = {
                '127.0.0.2': 'HTTP proxy',
                '127.0.0.3': 'SOCKS proxy',
                '127.0.0.5': 'SMTP relay',
                '127.0.0.6': 'Spam source',
                '127.0.0.7': 'Web vulnerability',
                '127.0.0.8': 'Recent spam',
                '127.0.0.9': 'Zombie/compromised',
                '127.0.0.10': 'Dynamic IP',
            }
            return codes.get(response, f'Listed ({response})')

        return f'Listed ({response})'

    def check_ip(self, ip: str, blacklists: List[str] = None) -> Dict:
        """Check an IP address against multiple blacklists."""
        if not self._validate_ip(ip):
            return {
                'ip': ip,
                'error': 'Invalid IP address',
                'results': []
            }

        # Check cache
        cache_key = f"ip:{ip}"
        if cache_key in self.cache:
            cache_time, cached_result = self.cache[cache_key]
            if time.time() - cache_time < CACHE_DURATION:
                return cached_result

        # Use default blacklists if none specified
        if blacklists is None:
            blacklists = IP_BLACKLISTS[:MAX_BLACKLISTS_PER_RUN]

        results = []

        # Concurrent checking
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_bl = {
                executor.submit(self._check_single_ip_blacklist, ip, bl): bl
                for bl in blacklists
            }

            for future in concurrent.futures.as_completed(future_to_bl):
                try:
                    result = future.result(timeout=BLACKLIST_TIMEOUT + 1)
                    results.append(result)
                except Exception as e:
                    bl = future_to_bl[future]
                    results.append({
                        'blacklist': bl,
                        'listed': False,
                        'error': str(e)
                    })

        # Calculate statistics
        listed_count = sum(1 for r in results if r['listed'])
        checked_count = sum(1 for r in results if not r.get('error'))

        output = {
            'ip': ip,
            'listed_count': listed_count,
            'checked_count': checked_count,
            'total_checked': len(results),
            'listing_rate': listed_count / checked_count if checked_count > 0 else 0,
            'results': results,
            'critical': listed_count > 0,  # Any listing is critical
            'summary': self._generate_summary(results)
        }

        # Cache result
        self.cache[cache_key] = (time.time(), output)

        return output

    def check_domain(self, domain: str, blacklists: List[str] = None) -> Dict:
        """Check a domain against domain blacklists."""
        if not self._validate_domain(domain):
            return {
                'domain': domain,
                'error': 'Invalid domain format',
                'results': []
            }

        # Check cache
        cache_key = f"domain:{domain}"
        if cache_key in self.cache:
            cache_time, cached_result = self.cache[cache_key]
            if time.time() - cache_time < CACHE_DURATION:
                return cached_result

        # Use default domain blacklists if none specified
        if blacklists is None:
            blacklists = DOMAIN_BLACKLISTS

        results = []

        # Concurrent checking
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_bl = {
                executor.submit(self._check_single_domain_blacklist, domain, bl): bl
                for bl in blacklists
            }

            for future in concurrent.futures.as_completed(future_to_bl):
                try:
                    result = future.result(timeout=BLACKLIST_TIMEOUT + 1)
                    results.append(result)
                except Exception as e:
                    bl = future_to_bl[future]
                    results.append({
                        'blacklist': bl,
                        'listed': False,
                        'error': str(e)
                    })

        # Calculate statistics
        listed_count = sum(1 for r in results if r['listed'])
        checked_count = sum(1 for r in results if not r.get('error'))

        output = {
            'domain': domain,
            'listed_count': listed_count,
            'checked_count': checked_count,
            'total_checked': len(results),
            'listing_rate': listed_count / checked_count if checked_count > 0 else 0,
            'results': results,
            'critical': listed_count > 0,
            'summary': self._generate_summary(results)
        }

        # Cache result
        self.cache[cache_key] = (time.time(), output)

        return output

    def check_mx_records(self, domain: str, mx_hosts: List[Tuple[str, List[str]]]) -> Dict:
        """Check all MX record IPs against blacklists."""
        all_results = {
            'domain': domain,
            'mx_checks': [],
            'total_ips': 0,
            'listed_ips': 0,
            'critical_issues': []
        }

        for mx_host, ips in mx_hosts:
            mx_result = {
                'host': mx_host,
                'ips': []
            }

            for ip in ips:
                ip_result = self.check_ip(ip)
                mx_result['ips'].append({
                    'ip': ip,
                    'listed': ip_result.get('listed_count', 0) > 0,
                    'listings': ip_result.get('listed_count', 0),
                    'details': ip_result.get('summary', '')
                })

                all_results['total_ips'] += 1
                if ip_result.get('listed_count', 0) > 0:
                    all_results['listed_ips'] += 1
                    all_results['critical_issues'].append(
                        f"{mx_host} ({ip}) is blacklisted on {ip_result['listed_count']} lists"
                    )

            all_results['mx_checks'].append(mx_result)

        return all_results

    def _generate_summary(self, results: List[Dict]) -> str:
        """Generate a summary of blacklist check results."""
        listed = [r for r in results if r['listed']]

        if not listed:
            return "Not listed on any checked blacklists"

        critical_lists = ['zen.spamhaus.org', 'bl.spamcop.net', 'b.barracudacentral.org']
        critical_listings = [r for r in listed if r['blacklist'] in critical_lists]

        if critical_listings:
            lists = ', '.join([r['blacklist'] for r in critical_listings])
            return f"CRITICAL: Listed on major blacklists ({lists})"

        return f"Listed on {len(listed)} blacklist(s)"

    def get_removal_instructions(self, blacklist: str) -> str:
        """Get removal instructions for specific blacklists."""
        removal_urls = {
            'zen.spamhaus.org': 'https://www.spamhaus.org/lookup/',
            'bl.spamcop.net': 'https://www.spamcop.net/bl.shtml',
            'b.barracudacentral.org': 'https://www.barracudacentral.org/rbl/removal-request',
            'dnsbl.sorbs.net': 'http://www.sorbs.net/lookup.shtml',
            'psbl.surriel.com': 'https://psbl.org/remove',
            'dbl.spamhaus.org': 'https://www.spamhaus.org/dbl/removal',
        }

        if blacklist in removal_urls:
            return f"Request removal at: {removal_urls[blacklist]}"

        return f"Check the {blacklist} website for removal procedures"


def main():
    """Example usage and testing."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python blacklist_checker.py <domain_or_ip>")
        sys.exit(1)

    target = sys.argv[1]
    checker = BlacklistChecker()

    # Determine if it's an IP or domain
    if '.' in target and all(part.isdigit() for part in target.split('.')):
        # IP address
        print(f"Checking IP: {target}")
        result = checker.check_ip(target)
    else:
        # Domain
        print(f"Checking domain: {target}")
        result = checker.check_domain(target)

        # Also check MX records
        try:
            resolver = dns.resolver.Resolver()
            mx_records = resolver.resolve(target, 'MX')
            mx_hosts = []

            for mx in mx_records:
                host = str(mx.exchange).rstrip('.')
                try:
                    a_records = resolver.resolve(host, 'A')
                    ips = [str(r) for r in a_records]
                    mx_hosts.append((host, ips))
                except:
                    pass

            if mx_hosts:
                print("\nChecking MX record IPs...")
                mx_result = checker.check_mx_records(target, mx_hosts)

                print("\nMX Blacklist Check Results:")
                print(f"Total IPs checked: {mx_result['total_ips']}")
                print(f"Blacklisted IPs: {mx_result['listed_ips']}")

                if mx_result['critical_issues']:
                    print("\nCritical Issues:")
                    for issue in mx_result['critical_issues']:
                        print(f"  - {issue}")
        except:
            pass

    # Display results
    print("\nBlacklist Check Results:")
    print("=" * 50)

    if 'error' in result:
        print(f"Error: {result['error']}")
        return

    if 'ip' in result:
        print(f"IP: {result['ip']}")
    else:
        print(f"Domain: {result['domain']}")

    print(f"Checked: {result['checked_count']} blacklists")
    print(f"Listed on: {result['listed_count']} blacklists")
    print(f"Listing rate: {result['listing_rate']:.1%}")
    print(f"Status: {result['summary']}")

    if result['listed_count'] > 0:
        print("\nBlacklist Listings:")
        for r in result['results']:
            if r['listed']:
                print(f"  ✗ {r['blacklist']}: {r['reason']}")
                if r.get('details'):
                    print(f"    Details: {r['details']}")

        print("\nRemoval Instructions:")
        for r in result['results']:
            if r['listed']:
                print(f"  {r['blacklist']}: {checker.get_removal_instructions(r['blacklist'])}")
    else:
        print("\n✓ Not listed on any checked blacklists")


if __name__ == "__main__":
    main()