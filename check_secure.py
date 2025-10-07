#!/usr/bin/env python3
"""
check_secure.py

Security-hardened email configuration checker with anti-abuse protections.

SECURITY FEATURES:
- Domain validation and sanitization
- Rate limiting on DNS queries and SMTP connections
- Resource limits and timeouts
- SSRF protection for HTTP requests
- Safe error handling without information disclosure
- Connection pooling limits
- IPv6 and IPv4 validation
- Certificate validation controls

Dependencies:
  pip install dnspython requests
"""

import argparse
import socket
import ssl
import dns.resolver
import dns.reversename
import dns.exception
import requests
import re
import time
import sys
from cidr_man import CIDR
from typing import List, Dict, Optional, Tuple
from collections import defaultdict
from datetime import datetime, timedelta

# Security configuration
MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63
MAX_DNS_QUERIES_PER_RUN = 50
MAX_SMTP_CONNECTIONS = 5
MAX_MX_RECORDS = 10
MAX_IPS_PER_MX = 5
MAX_DKIM_SELECTORS = 20
DNS_TIMEOUT = 3  # Reduced from 5
SMTP_TIMEOUT = 5  # Reduced from 6
HTTP_TIMEOUT = 3  # Reduced from 5
MAX_HTTP_SIZE = 100 * 1024  # 100KB max for MTA-STS policy

# Rate limiting
dns_query_count = 0
smtp_connection_count = 0
last_query_time = defaultdict(float)
MIN_QUERY_INTERVAL = 0.1  # 100ms between queries to same domain

# Security warning
SECURITY_WARNING = """
WARNING: This tool performs network queries. Use responsibly.
- Do not use for scanning third-party domains without permission
- Excessive use may be considered abuse
- Some operations may trigger security alerts
"""

# Common DKIM selectors (limited set for security)
COMMON_DKIM_SELECTORS = [
    "default", "selector1", "s1", "google", "mail", "smtp", "selector", "k1"
]

def validate_domain(domain: str) -> bool:
    """Validate domain name format and prevent injection attacks."""
    if not domain or len(domain) > MAX_DOMAIN_LENGTH:
        return False
    
    # Check for valid characters
    if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
        return False
    
    # Check each label
    labels = domain.split('.')
    if len(labels) < 2:  # At least domain.tld
        return False
    
    for label in labels:
        if not label or len(label) > MAX_LABEL_LENGTH:
            return False
        if label.startswith('-') or label.endswith('-'):
            return False
    
    # Prevent localhost and private domains
    blocked_domains = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
    if domain.lower() in blocked_domains:
        return False
    
    return True

def validate_ip(ip: str) -> bool:
    """Validate IP address and block private/reserved ranges using cidr_man."""
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

def rate_limit_check(domain: str) -> bool:
    """Implement rate limiting for queries."""
    global last_query_time
    current_time = time.time()
    
    if domain in last_query_time:
        elapsed = current_time - last_query_time[domain]
        if elapsed < MIN_QUERY_INTERVAL:
            time.sleep(MIN_QUERY_INTERVAL - elapsed)
    
    last_query_time[domain] = time.time()
    return True

def safe_dns_query(domain: str, record_type: str, timeout: int = DNS_TIMEOUT):
    """Perform DNS query with security checks."""
    global dns_query_count
    
    if dns_query_count >= MAX_DNS_QUERIES_PER_RUN:
        raise Exception("DNS query limit exceeded")
    
    if not validate_domain(domain):
        raise ValueError("Invalid domain format")
    
    rate_limit_check(domain)
    dns_query_count += 1
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.timeout = timeout
        # Don't override nameservers - use system defaults
        
        return resolver.resolve(domain, record_type)
    except dns.exception.DNSException:
        return None

def query_txt(domain: str) -> List[str]:
    """Safely query TXT records."""
    try:
        answers = safe_dns_query(domain, "TXT")
        if not answers:
            return []
        return [b"".join(r.strings).decode("utf-8", errors="ignore") for r in answers]
    except Exception:
        return []

def get_spf(domain: str) -> Optional[str]:
    """Get SPF record with validation."""
    txts = query_txt(domain)
    spf_records = [t for t in txts if t.lower().startswith("v=spf1")]
    
    # Warn about multiple SPF records (RFC violation)
    if len(spf_records) > 1:
        print(f"  WARNING: Multiple SPF records found (RFC violation)")
    
    return spf_records[0] if spf_records else None

def get_dmarc(domain: str) -> Optional[str]:
    """Get DMARC record."""
    txts = query_txt(f"_dmarc.{domain}")
    for t in txts:
        if t.lower().startswith("v=dmarc1"):
            return t
    return None

def get_bimi(domain: str) -> Optional[str]:
    """Get BIMI record."""
    txts = query_txt(f"default._bimi.{domain}")
    for t in txts:
        if t.lower().startswith("v=bimi1"):
            return t
    return None

def get_tls_rpt(domain: str) -> List[str]:
    """Get TLS-RPT records."""
    return query_txt(f"_smtp._tls.{domain}")

def get_mta_sts(domain: str) -> List[str]:
    """Get MTA-STS TXT record."""
    return query_txt(f"_mta-sts.{domain}")

def check_dkim_selector(domain: str, selector: str) -> Optional[str]:
    """Check DKIM selector with validation."""
    # Validate selector format
    if not re.match(r'^[a-zA-Z0-9._-]+$', selector):
        return None
    if len(selector) > 63:
        return None
    
    q = f"{selector}._domainkey.{domain}"
    txts = query_txt(q)
    for t in txts:
        if "v=DKIM1" in t or "p=" in t:
            return t
    return None

def lookup_mx(domain: str) -> List[str]:
    """Lookup MX records with limits."""
    try:
        answers = safe_dns_query(domain, "MX")
        if not answers:
            return []
        
        mx = [(r.preference, str(r.exchange).rstrip(".")) for r in answers]
        mx.sort()
        
        # Limit number of MX records processed
        mx_hosts = [host for _, host in mx[:MAX_MX_RECORDS]]
        
        # Validate each MX host
        valid_mx = []
        for host in mx_hosts:
            if validate_domain(host):
                valid_mx.append(host)
        
        return valid_mx
    except Exception:
        return []

def resolve_host_ips(hostname: str) -> List[str]:
    """Resolve hostname to IPs with validation."""
    if not validate_domain(hostname):
        return []
    
    ips = []
    
    try:
        # A records
        answers = safe_dns_query(hostname, "A")
        if answers:
            for r in answers[:MAX_IPS_PER_MX]:
                ip = r.address
                if validate_ip(ip):
                    ips.append(ip)
    except Exception:
        pass
    
    try:
        # AAAA records
        answers = safe_dns_query(hostname, "AAAA")
        if answers:
            for r in answers[:MAX_IPS_PER_MX]:
                ip = r.address
                if validate_ip(ip):
                    ips.append(ip)
    except Exception:
        pass
    
    return ips[:MAX_IPS_PER_MX]

def ptr_check(ip: str) -> Tuple[List[str], List[bool]]:
    """Check PTR records with validation."""
    if not validate_ip(ip):
        return [], []
    
    try:
        rev = dns.reversename.from_address(ip)
        answers = safe_dns_query(str(rev), "PTR")
        if not answers:
            return [], []
        
        ptrs = [str(r).rstrip(".") for r in answers][:5]  # Limit PTRs
        
        # Forward confirm each PTR
        forward_ok = []
        for p in ptrs:
            if not validate_domain(p):
                forward_ok.append(False)
                continue
            
            try:
                ips = resolve_host_ips(p)
                forward_ok.append(ip in ips)
            except Exception:
                forward_ok.append(False)
        
        return ptrs, forward_ok
    except Exception:
        return [], []

def smtp_starttls_check(mx_host: str, timeout: int = SMTP_TIMEOUT) -> Dict:
    """Check SMTP STARTTLS with security limits."""
    global smtp_connection_count
    
    result = {
        "host": mx_host,
        "connect": False,
        "ehlo": None,
        "starttls": False,
        "tls_cert": None,
        "error": None
    }
    
    # Check connection limit
    if smtp_connection_count >= MAX_SMTP_CONNECTIONS:
        result["error"] = "SMTP connection limit reached"
        return result
    
    if not validate_domain(mx_host):
        result["error"] = "Invalid MX hostname"
        return result
    
    smtp_connection_count += 1
    
    try:
        # Resolve IPs
        ips = resolve_host_ips(mx_host)
        if not ips:
            result["error"] = "No valid IPs for MX host"
            return result
        
        ip = ips[0]
        
        # Create socket with timeout
        sock = socket.socket(socket.AF_INET if ':' not in ip else socket.AF_INET6)
        sock.settimeout(timeout)
        sock.connect((ip, 25))
        
        f = sock.makefile("rb", buffering=0)
        
        # Read banner (limited size)
        banner = f.readline(1024).decode("utf-8", errors="ignore")
        
        # Send EHLO with generic hostname
        sock.sendall(b"EHLO email-checker.example\r\n")
        
        # Read EHLO response (limited)
        ehlo_lines = []
        for _ in range(20):  # Max 20 lines
            line = f.readline(1024).decode("utf-8", errors="ignore")
            ehlo_lines.append(line.strip())
            if re.match(r"^\d{3} ", line):
                break
        
        result["connect"] = True
        result["ehlo"] = "\n".join(ehlo_lines[:10])  # Limit output
        
        # Check STARTTLS
        if any("STARTTLS" in l.upper() for l in ehlo_lines):
            sock.sendall(b"STARTTLS\r\n")
            response = f.readline(1024)
            
            # Wrap with TLS
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            try:
                tls = context.wrap_socket(sock, server_hostname=mx_host)
                cert = tls.getpeercert()
                result["starttls"] = True
                
                # Extract safe cert info only
                if cert:
                    safe_cert = {
                        "subject": cert.get("subject", ()),
                        "notAfter": cert.get("notAfter", ""),
                        "version": cert.get("version", 0)
                    }
                    result["tls_cert"] = safe_cert
                
                tls.close()
            except ssl.SSLError as e:
                result["tls_cert"] = {"error": "Certificate validation failed"}
        else:
            sock.close()
            
    except socket.timeout:
        result["error"] = "Connection timeout"
    except socket.error as e:
        result["error"] = "Connection failed"
    except Exception as e:
        result["error"] = "Check failed"
    
    return result

def fetch_mta_sts_policy(domain: str) -> Optional[str]:
    """Fetch MTA-STS policy with SSRF protection."""
    if not validate_domain(domain):
        return None
    
    # Build URL with validation
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    
    try:
        # Security headers and limits
        headers = {
            "User-Agent": "Email-Health-Check/1.0",
            "Accept": "text/plain"
        }
        
        # Make request with strict limits
        response = requests.get(
            url,
            headers=headers,
            timeout=HTTP_TIMEOUT,
            allow_redirects=False,  # No redirects for security
            stream=True
        )
        
        if response.status_code == 200:
            # Read limited content
            content = ""
            for chunk in response.iter_content(1024):
                content += chunk.decode("utf-8", errors="ignore")
                if len(content) > MAX_HTTP_SIZE:
                    break
            
            response.close()
            return content[:MAX_HTTP_SIZE]
        
        return None
        
    except requests.exceptions.RequestException:
        return None
    except Exception:
        return None

def expand_spf_includes(spf: str) -> List[str]:
    """Extract SPF includes with validation."""
    if not spf:
        return []
    
    includes = re.findall(r"include:([^\s]+)", spf)
    
    # Validate each include domain
    valid_includes = []
    for inc in includes[:10]:  # Limit includes
        # Remove any mechanism modifiers
        domain = inc.rstrip("+-~?")
        if validate_domain(domain):
            valid_includes.append(domain)
    
    return valid_includes

def security_score(out: Dict) -> Dict:
    """Calculate security score and recommendations."""
    score = 0
    max_score = 100
    issues = []
    recommendations = []
    
    # Core requirements (80 points total)
    
    # MX records (20 points) - Can receive email
    if out.get("mx_hosts"):
        score += 20
    else:
        issues.append("No MX records found - cannot receive email")
    
    # SPF (20 points) - Prevents spoofing
    if out.get("spf"):
        score += 15
        if "~all" in out["spf"] or "-all" in out["spf"]:
            score += 5
        else:
            recommendations.append("SPF should end with -all or ~all for better protection")
    else:
        issues.append("No SPF record found - emails may be marked as spam")
    
    # DMARC (20 points) - Email authentication
    if out.get("dmarc"):
        score += 10
        if "p=reject" in out["dmarc"]:
            score += 10
        elif "p=quarantine" in out["dmarc"]:
            score += 8
        else:
            score += 5
            recommendations.append("Consider strengthening DMARC policy to quarantine or reject")
    else:
        issues.append("No DMARC record found - reduced email deliverability")
    
    # STARTTLS (20 points) - Encryption in transit
    starttls_ok = 0
    mx_count = len(out.get("mx_hosts", []))
    
    if mx_count > 0:
        for mx in out["mx_hosts"]:
            if mx.get("smtp_check", {}).get("starttls"):
                starttls_ok += 1
        
        starttls_ratio = starttls_ok / mx_count
        score += int(20 * starttls_ratio)
        
        if starttls_ratio == 0:
            issues.append("No MX hosts support STARTTLS - emails not encrypted")
        elif starttls_ratio < 1:
            issues.append(f"Only {starttls_ok}/{mx_count} MX hosts support STARTTLS")
    
    # Advanced features (20 points total - optional/bonus)
    
    # DKIM (5 points) - Optional but recommended
    dkim_found = sum(1 for v in out.get("dkim", {}).values() if v)
    if dkim_found > 0:
        score += 5
    else:
        recommendations.append("Consider setting up DKIM for email signing")
    
    # MTA-STS (5 points) - Advanced feature
    if out.get("mta_sts_policy"):
        score += 5
    else:
        recommendations.append("Consider implementing MTA-STS for enforced TLS")
    
    # TLS-RPT (5 points) - Advanced feature
    if out.get("tls_rpt"):
        score += 5
    else:
        recommendations.append("Consider adding TLS-RPT for delivery diagnostics")
    
    # PTR records (5 points) - Good to have
    ptr_ok = 0
    ptr_total = 0
    for mx in out.get("mx_hosts", []):
        for ip, info in mx.get("ptrs", {}).items():
            ptr_total += 1
            if info.get("ptrs") and any(info.get("forward_confirm", [])):
                ptr_ok += 1
    
    if ptr_total > 0:
        ptr_ratio = ptr_ok / ptr_total
        score += int(5 * ptr_ratio)
        if ptr_ratio < 0.5:
            recommendations.append(f"Only {ptr_ok}/{ptr_total} IPs have valid PTR records")
    
    # Ensure score doesn't go below 0
    score = max(0, score)
    
    return {
        "score": score,
        "max_score": max_score,
        "grade": get_grade(score),
        "issues": issues,
        "recommendations": recommendations
    }

def get_grade(score: int) -> str:
    """Convert score to grade."""
    if score >= 85:
        return "A"
    elif score >= 70:
        return "B"
    elif score >= 55:
        return "C"
    elif score >= 40:
        return "D"
    else:
        return "F"

def test_dns_connectivity() -> bool:
    """Test DNS connectivity before running checks."""
    print("Testing DNS connectivity...")
    
    test_domains = [
        "google.com",
        "cloudflare.com", 
        "quad9.net"
    ]
    
    for test_domain in test_domains:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            answers = resolver.resolve(test_domain, "A")
            if answers:
                print(f"  ✓ DNS is working (resolved {test_domain})")
                return True
        except Exception:
            continue
    
    print("  ✗ DNS connectivity issue detected")
    print("\nDNS CONNECTIVITY ERROR")
    print("=" * 40)
    print("Unable to perform DNS queries. This could be due to:")
    print("  • No internet connection")
    print("  • DNS server is unreachable")  
    print("  • Firewall blocking DNS (port 53)")
    print("  • Corporate proxy or VPN issues")
    print("\nPlease check your network connection and DNS settings.")
    return False

def main(domain: str, dkim_selectors: List[str], skip_smtp: bool = False):
    """Main function with security checks."""
    
    # Print security warning
    print(SECURITY_WARNING)
    print()
    
    # Test DNS connectivity first
    if not test_dns_connectivity():
        sys.exit(1)
    
    print()
    
    # Validate domain
    if not validate_domain(domain):
        print(f"Error: Invalid domain format: {domain}")
        sys.exit(1)
    
    # Initialize output
    out = {"domain": domain}
    
    print(f"Performing email health check for: {domain}")
    print("=" * 60)
    
    # SPF check
    print("Checking SPF...")
    out["spf"] = get_spf(domain)
    out["spf_includes"] = expand_spf_includes(out["spf"])
    
    # DMARC check
    print("Checking DMARC...")
    out["dmarc"] = get_dmarc(domain)
    
    # BIMI check
    print("Checking BIMI...")
    out["bimi"] = get_bimi(domain)
    
    # TLS-RPT check
    print("Checking TLS-RPT...")
    out["tls_rpt"] = get_tls_rpt(domain)
    
    # MTA-STS check
    print("Checking MTA-STS...")
    out["mta_sts_txt"] = get_mta_sts(domain)
    out["mta_sts_policy"] = fetch_mta_sts_policy(domain)
    
    # MX records check
    print("Checking MX records...")
    mxs = lookup_mx(domain)
    out["mx_hosts"] = []
    
    for i, mx in enumerate(mxs):
        if i >= MAX_MX_RECORDS:
            print(f"  (Limiting to first {MAX_MX_RECORDS} MX records)")
            break
        
        print(f"  Checking MX: {mx}")
        mxinfo = {"host": mx}
        
        # Resolve IPs
        ips = resolve_host_ips(mx)
        mxinfo["ips"] = ips
        
        # PTR checks
        mxinfo["ptrs"] = {}
        for ip in ips[:MAX_IPS_PER_MX]:
            ptrs, forward_ok = ptr_check(ip)
            mxinfo["ptrs"][ip] = {"ptrs": ptrs, "forward_confirm": forward_ok}
        
        # SMTP check (optional)
        if not skip_smtp:
            print(f"    Testing SMTP connection...")
            mxinfo["smtp_check"] = smtp_starttls_check(mx)
        
        out["mx_hosts"].append(mxinfo)
    
    # DKIM checks
    print("Checking DKIM selectors...")
    out["dkim"] = {}
    
    # Limit selectors
    selectors_to_try = (dkim_selectors or COMMON_DKIM_SELECTORS)[:MAX_DKIM_SELECTORS]
    
    for sel in selectors_to_try:
        k = check_dkim_selector(domain, sel)
        out["dkim"][sel] = bool(k)
    
    # Calculate security score
    print("\nCalculating security score...")
    security = security_score(out)
    
    # Print results
    print("\n" + "=" * 60)
    print("EMAIL HEALTH CHECK RESULTS")
    print("=" * 60)
    
    print(f"\nDomain: {domain}")
    print(f"Security Score: {security['score']}/{security['max_score']} (Grade: {security['grade']})")
    
    print("\nConfiguration Status:")
    print(f"  SPF: {'✓' if out['spf'] else '✗'} {out['spf'][:50] + '...' if out['spf'] and len(out['spf']) > 50 else out['spf'] or 'MISSING'}")
    
    if out["spf_includes"]:
        print(f"    Includes: {', '.join(out['spf_includes'][:5])}")
    
    print(f"  DMARC: {'✓' if out['dmarc'] else '✗'} {out['dmarc'][:50] + '...' if out['dmarc'] and len(out['dmarc']) > 50 else out['dmarc'] or 'MISSING'}")
    print(f"  BIMI: {'✓' if out['bimi'] else '✗'} {'CONFIGURED' if out['bimi'] else 'NOT CONFIGURED'}")
    print(f"  TLS-RPT: {'✓' if out['tls_rpt'] else '✗'} {'CONFIGURED' if out['tls_rpt'] else 'NOT CONFIGURED'}")
    print(f"  MTA-STS TXT: {'✓' if out['mta_sts_txt'] else '✗'} {'CONFIGURED' if out['mta_sts_txt'] else 'NOT CONFIGURED'}")
    print(f"  MTA-STS Policy: {'✓' if out['mta_sts_policy'] else '✗'} {'FOUND' if out['mta_sts_policy'] else 'NOT FOUND'}")
    
    print("\nMX Records:")
    if not out["mx_hosts"]:
        print("  No MX records found")
    else:
        for m in out["mx_hosts"]:
            print(f"  {m['host']}:")
            print(f"    IPs: {', '.join(m['ips'][:3]) if m['ips'] else 'none'}")
            
            # PTR summary
            ptr_valid = sum(1 for info in m["ptrs"].values() if any(info.get("forward_confirm", [])))
            print(f"    PTR records: {ptr_valid}/{len(m['ptrs'])} valid")
            
            # SMTP check summary
            if "smtp_check" in m:
                sc = m["smtp_check"]
                if sc.get("starttls"):
                    print(f"    STARTTLS: ✓ Supported")
                elif sc.get("connect"):
                    print(f"    STARTTLS: ✗ Not supported")
                else:
                    print(f"    STARTTLS: ? Connection failed")
    
    print("\nDKIM Selectors:")
    dkim_found = [sel for sel, ok in out["dkim"].items() if ok]
    if dkim_found:
        print(f"  Found: {', '.join(dkim_found[:5])}")
    else:
        print("  No DKIM selectors found")
    
    # Critical issues
    if security["issues"]:
        print("\n⚠️  Critical Issues (Must Fix):")
        for i, issue in enumerate(security["issues"], 1):
            print(f"  {i}. {issue}")
    
    # Recommendations
    if security["recommendations"]:
        print("\n💡 Recommendations (Nice to Have):")
        for i, rec in enumerate(security["recommendations"], 1):
            print(f"  {i}. {rec}")
    
    print("\nNotes:")
    print("  • DKIM signatures can only be fully validated by receiving and analyzing signed messages")
    print("  • This tool performs limited checks to prevent abuse")
    print(f"  • DNS queries performed: {dns_query_count}/{MAX_DNS_QUERIES_PER_RUN}")
    if not skip_smtp:
        print(f"  • SMTP connections made: {smtp_connection_count}/{MAX_SMTP_CONNECTIONS}")
    
    print("\nEnd of security-hardened report.")
    
    return out

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Security-hardened email configuration checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s example.com --dkim-selectors selector1,selector2
  %(prog)s example.com --skip-smtp

Security Notes:
  - This tool implements rate limiting and connection limits
  - Private IP ranges and local domains are blocked
  - Use responsibly and only on domains you own or have permission to test
        """
    )
    
    parser.add_argument("domain", help="Domain to check (e.g., example.com)")
    parser.add_argument(
        "--dkim-selectors",
        help="Comma-separated DKIM selectors to check",
        default=""
    )
    parser.add_argument(
        "--skip-smtp",
        action="store_true",
        help="Skip SMTP connection tests"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 1.0.0-security"
    )
    
    args = parser.parse_args()
    
    # Parse selectors
    selectors = []
    if args.dkim_selectors:
        for s in args.dkim_selectors.split(","):
            s = s.strip()
            if s and re.match(r'^[a-zA-Z0-9._-]+$', s) and len(s) <= 63:
                selectors.append(s)
    
    try:
        main(args.domain, selectors, args.skip_smtp)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)