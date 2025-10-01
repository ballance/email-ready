#!/usr/bin/env python3
"""
email_health_check.py

Checks SPF, DMARC, DKIM (public keys), MX, PTR, MTA-STS, TLS-RPT, BIMI, and basic SMTP STARTTLS cert info for a domain.

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
from typing import List

resolver = dns.resolver.Resolver()
resolver.lifetime = 5
resolver.timeout = 5

COMMON_DKIM_SELECTORS = [
    "default", "selector1", "s1", "google", "mail", "smtp", "selector", "k1"
]

def query_txt(domain: str):
    try:
        answers = resolver.resolve(domain, "TXT")
        return [b"".join(r.strings).decode("utf-8") for r in answers]
    except dns.exception.DNSException:
        return []

def get_spf(domain: str):
    txts = query_txt(domain)
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    return spf[0] if spf else None

def get_dmarc(domain: str):
    txts = query_txt("_dmarc." + domain)
    for t in txts:
        if t.lower().startswith("v=dmarc1"):
            return t
    return None

def get_bimi(domain: str):
    txts = query_txt("default._bimi." + domain)
    for t in txts:
        if t.lower().startswith("v=bimi1"):
            return t
    return None

def get_tls_rpt(domain: str):
    txts = query_txt("_smtp._tls." + domain)
    return txts

def get_mta_sts(domain: str):
    txts = query_txt("_mta-sts." + domain)
    # There is also a policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt
    return txts

def check_dkim_selector(domain: str, selector: str):
    q = f"{selector}._domainkey.{domain}"
    txts = query_txt(q)
    for t in txts:
        if "v=DKIM1" in t or "p=" in t:
            return t
    return None

def lookup_mx(domain: str):
    try:
        ans = resolver.resolve(domain, "MX")
        mx = [(r.preference, str(r.exchange).rstrip(".")) for r in ans]
        mx.sort()
        return [host for _, host in mx]
    except dns.exception.DNSException:
        return []

def resolve_host_ips(hostname: str):
    ips = []
    try:
        a = resolver.resolve(hostname, "A")
        ips += [r.address for r in a]
    except dns.exception.DNSException:
        pass
    try:
        aaaa = resolver.resolve(hostname, "AAAA")
        ips += [r.address for r in aaaa]
    except dns.exception.DNSException:
        pass
    return ips

def ptr_check(ip: str):
    try:
        rev = dns.reversename.from_address(ip)
        ans = resolver.resolve(rev, "PTR")
        ptrs = [str(r).rstrip(".") for r in ans]
        # forward confirm each ptr resolves back to ip
        forward_ok = []
        for p in ptrs:
            try:
                ips = resolve_host_ips(p)
                forward_ok.append(ip in ips)
            except Exception:
                forward_ok.append(False)
        return ptrs, forward_ok
    except dns.exception.DNSException:
        return [], []

def smtp_starttls_check(mx_host: str, timeout=6):
    result = {"host": mx_host, "connect": False, "ehlo": None, "starttls": False, "tls_cert": None, "error": None}
    try:
        # Resolve an IP to connect to
        ips = resolve_host_ips(mx_host)
        if not ips:
            result["error"] = "No A/AAAA records for MX host"
            return result
        ip = ips[0]
        sock = socket.create_connection((ip, 25), timeout=timeout)
        f = sock.makefile("rb", buffering=0)
        # read banner
        banner = f.readline().decode(errors="ignore")
        # send EHLO
        sock.sendall(b"EHLO email-checker.example\r\n")
        ehlo_lines = []
        while True:
            line = f.readline().decode(errors="ignore")
            ehlo_lines.append(line.strip())
            if re.match(r"^\d{3} ", line):
                break
        result["connect"] = True
        result["ehlo"] = "\n".join(ehlo_lines)
        # check if STARTTLS present
        if any("STARTTLS" in l.upper() for l in ehlo_lines):
            sock.sendall(b"STARTTLS\r\n")
            _ = f.readline()  # response
            context = ssl.create_default_context()
            tls = context.wrap_socket(sock, server_hostname=mx_host)
            cert = tls.getpeercert()
            result["starttls"] = True
            result["tls_cert"] = cert
            try:
                tls.close()
            except Exception:
                pass
        else:
            sock.close()
    except Exception as e:
        result["error"] = str(e)
    return result

def fetch_mta_sts_policy(domain: str):
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            return r.text
        return None
    except Exception:
        return None

def expand_spf_includes(spf: str):
    # naive: extract "include:domain" tokens
    includes = re.findall(r"include:([^\s]+)", spf or "")
    return includes

def main(domain: str, dkim_selectors: List[str]):
    out = {"domain": domain}
    out["spf"] = get_spf(domain)
    out["spf_includes"] = expand_spf_includes(out["spf"])
    out["dmarc"] = get_dmarc(domain)
    out["bimi"] = get_bimi(domain)
    out["tls_rpt"] = get_tls_rpt(domain)
    out["mta_sts_txt"] = get_mta_sts(domain)
    out["mta_sts_policy_url"] = fetch_mta_sts_policy(domain)
    mxs = lookup_mx(domain)
    out["mx_hosts"] = []
    for mx in mxs:
        mxinfo = {"host": mx}
        ips = resolve_host_ips(mx)
        mxinfo["ips"] = ips
        # PTRs for each ip
        mxinfo["ptrs"] = {}
        for ip in ips:
            ptrs, forward_ok = ptr_check(ip)
            mxinfo["ptrs"][ip] = {"ptrs": ptrs, "forward_confirm": forward_ok}
        # smtp check
        mxinfo["smtp_check"] = smtp_starttls_check(mx)
        out["mx_hosts"].append(mxinfo)
    # DKIM checks
    out["dkim"] = {}
    selectors_to_try = dkim_selectors or COMMON_DKIM_SELECTORS
    for sel in selectors_to_try:
        k = check_dkim_selector(domain, sel)
        out["dkim"][sel] = bool(k)
    # print summary
    print("\nEMAIL HEALTH CHECK for", domain)
    print("="*60)
    print("SPF:", out["spf"] or "MISSING")
    if out["spf_includes"]:
        print(" SPF includes:", ", ".join(out["spf_includes"]))
    print("DMARC:", out["dmarc"] or "MISSING")
    print("BIMI:", out["bimi"] or "MISSING")
    print("TLS-RPT TXT:", out["tls_rpt"] or "MISSING")
    print("MTA-STS TXT:", out["mta_sts_txt"] or "MISSING")
    print("MTA-STS policy (https):", "FOUND" if out["mta_sts_policy_url"] else "MISSING")
    print("\nMX Checks:")
    if not out["mx_hosts"]:
        print(" No MX records found")
    for m in out["mx_hosts"]:
        print("- MX host:", m["host"])
        print("  IPs:", ", ".join(m["ips"]) if m["ips"] else "none")
        for ip, info in m["ptrs"].items():
            print(f"   PTR {ip} -> {info['ptrs']} forward-confirm:", info["forward_confirm"])
        sc = m["smtp_check"]
        if sc.get("connect"):
            print("  SMTP: connect ok")
            print("   EHLO response preview:", (sc.get("ehlo") or "").splitlines()[0] if sc.get("ehlo") else "n/a")
            print("   STARTTLS available:", sc.get("starttls"))
            if sc.get("tls_cert"):
                cert = sc.get("tls_cert")
                subj = cert.get('subject', ())
                cn = None
                for s in subj:
                    for k, v in s:
                        if k.lower() == 'commonname':
                            cn = v
                print("   TLS cert CN:", cn)
        else:
            print("  SMTP: connection failed:", sc.get("error"))
    print("\nDKIM selectors checked (presence of public key in DNS):")
    for sel, ok in out["dkim"].items():
        print(f"  {sel}: {'FOUND' if ok else 'missing'}")
    print("\nNotes:")
    print(" - You cannot validate DKIM signature handling without sending a signed message and inspecting headers.")
    print(" - If DMARC is missing, receivers may not trust your mail. Consider publishing a DMARC TXT at _dmarc.<domain> with v=DMARC1; p=none|quarantine|reject; pct=100")
    print(" - If SPF exists, ensure it covers all sending IPs and includes for third-party senders.")
    print(" - For MTA-STS, publish _mta-sts TXT plus policy at https://mta-sts.<domain>/.well-known/mta-sts.txt")
    print("\nEnd of report.")
    return out

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Email health check for domain")
    parser.add_argument("domain", help="domain to check (example.com)")
    parser.add_argument("--dkim-selectors", help="comma separated DKIM selectors to check", default="")
    args = parser.parse_args()
    selectors = [s.strip() for s in args.dkim_selectors.split(",") if s.strip()] if args.dkim_selectors else []
    main(args.domain, selectors)
