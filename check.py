#!/usr/bin/env python3
"""
Business Email Health Check

Checks if your business email is configured correctly.
Written in plain English. No technical knowledge needed.
"""

import sys
import time
import socket
import dns.resolver


class BusinessEmailChecker:
    """Checks business email setup using plain language."""
    
    def __init__(self):
        """Set up the checker."""
        self.domain = None
        self.can_receive_email = False
        self.has_spam_protection = False
        self.has_authenticity_check = False
        self.has_encryption = False
        self.problems = []
        self.solutions = []
    
    def explain_why_this_matters(self):
        """Explain why email configuration matters in business terms."""
        print("""
WHY YOUR EMAIL CONFIGURATION MATTERS
=====================================

Poor email setup can cause:
• Lost sales when customer emails bounce
• Your emails landing in spam folders
• Scammers impersonating your business
• Sensitive information being exposed
• Damage to your business reputation

This check takes about 30 seconds and will tell you:
• If customers can reach you by email
• If your emails look legitimate to Gmail, Outlook, etc.
• If your email is protected from hackers
• Exactly what to tell your IT team to fix any issues

Let's begin...
        """)
        time.sleep(3)
    
    def check_if_email_works(self):
        """Check if the domain can receive email."""
        print("\n1. Can customers send you email?")
        print("   Checking...", end="", flush=True)
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            answers = resolver.resolve(self.domain, "MX")
            
            if answers:
                print(" YES")
                print("   Your email is delivered to:", str(answers[0].exchange).rstrip("."))
                self.can_receive_email = True
                return True
        except:
            pass
        
        print(" NO - CRITICAL PROBLEM")
        print("   Customer emails to your domain will bounce back.")
        self.problems.append(
            "Your domain cannot receive email. All incoming emails will fail."
        )
        self.solutions.append(
            "Ask your email provider to set up MX records for your domain."
        )
        return False
    
    def check_spam_protection(self):
        """Check if spam protection is configured."""
        print("\n2. Are you protected from email spoofing?")
        print("   Checking...", end="", flush=True)
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            answers = resolver.resolve(self.domain, "TXT")
            
            for record in answers:
                text = b"".join(record.strings).decode("utf-8", errors="ignore")
                if text.lower().startswith("v=spf1"):
                    print(" YES")
                    print("   Spoof protection is active.")
                    self.has_spam_protection = True
                    return True
        except:
            pass
        
        print(" NO - SECURITY RISK")
        print("   Anyone can send emails pretending to be from your company.")
        self.problems.append(
            "No protection against email spoofing. Scammers can impersonate you."
        )
        self.solutions.append(
            "Add an SPF record. Tell your IT team: 'We need an SPF TXT record in our DNS.'"
        )
        return False
    
    def check_authenticity(self):
        """Check if email authenticity verification is set up."""
        print("\n3. Will email providers trust your emails?")
        print("   Checking...", end="", flush=True)
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            dmarc_domain = f"_dmarc.{self.domain}"
            answers = resolver.resolve(dmarc_domain, "TXT")
            
            for record in answers:
                text = b"".join(record.strings).decode("utf-8", errors="ignore")
                if text.lower().startswith("v=dmarc1"):
                    print(" YES")
                    
                    # Explain the policy in business terms
                    if "p=reject" in text.lower():
                        print("   Strong protection: Fake emails are blocked.")
                    elif "p=quarantine" in text.lower():
                        print("   Moderate protection: Suspicious emails go to spam.")
                    else:
                        print("   Basic monitoring: You track fake emails but don't block them yet.")
                    
                    self.has_authenticity_check = True
                    return True
        except:
            pass
        
        print(" PARTIALLY")
        print("   Gmail and Outlook may mark your emails as suspicious.")
        self.problems.append(
            "Missing email authentication. Your emails might go to spam folders."
        )
        self.solutions.append(
            "Add a DMARC policy. Tell your IT team: 'Set up DMARC starting with p=none.'"
        )
        return False
    
    def check_encryption(self):
        """Check if email is encrypted during delivery."""
        print("\n4. Is your email encrypted during delivery?")
        print("   Checking...", end="", flush=True)
        
        if not self.can_receive_email:
            print(" SKIPPED")
            print("   (No email server to test)")
            return False
        
        try:
            # Get mail server address
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            answers = resolver.resolve(self.domain, "MX")
            mx_host = str(answers[0].exchange).rstrip(".")
            
            # Test connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((mx_host, 25))
            
            # Get greeting
            greeting = sock.recv(1024)
            
            # Say hello
            sock.send(b"EHLO test.example.com\r\n")
            
            # Check response
            response = b""
            for _ in range(10):
                chunk = sock.recv(1024)
                response += chunk
                if b"250 " in chunk:
                    break
            
            sock.close()
            
            if b"STARTTLS" in response.upper():
                print(" YES")
                print("   Your email is protected like online banking.")
                self.has_encryption = True
                return True
            else:
                print(" NO - PRIVACY RISK")
                print("   Your emails are like postcards - anyone can read them.")
                self.problems.append(
                    "Emails are not encrypted. They could be intercepted and read."
                )
                self.solutions.append(
                    "Enable email encryption. Tell your IT team: 'Enable STARTTLS on port 25.'"
                )
                return False
        except:
            print(" COULD NOT TEST")
            print("   (This test may be blocked by your network)")
            return False
    
    def calculate_risk_level(self):
        """Determine business risk level."""
        score = 0
        if self.can_receive_email:
            score += 25
        if self.has_spam_protection:
            score += 25
        if self.has_authenticity_check:
            score += 25
        if self.has_encryption:
            score += 25
        
        if score >= 75:
            return "LOW RISK", score
        elif score >= 50:
            return "MODERATE RISK", score
        else:
            return "HIGH RISK", score
    
    def generate_business_report(self):
        """Create a business-friendly report."""
        risk_level, score = self.calculate_risk_level()
        
        print("\n" + "="*50)
        print("BUSINESS EMAIL HEALTH REPORT")
        print("="*50)
        
        print(f"\nDomain tested: {self.domain}")
        print(f"Date: {time.strftime('%B %d, %Y')}")
        print(f"\nRISK LEVEL: {risk_level} ({score}/100)")
        
        # Business impact summary
        print("\nWHAT THIS MEANS FOR YOUR BUSINESS:")
        print("-"*35)
        
        if risk_level == "HIGH RISK":
            print("""
IMMEDIATE ACTION REQUIRED

Your email configuration has serious problems that could:
• Prevent you from receiving customer emails
• Cause your emails to be blocked as spam
• Allow criminals to impersonate your business
• Expose confidential information

You should fix these issues immediately to protect your
business reputation and ensure reliable communication.
            """)
        elif risk_level == "MODERATE RISK":
            print("""
IMPROVEMENTS RECOMMENDED

Your email works but has security gaps that could:
• Reduce email delivery success
• Make it easier for scammers to impersonate you
• Cause some emails to go to spam folders

These issues should be addressed soon to improve
email reliability and security.
            """)
        else:
            print("""
GOOD CONFIGURATION

Your email setup follows industry best practices.
Continue to monitor your email configuration quarterly
to ensure it remains secure and properly configured.
            """)
        
        # Specific problems and solutions
        if self.problems:
            print("\nPROBLEMS FOUND:")
            print("-"*15)
            for i, problem in enumerate(self.problems, 1):
                print(f"\n{i}. {problem}")
            
            print("\n\nWHAT YOUR IT TEAM NEEDS TO DO:")
            print("-"*30)
            for i, solution in enumerate(self.solutions, 1):
                print(f"\n{i}. {solution}")
        
        # Next steps
        print("\n\nNEXT STEPS:")
        print("-"*11)
        if risk_level == "HIGH RISK":
            print("""
1. Share this report with your IT team immediately
2. If you don't have IT support, contact your email provider
3. Request they fix the issues listed above
4. Re-run this check after fixes are applied
            """)
        else:
            print("""
1. Save this report for your records
2. Share with your IT team for awareness
3. Schedule a quarterly check of your email configuration
4. Monitor your email delivery rates for any issues
            """)
        
        # Simple glossary at the end
        if self.problems:
            print("\n\nSIMPLE DEFINITIONS:")
            print("-"*18)
            print("""
MX Records = Email delivery address (like a mailing address)
SPF = List of who's allowed to send email for you
DMARC = Rules for handling suspicious emails
Encryption = Scrambling emails so only recipient can read them
            """)
    
    def test_dns_connectivity(self):
        """Test DNS connectivity before running checks."""
        print("\nTesting DNS connectivity...")
        print("   Checking...", end="", flush=True)
        
        test_domains = ["google.com", "cloudflare.com", "quad9.net"]
        
        for test_domain in test_domains:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 3
                answers = resolver.resolve(test_domain, "A")
                if answers:
                    print(" YES")
                    print(f"   DNS is working properly")
                    return True
            except:
                continue
        
        print(" NO - CRITICAL PROBLEM")
        print("""
   
DNS CONNECTIVITY PROBLEM
========================

Your computer cannot perform DNS lookups. This could be because:

• No internet connection
• Your DNS server is down
• Firewall is blocking DNS
• VPN or proxy issues

WHAT TO DO:
-----------
1. Check your internet connection
2. Try restarting your router/modem
3. Contact your IT department
4. Check if you're connected to VPN

This check cannot continue without DNS working.
        """)
        return False
    
    def run_check(self, domain):
        """Run all checks and generate report."""
        self.domain = domain
        
        print("\n" + "="*50)
        print("BUSINESS EMAIL HEALTH CHECK")
        print(f"Checking: {domain}")
        print("="*50)
        
        # Test DNS connectivity first
        if not self.test_dns_connectivity():
            print("\n" + "="*50)
            print("CHECK ABORTED - DNS NOT WORKING")
            print("="*50)
            return
        
        self.explain_why_this_matters()
        
        print("\nRUNNING CHECKS")
        print("="*50)
        
        # Run all checks
        self.check_if_email_works()
        self.check_spam_protection()
        self.check_authenticity()
        self.check_encryption()
        
        # Generate report
        self.generate_business_report()
        
        print("\n" + "="*50)
        print("END OF REPORT")
        print("="*50)


def clean_domain_input(user_input):
    """Clean up common input mistakes."""
    domain = user_input.lower().strip()
    
    # Remove common prefixes
    prefixes = ["http://", "https://", "www.", "mail.", "email."]
    for prefix in prefixes:
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    
    # Remove everything after first slash
    if "/" in domain:
        domain = domain.split("/")[0]
    
    # Handle email addresses
    if "@" in domain:
        domain = domain.split("@")[-1]
    
    return domain


def validate_domain_format(domain):
    """Check if domain looks valid."""
    # Must have at least one dot
    if "." not in domain:
        return False, "Missing extension (like .com or .org)"
    
    # Check length
    if len(domain) > 253:
        return False, "Too long to be a valid domain"
    
    # Check for spaces or invalid characters
    if " " in domain:
        return False, "Contains spaces"
    
    # Basic character check
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789.-"
    if not all(c in allowed for c in domain):
        return False, "Contains invalid characters"
    
    # Don't allow local addresses
    blocked = ["localhost", "127.0.0.1", "0.0.0.0", "example.com", "test.com"]
    if domain in blocked:
        return False, "This is a test domain, not a real business domain"
    
    return True, "Valid"


def main():
    """Main entry point."""
    
    # Check if user provided a domain
    if len(sys.argv) < 2:
        print("""
BUSINESS EMAIL HEALTH CHECK
===========================

This tool checks if your business email is properly configured.

HOW TO USE:
-----------
Type: python check.py yourbusiness.com

Replace 'yourbusiness.com' with your actual domain name.

EXAMPLES:
---------
python check.py acme-corp.com
python check.py mybusiness.org
python check.py company.co.uk

COMMON QUESTIONS:
-----------------
Q: What's my domain?
A: It's the part after @ in your email address.
   If your email is john@acme.com, your domain is acme.com

Q: How long does this take?
A: About 30 seconds

Q: Is this safe?
A: Yes, this only reads public information about your domain

Q: Who should see the results?
A: Share the report with your IT team or email provider

Need help? Contact your IT support team.
        """)
        sys.exit(0)
    
    # Get and clean domain
    user_input = sys.argv[1]
    domain = clean_domain_input(user_input)
    
    # Validate domain
    is_valid, message = validate_domain_format(domain)
    
    if not is_valid:
        print(f"""
ERROR: '{user_input}' doesn't look like a valid domain.

Problem: {message}

WHAT TO DO:
-----------
Enter just your domain name, like: mybusiness.com

Don't include:
• http:// or https://
• www. at the beginning  
• Your email address (just the part after @)
• Any slashes or paths

EXAMPLES OF CORRECT FORMAT:
• acme.com ✓
• mybusiness.org ✓  
• company.co.uk ✓

EXAMPLES OF INCORRECT FORMAT:
• https://www.acme.com ✗ (remove https://www.)
• john@acme.com ✗ (just use acme.com)
• acme.com/contact ✗ (remove /contact)
• acme ✗ (needs .com, .org, etc.)

Please try again with just your domain name.
        """)
        sys.exit(1)
    
    # Show cleaned domain if different
    if domain != user_input:
        print(f"\nNote: Checking '{domain}' (cleaned from '{user_input}')")
    
    # Run the check
    try:
        checker = BusinessEmailChecker()
        checker.run_check(domain)
        
    except KeyboardInterrupt:
        print("\n\nCheck cancelled. You can run it again anytime.")
        sys.exit(0)
        
    except Exception as e:
        print(f"""
TECHNICAL ERROR
===============

The check encountered an error:
{str(e)}

POSSIBLE CAUSES:
• The domain might not exist
• Your internet connection might be down
• The domain's servers might be unreachable

WHAT TO DO:
1. Verify you spelled the domain correctly
2. Check your internet connection
3. Try again in a few minutes
4. If the problem persists, contact your IT team

You entered: {domain}
        """)
        sys.exit(1)


if __name__ == "__main__":
    main()