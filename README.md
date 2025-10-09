# Email Ready - Email Configuration Health Check

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)

A comprehensive email configuration health checker that helps businesses ensure their email infrastructure is properly configured for security, deliverability, and compliance.

## Two Versions for Different Needs

### 📊 check.py - Business Version
For business owners, managers, and non-technical users who need to understand their email health in plain English.

**Features:**
- Zero technical jargon
- Business risk assessment (HIGH/MODERATE/LOW)
- Clear explanations of problems and solutions
- What to tell your IT team to fix issues

### 🔒 check_secure.py - Technical Version  
For IT professionals, system administrators, and security teams who need detailed technical analysis.

**Features:**
- Full security analysis with rate limiting
- Detailed technical diagnostics
- Anti-abuse protections
- Production-ready with hardened security

## Quick Start

### For Business Users

```bash
python check.py yourdomain.com
```

Example output:
```
BUSINESS EMAIL HEALTH CHECK
Checking: example.com

1. Can customers send you email? YES
2. Are you protected from email spoofing? YES
3. Will email providers trust your emails? PARTIALLY
4. Is your email encrypted during delivery? YES

RISK LEVEL: MODERATE RISK
Health Score: 75 out of 100 points (75%)

PROBLEMS FOUND:
1. Missing email authentication. Your emails might go to spam folders.

WHAT YOUR IT TEAM NEEDS TO DO:
1. Add a DMARC policy. Tell your IT team: 'Set up DMARC starting with p=none.'
```

### For IT Professionals

```bash
python check_secure.py example.com

# With custom DKIM selectors
python check_secure.py example.com --dkim-selectors google,selector1

# Skip SMTP tests (if behind firewall)
python check_secure.py example.com --skip-smtp
```

## Installation

```bash
# Clone repository
git clone https://github.com/ballance/email-ready.git
cd email-ready

# Install dependencies
pip install -r requirements.txt
```

## Requirements

- Python 3.6+
- dnspython
- requests

## What Gets Checked

Both versions check these essential email configurations:

| Configuration | What It Does | Business Impact |
|--------------|--------------|-----------------|
| **MX Records** | Directs incoming email | Without these, you can't receive email |
| **SPF** | Lists authorized senders | Prevents spammers from impersonating you |
| **DMARC** | Email authentication policy | Tells providers how to handle fake emails |
| **DKIM** | Digital signatures | Proves emails are really from you |
| **Encryption** | STARTTLS support | Protects email content in transit |

## Which Version Should I Use?

**Use check.py if you:**
- Run a business and want to check your email setup
- Need to explain email issues to management
- Want a risk assessment in business terms
- Don't know technical terminology

**Use check_secure.py if you:**
- Manage email infrastructure
- Need detailed technical analysis
- Are performing security audits
- Want to integrate with monitoring systems

## Security

The technical version (`check_secure.py`) includes:
- Input validation to prevent injection attacks
- Rate limiting (50 DNS queries, 5 SMTP connections max)
- SSRF protection
- Safe error handling
- See [SECURITY.md](SECURITY.md) for details

## Documentation

- [SECURITY.md](SECURITY.md) - Security features and considerations
- [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) - Technical documentation for developers

## License

MIT License - See [LICENSE](LICENSE) file

## Support

For issues or questions:
1. Check your spelling of the domain name
2. Ensure you have internet connectivity
3. Try the business version first for clear explanations
4. If you find a bug, please report it via [GitHub Issues](https://github.com/ballance/email-ready/issues)

## Contributing

Contributions are welcome! Please see [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) for technical details and contribution guidelines.

## Responsible Use

This tool is for checking domains you own or have permission to test. Do not use for unauthorized scanning or testing of third-party domains.

## Author

Created by Chris Ballance