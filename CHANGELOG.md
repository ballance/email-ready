# Changelog

All notable changes to Email Ready will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-10-01

### Added
- Initial release with two versions: business and technical
- Business version (`check.py`) with plain English explanations
- Technical version (`check_secure.py`) with security hardening
- Comprehensive SPF, DKIM, DMARC, MX, and STARTTLS checking
- Risk assessment scoring (HIGH/MODERATE/LOW)
- Rate limiting and anti-abuse protections in secure version
- Input validation and SSRF protection
- Detailed documentation (README, SECURITY, DEVELOPER_GUIDE)
- MIT License

### Security
- Implemented rate limiting (50 DNS queries, 5 SMTP connections max)
- Added input validation to prevent injection attacks
- Blocked private IP ranges and localhost
- Added SSRF protection for HTTP requests
- Implemented safe error handling without information disclosure

### Features
- Auto-cleaning of common input mistakes (http://, www., etc.)
- Business-friendly risk assessment and recommendations
- Support for custom DKIM selectors
- SMTP encryption testing with STARTTLS
- MTA-STS and TLS-RPT support
- PTR record verification with forward confirmation

### Documentation
- Comprehensive README with clear usage instructions
- Security documentation with threat model
- Developer guide with architecture overview
- Clear distinction between business and technical versions

## Author

Chris Ballance (ballance@gmail.com)