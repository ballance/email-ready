# Security Considerations

## Overview

This email health check tool performs network queries to analyze email configuration. It has been designed with security in mind to prevent abuse and protect both the user and target systems.

## Security Features

### 1. Input Validation
- **Domain Validation**: Strict validation of domain names to prevent injection attacks
- **IP Address Filtering**: Blocks private, loopback, and reserved IP ranges
- **Selector Validation**: DKIM selector names are validated against safe patterns
- **Length Limits**: Maximum lengths enforced for all inputs

### 2. Rate Limiting
- **DNS Query Limits**: Maximum 50 DNS queries per run
- **SMTP Connection Limits**: Maximum 5 SMTP connections per run
- **Query Intervals**: 100ms minimum between queries to same domain
- **Connection Timeouts**: Reduced timeouts to prevent hanging

### 3. Anti-Abuse Protections
- **No Recursive Queries**: Prevents DNS amplification attacks
- **Limited Scope**: Only checks explicitly requested domains
- **Resource Limits**: Caps on concurrent operations
- **Size Limits**: Maximum response sizes for HTTP requests (100KB)

### 4. SSRF Prevention
- **No Redirects**: HTTP requests don't follow redirects
- **Domain Validation**: All URLs are validated before requests
- **Private IP Blocking**: Cannot query internal network resources
- **Strict Timeouts**: 3-second timeout for HTTP requests

### 5. Information Security
- **Generic Error Messages**: Prevents information disclosure
- **No Credential Storage**: Never stores or logs sensitive data
- **Limited Output**: Truncates excessive output data
- **Safe Certificate Handling**: Only extracts non-sensitive cert info

## Responsible Usage

### DO:
- ✅ Use on domains you own or have explicit permission to test
- ✅ Respect rate limits and connection limits
- ✅ Use for legitimate email configuration verification
- ✅ Report security issues responsibly

### DON'T:
- ❌ Use for scanning third-party domains without permission
- ❌ Attempt to bypass security controls
- ❌ Use as part of automated scanning tools
- ❌ Run excessive queries against any single domain

## Security Reporting

If you discover a security vulnerability in this tool, please report it responsibly by:

1. **Do NOT** create a public issue
2. Email the details to the maintainer
3. Allow time for a fix before disclosure
4. Include steps to reproduce if possible

## Threat Model

This tool considers the following threats:

1. **DNS Amplification**: Mitigated by query limits and no recursive resolution
2. **SMTP Abuse**: Mitigated by connection limits and generic EHLO
3. **SSRF Attacks**: Mitigated by validation and no redirect following
4. **Resource Exhaustion**: Mitigated by timeouts and limits
5. **Information Disclosure**: Mitigated by generic errors and output limits

## Compliance Notes

- Follows RFC specifications for email protocols
- Respects DNS query limits and best practices
- Uses standard User-Agent for HTTP requests
- Implements proper SSL/TLS certificate validation

## Version History

- v1.0.0-security: Initial security-hardened release
  - Added comprehensive input validation
  - Implemented rate limiting
  - Added anti-abuse protections
  - Enhanced error handling

## License

This tool is provided for legitimate security testing and configuration verification only. Any use for malicious purposes is strictly prohibited.