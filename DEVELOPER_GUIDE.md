# Developer Guide

## Repository Structure

This repository contains two versions of the email health checker:

### check.py - Business Version
- **Purpose**: User-friendly tool for non-technical users
- **Audience**: Business owners, managers, support teams  
- **Language**: Plain English with zero jargon
- **Output**: Risk assessment and actionable recommendations

### check_secure.py - Technical Version
- **Purpose**: Production-ready tool with security hardening
- **Audience**: IT professionals, security teams, developers
- **Language**: Technical terminology with detailed diagnostics
- **Security**: Rate limiting, input validation, anti-abuse protections

## Architecture Overview

```
User Input
    ↓
Domain Validation 
    ↓
DNS Queries → TXT Records (SPF, DMARC, DKIM)
            → MX Records
            → PTR Records
    ↓
SMTP Tests → Connection Test
          → STARTTLS Check
          → Certificate Validation
    ↓
Report Generation
```

## Key Differences

| Feature | check.py | check_secure.py |
|---------|----------|-----------------|
| Error Handling | User-friendly messages | Technical details |
| Rate Limiting | No | Yes (50 DNS, 5 SMTP) |
| Input Validation | Basic | Comprehensive |
| Output Format | Business report | Technical analysis |
| Security Features | Minimal | Full hardening |
| Dependencies | dnspython | dnspython, requests |
| Code Complexity | ~500 lines, simple | ~700 lines, complex |

## Security Considerations

### check_secure.py Security Features

1. **Input Validation**
   - Domain format validation
   - IP range blocking (RFC1918, loopback)
   - Selector sanitization
   - Length limits

2. **Rate Limiting**
   ```python
   MAX_DNS_QUERIES = 50
   MAX_SMTP_CONNECTIONS = 5
   MIN_QUERY_INTERVAL = 0.1  # 100ms between queries
   ```

3. **SSRF Protection**
   - No redirect following
   - Response size limits
   - URL validation
   - Timeout controls

4. **Resource Protection**
   - Connection timeouts
   - Query limits
   - Memory limits
   - Safe error handling

## Testing

### Manual Testing
```bash
# Test business version
python check.py example.com

# Test technical version
python check_secure.py example.com --skip-smtp

# Test with invalid input
python check.py "'; DROP TABLE domains;--"
```

### Test Domains
- `gmail.com` - Well-configured domain
- `example.com` - Limited configuration
- Your own domain - Real-world testing

## Common Issues and Solutions

### Issue: Connection Refused on Port 25
**Cause**: ISP or firewall blocking SMTP
**Solution**: Use `--skip-smtp` flag in check_secure.py

### Issue: DNS Timeouts
**Cause**: Slow DNS servers or network issues
**Solution**: Increase timeout values in code

### Issue: Rate Limit Exceeded
**Cause**: Too many queries in check_secure.py
**Solution**: Wait and retry, or adjust limits

## Code Maintenance

### Adding New Checks
1. Add check method to appropriate class
2. Update scoring logic
3. Add explanations for both versions
4. Update documentation

### Updating Dependencies
```bash
pip install --upgrade dnspython requests
pip freeze > requirements.txt
```

## Future Enhancements

Potential improvements to consider:

1. **JSON Output** - Machine-readable format for integration
2. **Batch Processing** - Check multiple domains
3. **Web Interface** - Browser-based version
4. **API Endpoint** - RESTful service
5. **Caching** - Reduce redundant queries
6. **Async Operations** - Parallel checking
7. **Report Export** - PDF/HTML generation
8. **Monitoring Integration** - Prometheus/Grafana

## Contributing

### Code Style
- Follow PEP 8
- Use meaningful variable names
- Add docstrings to functions
- Keep functions under 50 lines
- Maintain consistent error handling

### Pull Request Checklist
- [ ] Both versions tested
- [ ] Documentation updated
- [ ] Security impact considered
- [ ] Error handling comprehensive
- [ ] No hardcoded values

## Resources

### Standards (RFCs)
- RFC 7208 - SPF
- RFC 7489 - DMARC  
- RFC 6376 - DKIM
- RFC 8461 - MTA-STS
- RFC 8460 - TLS-RPT

### Tools for Manual Testing
- `dig` - Command-line DNS lookup tool
  ```bash
  dig example.com TXT              # Check SPF
  dig _dmarc.example.com TXT       # Check DMARC
  dig example.com MX               # Check mail servers
  ```
- `nslookup` - Alternative DNS tool
  ```bash
  nslookup -type=TXT example.com
  nslookup -type=MX example.com
  ```
- `openssl s_client` - Test SSL/TLS connections
  ```bash
  openssl s_client -connect mail.example.com:25 -starttls smtp
  ```
- `telnet` - Manual SMTP testing
  ```bash
  telnet mail.example.com 25
  EHLO test.example.com
  QUIT
  ```

### Standards (RFCs)
- **RFC 7208** - SPF (Sender Policy Framework)
- **RFC 7489** - DMARC (Domain-based Message Authentication)
- **RFC 6376** - DKIM (DomainKeys Identified Mail)
- **RFC 8461** - MTA-STS (SMTP MTA Strict Transport Security)
- **RFC 8460** - TLS-RPT (SMTP TLS Reporting)
- **RFC 5321** - SMTP (Simple Mail Transfer Protocol)
- **RFC 5322** - Internet Message Format

### Learning Resources
- [DNS Basics](https://www.cloudflare.com/learning/dns/what-is-dns/)
- [Email Authentication Explained](https://www.mailgun.com/blog/deliverability/spf-dkim-dmarc/)
- [Python Socket Programming](https://realpython.com/python-sockets/)
- [SMTP Protocol Guide](https://www.rfc-editor.org/rfc/rfc5321.html)
- [DNS Python Documentation](https://dnspython.readthedocs.io/)

## License

MIT License - See LICENSE file for details