# Security Policy

## Reporting Security Vulnerabilities

**If you discover a security vulnerability, please DO NOT open a public issue.**

### How to Report

1. **Email**: Send details to the maintainers (create issue for contact info)
2. **GitHub Security Advisory**: Use [GitHub's private vulnerability reporting](https://github.com/AntonUshakov/osint-reconnaissance-tool/security/advisories)
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce (if possible)
   - Potential impact
   - Suggested fix (if you have one)

### Response Timeline

- **Acknowledgment**: Within 24 hours
- **Assessment**: Within 7 days
- **Fix Release**: Within 30 days (for critical issues)
- **Public Disclosure**: After fix is released

---

## Security Commitments

This project commits to:

✅ **Data Privacy**: No storage of authentication credentials  
✅ **Local-Only Execution**: No cloud, no external data transmission  
✅ **Token Safety**: GitHub tokens never logged or persisted  
✅ **Dependency Security**: Regular updates of dependencies  
✅ **Code Review**: Security-focused review before releases  
✅ **Transparency**: Full disclosure of security practices  

---

## Security Features

### Authentication
- Uses PyGithub official library
- Direct GitHub API communication
- No proxying or logging
- User-provided credentials only

### Data Handling
- Results stored locally only
- No database backends
- No cloud storage
- No external API calls (except GitHub)

### Transport Security
- HTTPS/TLS for GitHub API
- Local HTTP (localhost only)
- No token transmission to external services

---

## Best Practices for Users

### Creating a Token

1. Go to https://github.com/settings/tokens
2. Click "Generate new token"
3. **Scopes needed**:
   - `repo` (read repositories)
   - `admin:org_hook` (read webhooks)
   - `read:org` (read org info)
4. **Scopes NOT needed**:
   - `write:` permissions
   - `delete:` permissions
   - `admin:` full access
5. Set **Expiration**: 30-90 days recommended
6. Copy and use with this tool only

### After Running Audits

1. Review the generated reports
2. Delete reports you don't need
3. Keep in secure location (not shared drives)
4. Consider revoking token after use

---

## Known Limitations

### What This Tool Can't Audit
- Secret scanning (use GitHub's native feature)
- Code quality (use code scanning tools)
- Performance/availability
- Business logic vulnerabilities

### What This Tool Won't Do
- Access repository content
- Modify any GitHub settings
- Store credentials
- Send data external
- Require registration

---

## Security Disclosure History

**No known vulnerabilities to date.**

### Resolved Issues
- None yet

### Current Status
- ✅ Reviewed for token handling
- ✅ Verified local-only storage
- ✅ Checked for data leaks
- ✅ Audit passed

---

## Dependencies Security

### Monitored Packages
- PyGithub - Official library, regularly maintained
- Flask - Industry standard, security updates followed
- requests - Well-maintained, no known vulnerabilities
- python-dotenv - Simple, minimal code, secure

### Version Policy
- Regular updates checked
- Security patches applied immediately
- No beta/alpha dependencies
- All dependencies reviewed

---

## Compliance

This project aims to comply with:
- ✅ OWASP Top 10 prevention measures
- ✅ CWE/SANS Top 25 prevention
- ✅ General security best practices
- ✅ GitHub's own security guidelines

---

## Contact

For security questions or concerns:
1. Create private security advisory on GitHub
2. Include security in email subject
3. Provide details without disclosing publicly

---

**Last Updated**: August 8, 2026  
**Status**: Active & Maintained ✅
