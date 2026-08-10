# Contributing to GitHub Security Auditor

Thank you for your interest in contributing! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please note that this project is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How to Contribute

### Reporting Issues

Found a bug? Have a feature request? Here's how to report:

1. **Search** existing issues first (avoid duplicates)
2. **Check** if it's a known limitation (see SECURITY.md, PRIVACY.md)
3. **Create** a new issue with:
   - Clear title
   - Detailed description
   - Steps to reproduce (if bug)
   - Expected vs. actual behavior
   - Your environment (OS, Python version)

### Security Issues

**DO NOT** open a public issue for security vulnerabilities.

See [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.

### Feature Requests

1. **Describe** the feature clearly
2. **Explain** why you need it
3. **Suggest** implementation if possible
4. **Link** to any related issues

### Submitting Pull Requests

#### Before You Start

1. **Fork** the repository
2. **Clone** your fork locally
3. **Create** a branch for your feature: `git checkout -b feature/description`
4. **Read** this entire CONTRIBUTING.md

#### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/github-auditor.git
cd github-auditor

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install dev dependencies (optional)
pip install pytest flake8
```

#### Making Changes

1. **Code Style**:
   - Follow PEP 8
   - Use meaningful variable names
   - Add docstrings to functions
   - Add comments for complex logic

2. **Security**:
   - ❌ DO NOT log tokens or credentials
   - ❌ DO NOT send data external (except GitHub API)
   - ✅ DO add security comments
   - ✅ DO consider privacy impact

3. **Testing**:
   - Test locally with real GitHub org (test token)
   - Verify HTML/JSON reports generate correctly
   - Check that no tokens appear in reports
   - Test with different org sizes

4. **Documentation**:
   - Update README if needed
   - Add docstrings
   - Comment complex logic
   - Update relevant .md files

#### Commit Messages

```
Subject line (50 chars or less)

More detailed explanation if needed. Wrap at 72 characters.
Explain the problem you're solving and why this change helps.

Fixes #123  (if applicable)
```

#### Before Submitting

```bash
# Format code (optional)
python3 -m black *.py  # if installed

# Check syntax
python3 -m py_compile *.py

# Run tests (if you add them)
pytest tests/

# Test the app
./run.sh
# Visit http://localhost:5000
```

#### Submitting Your PR

1. **Push** to your fork
2. **Create** Pull Request with:
   - Clear title
   - Description of changes
   - Reason for the change
   - Links to related issues
   - Screenshots (if UI change)

3. **Respond** to review feedback
4. **Wait** for approval

---

## What We Accept

✅ **We welcome:**
- Bug fixes
- Security improvements
- Performance optimizations
- Documentation improvements
- New compliance standards
- New security checks
- Code quality improvements
- Test additions
- Dependency updates

❌ **We do NOT accept:**
- Changes that store tokens
- Changes that send data external
- Changes that add analytics/telemetry
- Changes that require registration
- Changes that violate privacy
- Changes without tests (for complex features)
- Changes that break existing functionality

---

## Development Guidelines

### Adding a New Security Check

1. **Create** function in `checks.py`:
```python
def check_new_feature(self):
    """
    Check description.
    
    Returns:
        dict: {"status": "PASSED"/"FAILED", "details": "..."}
    """
    try:
        # Your logic here
        return {"status": "PASSED", "details": "Details..."}
    except Exception as e:
        return {"status": "FAILED", "details": str(e)}
```

2. **Add** to checks list in `github_auditor.py`
3. **Add** compliance mapping in `compliance_mapping.py`
4. **Test** thoroughly
5. **Document** in wiki

### Adding Compliance Standard

1. **Add** mapping in `compliance_mapping.py`
2. **Link** checks to controls
3. **Add** wiki page explaining standard
4. **Update** README with new standard

### Updating Dependencies

```bash
# Check for updates
pip list --outdated

# Update specific package
pip install --upgrade package_name

# Update requirements.txt
pip freeze > requirements.txt

# Test thoroughly
./run.sh
```

---

## Review Process

1. **Automated Checks**:
   - Code runs without errors
   - No obvious security issues
   - Follows style guidelines

2. **Manual Review**:
   - Security impact assessment
   - Privacy impact assessment
   - Code quality review
   - Testing verification

3. **Approval**:
   - Usually 1-2 approvals needed
   - Maintainer merges after approval

4. **Release**:
   - May be included in next version
   - Credit given in CHANGELOG

---

## Development Roadmap

### High Priority
- [ ] More security checks
- [ ] Better error handling
- [ ] Performance improvements

### Medium Priority
- [ ] Additional compliance standards
- [ ] Improved reports
- [ ] More configuration options

### Lower Priority
- [ ] UI redesign
- [ ] Advanced features
- [ ] Enterprise features

---

## Questions?

1. **Check** existing documentation
2. **Search** closed issues
3. **Create** a discussion issue
4. **Ask** in PR comments

---

## Recognition

Contributors will be:
- ✅ Listed in CHANGELOG
- ✅ Credited in releases
- ✅ Thanked publicly

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License (see LICENSE).

---

Thank you for contributing! 🙏
