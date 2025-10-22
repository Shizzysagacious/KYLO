# KYLO 🛡️

[![PyPI version](https://badge.fury.io/py/kylo.svg)](https://badge.fury.io/py/kylo)
[![Python Support](https://img.shields.io/pypi/pyversions/kylo.svg)](https://pypi.org/project/kylo/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Downloads](https://pepy.tech/badge/kylo)](https://pepy.tech/project/kylo)

**KYLO** is an AI-powered security code auditor that helps developers ship safer code. It performs static analysis, detects vulnerabilities, and aligns your codebase with your project goals—all from the command line.

## ✨ Features

- 🔍 **AST-Based Security Scanning** — Detects dangerous functions (`eval`, `exec`), SQL injection risks, and common vulnerabilities
- 🛡️ **Advanced Security Checks** — Finds hardcoded secrets, weak crypto, auth risks, and more
- 📊 **Project Alignment** — Validates code against your README goals and requirements
- 🔒 **Privacy-First** — Encrypted local storage for sensitive data
- 🎨 **Beautiful Terminal UI** — Rich, colorful output with progress indicators
- 📈 **Usage Tracking** — Monitor audits and scans with built-in analytics
- ⚡ **Zero-Config** — Works out of the box, no API keys required for basic scanning

## 🚀 Installation

### Via pip (Recommended)

```bash
pip install kylo
```

### From source

```bash
git clone https://github.com/yourusername/kylo.git
cd kylo
pip install -e .
```

## 📖 Quick Start

### 1. Initialize KYLO in your project

```bash
cd your-project
kylo init
```

This creates:
- `.kylo/` directory for state and configuration
- `README.md` template (if missing)
- Project goals tracking

### 2. Run a security audit

```bash
# Audit current directory
kylo audit

# Audit specific file or folder
kylo audit backend/api.py
kylo audit src/
```

### 3. Get security hardening recommendations

```bash
kylo secure backend/
```

### 4. View usage statistics

```bash
kylo stats
```

## 🔧 Configuration

### Setting an Admin Token

Protect sensitive operations with an admin token:

```bash
kylo config set-admin-token
```

### Storing API Keys (Optional)

For advanced features, you can store API keys securely:

```bash
kylo config set-api-key gemini
```

All keys are encrypted using hardware-bound encryption and stored in `.kylo/secure/`.

### Environment Variables

Customize KYLO's behavior with environment variables:

```bash
# Rate limits (requests per hour)
export KYLO_RATE_LIMIT_AUDITS=100
export KYLO_RATE_LIMIT_SECURE=50

# CLI colors
export KYLO_CLI_PRIMARY_COLOR=magenta
export KYLO_CLI_ACCENT_COLOR=purple

# Logging
export KYLO_LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR
```

## 🛡️ Security Checks

KYLO performs comprehensive security analysis:

### Basic Checks
- Dangerous function usage (`eval`, `exec`, `pickle.loads`)
- SQL injection vulnerabilities (f-strings in queries)
- Insecure file operations
- Weak cryptographic functions (MD5, SHA1)

### Advanced Checks (Aggressive Mode)
- Hardcoded secrets and credentials
- Authentication and session management risks
- Network operation vulnerabilities
- Data deserialization issues
- Security-relevant code comments (TODO, FIXME, HACK)

## 📊 Usage Examples

### Audit with verbose output

```bash
kylo -v audit backend/
```

### Check specific security concerns

```bash
kylo secure api/auth.py
```

### List stored API keys

```bash
kylo config list-keys
```

## 🎨 Terminal UI

KYLO features a beautiful, modern terminal interface:

```
██╗  ██╗██╗   ██╗██╗      ██████╗ 
██║ ██╔╝╚██╗ ██╔╝██║     ██╔═══██╗
█████╔╝  ╚████╔╝ ██║     ██║   ██║
██╔═██╗   ╚██╔╝  ██║     ██║   ██║
██║  ██╗   ██║   ███████╗╚██████╔╝
╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ 

AI-Powered Security Code Auditor v1.0.0

🔍 Scanning files...
📂 Reading project structure...
🛡️ Running security checks...
✓ Audit complete!

Files scanned: 45
Issues found: 3
```

## 🏗️ Project Structure

```
your-project/
├── .kylo/
│   ├── state.json          # Audit results and history
│   ├── goals.json          # Project goals for alignment
│   ├── secure/             # Encrypted API keys (if configured)
│   │   └── humanwhocodes.enc
│   └── stats/              # Usage statistics
│       └── usage.json
└── README.md               # Your project documentation
```

## 🔐 Privacy & Security

- **Local-First**: All scanning happens on your machine
- **Encrypted Storage**: API keys and sensitive data are encrypted using hardware-bound keys
- **Privacy-Preserving**: Usage tracking uses SHA256 hashes, not actual code
- **No Telemetry**: KYLO doesn't send your code anywhere (unless you explicitly use AI features)

## 🤝 Contributing

Contributions are welcome! Here's how:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 Development

### Setup

```bash
git clone https://github.com/yourusername/kylo.git
cd kylo
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

### Running Tests

```bash
python tests/run_tests.py
```

## 🗺️ Roadmap

- [ ] Multi-language support (JavaScript, Go, Rust, TypeScript)
- [ ] CI/CD integrations (GitHub Actions, GitLab CI, CircleCI)
- [ ] Live monitoring dashboard
- [ ] AI-powered deep analysis (via optional proxy service)
- [ ] Custom rule definitions
- [ ] Team collaboration features

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [Click](https://click.palletsprojects.com/) for CLI
- Beautiful terminal UI powered by [Rich](https://rich.readthedocs.io/)
- Encryption using [Cryptography](https://cryptography.io/)

## 💬 Support

- 🌐 Website: [kylo.pxxl.click](https://kylo.pxxl.click)
- 📧 Email: support@pxxl.click
- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/kylo/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/Shizzysagacous/kylo/discussions)
**Made with ❤️ by the PXXL team**

*Ship safer code, faster.*
