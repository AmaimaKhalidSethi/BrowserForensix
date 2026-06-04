# Security Policy

## Supported Versions

The following table lists the versions of BrowserForensix currently receiving security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

Only the latest release within a supported version line receives patches. Users are strongly encouraged to stay on the most recent release.

## Reporting a Vulnerability

If you discover a security vulnerability in BrowserForensix, **please do not open a public issue.** Instead, report it responsibly via email:

**Email:** [security@browserforensix.dev](mailto:security@browserforensix.dev)

When reporting, please include:

- A clear description of the vulnerability and its potential impact.
- Detailed steps to reproduce the issue, including any relevant configuration.
- The version of BrowserForensix you are running.
- Your operating system and Python version.
- Any proof-of-concept code or screenshots, if applicable.

### What to Expect

| Timeframe       | Action                                                      |
| --------------- | ----------------------------------------------------------- |
| Within 48 hours | You will receive an acknowledgment of your report.          |
| Within 7 days   | The team will provide an initial assessment and severity rating. |
| Within 30 days  | A fix or mitigation will be developed and released.         |

You will be credited in the release notes unless you request anonymity.

## Responsible Disclosure Policy

We follow a responsible disclosure model:

1. **Report privately** — Send vulnerability details to the security email above. Do not disclose them publicly until a fix is available.
2. **Allow reasonable time** — Give the maintainers up to 30 days to investigate, develop, and release a patch before any public disclosure.
3. **Coordinate disclosure** — Once a fix is released, we will work with you to publish a coordinated advisory if appropriate.
4. **No retaliation** — We will never pursue legal action against researchers who act in good faith and follow this policy.

We appreciate the security research community's efforts to keep BrowserForensix and its users safe.

## Important Security Considerations

### Local Analysis Only

BrowserForensix is designed exclusively for **local forensic analysis** on trusted machines. It processes sensitive browser artifacts — browsing history, cookies, saved credentials metadata, and local storage — that should never be transmitted over a network or exposed to untrusted parties.

> **⚠️ BrowserForensix must never be exposed to the public internet.**

Do not bind the application to a public-facing network interface (`0.0.0.0`) or deploy it behind a reverse proxy accessible from external networks. Doing so could expose highly sensitive browser forensic data to unauthorized parties.

### Flask Development Server

BrowserForensix uses Flask's built-in development server (`serve.py`) for its web interface. This server is **not production-grade** and is unsuitable for deployment in any environment beyond a single analyst's local workstation.

Specifically, the Flask development server:

- Does **not** support TLS/SSL encryption.
- Is **not** hardened against denial-of-service or injection attacks.
- Is **single-threaded** and not designed for concurrent access.
- Provides **no authentication or authorization** mechanisms.

If you require multi-user or networked access for a forensic lab environment, you must place the application behind a properly configured WSGI server (e.g., Gunicorn) with TLS termination, authentication, and firewall rules. This configuration is not officially supported and is undertaken at your own risk.

## Scope

The following are considered **in scope** for security reports:

- Vulnerabilities in BrowserForensix source code (Python backend, web frontend).
- Path traversal or injection flaws in artifact parsing.
- Cross-site scripting (XSS) in the web interface.
- Information disclosure beyond intended forensic output.

The following are considered **out of scope**:

- Issues arising from deploying the Flask development server on a public network (this is explicitly unsupported).
- Vulnerabilities in third-party dependencies (report these upstream; however, do let us know so we can update our pinned versions).
- Social engineering attacks against maintainers or users.
