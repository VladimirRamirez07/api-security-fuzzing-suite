# 🔐 API Security Fuzzing Suite

> Security testing suite for public APIs — fuzzing, rate limit analysis, error disclosure detection & automated contract documentation.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Security](https://img.shields.io/badge/Focus-API%20Security-red?style=flat-square&logo=hackthebox)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![CI](https://github.com/VladimirRamirez07/api-security-fuzzing-suite/actions/workflows/ci.yml/badge.svg)
![Tests](https://img.shields.io/badge/Tests-12%20passing-brightgreen?style=flat-square&logo=pytest)
![GitHub API](https://img.shields.io/badge/Target-GitHub%20REST%20API%20v3-black?style=flat-square&logo=github)
![Fuzzing](https://img.shields.io/badge/Technique-Fuzzing-orange?style=flat-square)
![Rate Limit](https://img.shields.io/badge/Technique-Rate%20Limit%20Testing-purple?style=flat-square)
![Error Detection](https://img.shields.io/badge/Technique-Error%20Disclosure-red?style=flat-square)
![Requests](https://img.shields.io/badge/Library-Requests-blue?style=flat-square&logo=python)
![Rich](https://img.shields.io/badge/Library-Rich-blueviolet?style=flat-square&logo=python)
![Pytest](https://img.shields.io/badge/Testing-Pytest-blue?style=flat-square&logo=pytest)

---

## 🎯 What This Does

This suite **thinks like an attacker** to test how robust public APIs are against:

- 💉 **Fuzzing** — Sends corrupted parameters, invalid types, SQL injections, oversized payloads and boundary values to find unexpected behaviors
- ⚡ **Rate Limit Testing** — Fires burst requests to verify the API properly blocks abuse and returns correct `Retry-After` headers
- 🔎 **Error Disclosure Detection** — Crafts inputs designed to trigger verbose errors and checks if the API leaks stack traces, internal paths, DB names or framework details
- 📄 **Automated Reporting** — Generates structured JSON results + a full visual HTML security report with dark mode dashboard

---

## 🏗️ Project Structure
```
api-security-fuzzing-suite/
├── .github/
│   └── workflows/
│       └── ci.yml               # GitHub Actions — auto-run tests on every push
├── src/
│   ├── auth.py                  # GitHub Personal Access Token auth
│   ├── config.py                # Target URLs, endpoints, constants
│   ├── fuzzer/
│   │   └── fuzzer.py            # Core fuzzing engine + payload library
│   ├── rate_limiter/
│   │   └── rate_limiter.py      # Burst tester + rate limit header analysis
│   ├── error_detector/
│   │   └── error_detector.py    # Info disclosure scanner
│   └── reporter/
│       └── reporter.py          # JSON + HTML report generator
├── results/                     # Auto-generated test results (gitignored)
│   ├── fuzzing/
│   ├── rate_limit/
│   └── errors/
├── tests/
│   ├── test_auth.py             # Auth module unit tests
│   ├── test_fuzzer.py           # Fuzzing engine unit tests
│   └── test_error_detector.py   # Error detector unit tests
├── main.py                      # Entry point — interactive CLI
├── .env.example                 # Credentials template
└── requirements.txt
```
---

## ⚙️ Setup

### 1. Clone & install

```bash
git clone https://github.com/VladimirRamirez07/api-security-fuzzing-suite.git
cd api-security-fuzzing-suite
pip install -r requirements.txt
```

### 2. Get a GitHub Personal Access Token

1. Go to [github.com/settings/tokens](https://github.com/settings/tokens)
2. Click **"Generate new token (classic)"**
3. Select scopes: `public_repo` and `read:user`
4. Copy the generated token

### 3. Configure your `.env`

```bash
cp .env.example .env
# Edit .env and add your token
```

```env
GITHUB_TOKEN=your_token_here
GITHUB_BASE_URL=https://api.github.com
```

### 4. Run

```bash
python main.py
```

The CLI will ask which modules to run interactively.

---

## 🧪 Fuzzing Payload Categories

| Category | Examples | What it tests |
|----------|----------|---------------|
| SQL Injection | `' OR 1=1--`, `'; DROP TABLE` | Input sanitization |
| Type Confusion | `null`, `[]`, `{}`, `True`, `-0.0` | Type validation |
| Special Chars | `\x00`, `%00`, `../../etc/passwd` | Encoding & path handling |
| Oversized | `"A" * 10000`, `"🔥" * 500` | Size limits & DoS resistance |
| Boundary Values | `-1`, `2147483648`, `9999999999` | Integer overflow handling |
| Format Breaking | Invalid dates, malformed IDs, URI injection | Format validation |
| Path Traversal | `../../../etc/passwd`, `%2e%2e%2f` | Directory traversal |

---

## 🔎 Error Disclosure Severity Levels

| Severity | What it detects | Example |
|----------|----------------|---------|
| 🔴 CRITICAL | Stack traces, credentials in errors | `Traceback (most recent call last)` |
| 🟠 HIGH | DB names, internal paths, server errors | `MongoDB connection refused` |
| 🟡 MEDIUM | Framework info, debug mode, exceptions | `Django version 3.2.1` |
| 🔵 LOW | Parameter names, validation logic | `field 'username' is required` |

---

## ⚡ Rate Limit Analysis

The suite fires burst requests and measures:

- At which request number the API starts blocking
- Whether `Retry-After` headers are present
- Which rate limit headers are exposed (`X-RateLimit-Limit`, `X-RateLimit-Remaining`, etc.)
- Whether the API returns `429 Too Many Requests` or silently drops requests

---

## 📊 Sample Output
```
🔐 API Security Fuzzing Suite
Target:   GitHub REST API v3
Modules:  Fuzzer · Rate Limiter · Error Detector · Reporter
🔑 Authenticating with GitHub...
✅ Authenticated as: VladimirRamirez07 (Vladimir Ramirez)
MODULE 1 — Fuzzing Engine
🔍 Fuzzing: /search/repositories → param: q
INTERESTING payload={} status=200
INTERESTING payload=AAAA...AAAA status=200
MODULE 2 — Rate Limit Tester
⚡ Rate Limit Burst Test: /search/repositories
✓ 10/40 requests OK
⚠ Request #26 → status 403
MODULE 3 — Error Disclosure Detector
🔎 Error Disclosure Scan: /search/repositories
✅ No information disclosure detected
✅ HTML Report generated: results/security_report_20260520_015517.html
🔐 Final Report
━━━━━━━━━━━━━━━━━━━━━━━
Security Assessment Complete
Critical: 0 | High: 0 | Medium: 0
✅ No critical findings
```
Results saved as:
- `results/fuzzing/fuzzing_YYYYMMDD_HHMMSS.json`
- `results/rate_limit/rate_limit_YYYYMMDD_HHMMSS.json`
- `results/errors/errors_YYYYMMDD_HHMMSS.json`
- `results/security_report_YYYYMMDD_HHMMSS.html` ← Visual dashboard

---

## 🤖 CI/CD Pipeline

Every push to `main` automatically:

1. Spins up a Ubuntu environment
2. Installs all dependencies
3. Runs all 12 unit tests via pytest
4. Uploads test artifacts

```yaml
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
```

---

## 🛡️ Ethical Use

This tool is designed for **authorized security testing only**.
All tests target **public APIs within their documented usage limits**.
Never use against APIs without explicit permission.

---

## 👤 Author

**Vladimir Ramirez** — [@VladimirRamirez07](https://github.com/VladimirRamirez07)