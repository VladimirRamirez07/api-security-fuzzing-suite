# 🔐 API Security Fuzzing Suite

> Security testing suite for public APIs — fuzzing, rate limit analysis, error disclosure detection & automated contract documentation.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Security](https://img.shields.io/badge/Focus-API%20Security-red?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

---

## 🎯 What This Does

This suite **thinks like an attacker** to test how robust public APIs are against:

- 💉 **Fuzzing** — Sends corrupted parameters, invalid types, SQL injections, oversized payloads and boundary values to find unexpected behaviors
- ⚡ **Rate Limit Testing** — Fires burst requests to verify the API properly blocks abuse and returns correct `Retry-After` headers
- 🔎 **Error Disclosure Detection** — Crafts inputs designed to trigger verbose errors and checks if the API leaks stack traces, internal paths, DB names or framework details
- 📄 **Automated Reporting** — Generates structured JSON results + a full visual HTML security report

---

## 🏗️ Project Structure
```
api-security-fuzzing-suite/
├── src/
│   ├── auth.py              # Spotify OAuth2 Client Credentials
│   ├── config.py            # Target URLs, endpoints, constants
│   ├── fuzzer/
│   │   └── fuzzer.py        # Core fuzzing engine + payload library
│   ├── rate_limiter/
│   │   └── rate_limiter.py  # Burst tester + rate limit header analysis
│   ├── error_detector/
│   │   └── error_detector.py # Info disclosure scanner
│   └── reporter/
│       └── reporter.py      # JSON + HTML report generator
├── results/                 # Auto-generated test results
│   ├── fuzzing/
│   ├── rate_limit/
│   └── errors/
├── tests/                   # Unit tests
├── main.py                  # Entry point — interactive CLI
├── .env.example             # Credentials template
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

### 2. Get Spotify credentials

1. Go to [developer.spotify.com/dashboard](https://developer.spotify.com/dashboard)
2. Create an app → copy **Client ID** and **Client Secret**
3. Configure your `.env`:

```bash
cp .env.example .env
# Edit .env and add your credentials
```

### 3. Run

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

---

## 📊 Sample Report Output
```
🔐 Final Report
━━━━━━━━━━━━━━━━━━━━━━━━
Security Assessment Complete
Critical:  0
High:      2
Medium:    3
✅ No critical findings
```
Results are saved as:
- `results/fuzzing/fuzzing_YYYYMMDD_HHMMSS.json`
- `results/rate_limit/rate_limit_YYYYMMDD_HHMMSS.json`
- `results/errors/errors_YYYYMMDD_HHMMSS.json`
- `results/security_report_YYYYMMDD_HHMMSS.html`

---

## 🛡️ Ethical Use

This tool is designed for **authorized security testing only**.  
All tests target **public APIs within their documented usage limits**.  
Never use against APIs without explicit permission.

---

## 👤 Author

**Vladimir Ramirez** — [@VladimirRamirez07](https://github.com/VladimirRamirez07)