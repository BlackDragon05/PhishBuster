<div align="center">

```
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗
██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗
██████╔╝███████║██║███████╗███████║██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝
██╔═══╝ ██╔══██║██║╚════██║██╔══██║██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗
██║     ██║  ██║██║███████║██║  ██║██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

# 🎣 PhishBuster

**Phishing Website Detection Tool**

A modular, CLI-based cybersecurity tool that detects phishing websites using
multi-layer analysis — URL heuristics, domain intelligence, webpage content
inspection, blacklist checking, and an optional Machine Learning engine.

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Kali Linux](https://img.shields.io/badge/Kali_Linux-Supported-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)](https://kali.org)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-orange?style=for-the-badge)]()
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)]()

</div>

---

## 📸 Preview

```
  Phishing Website Detection Tool  v1.0.0
  Developed by: Anand & Vikrant Yadav
  ─────────────────────────────────────────────────────

╔══════════════════════════════════════════════════════════════╗
║                    PhishBuster Result                        ║
║                                                              ║
║    🚨 PHISHING                                               ║
║                                                              ║
║    Risk Score: 8.7 / 10  ████████░░                         ║
║                                                              ║
║    http://secure-login-verify-paypal.xyz/account/update      ║
╚══════════════════════════════════════════════════════════════╝

 Module     Check                   Value     Status
 ──────────────────────────────────────────────────
 URL        Length                  61        ⚠ Risk
 URL        HTTPS                   No        ⚠ Risk
 URL        Suspicious keywords     3         ⚠ Risk
 Domain     Age (days)              2         ⚠ Risk
 Domain     SSL valid               No        ⚠ Risk
 Content    Login form              Yes       ⚠ Risk
 Content    Urgency language        2         ⚠ Risk
 Blacklist  PhishTank               HIT       ⚠ Risk
 ML Model   Phishing probability    91%       ⚠ Risk
```

---

## 🔍 Detection Modules

| Module | What it analyzes |
|--------|-----------------|
| 🔗 **URL Analysis** | URL length, special characters (`@`, `-`), IP-as-hostname, HTTPS, subdomain depth, suspicious keywords, URL shorteners, hex encoding |
| 🌐 **Domain Analysis** | WHOIS domain age, registrar, SSL certificate validation, DNS resolution |
| 📄 **Content Analysis** | Login forms, password fields, hidden HTML elements, external scripts, iframes, JS redirects, obfuscated JavaScript, urgency language, brand impersonation |
| 🚫 **Blacklist Check** | PhishTank free lookup — no API key required |
| 🤖 **ML Engine** | Random Forest classifier trained on PhishTank + Tranco dataset (optional) |

---

## 🎯 Risk Score System

| Score | Verdict | Meaning |
|-------|---------|---------|
| **0 – 3** | ✅ Safe | No significant threat indicators |
| **4 – 7** | ⚠️ Suspicious | Risk signals present — proceed with caution |
| **8 – 10** | 🚨 Phishing | High-confidence phishing / malicious site |

---

## 📁 Project Structure

```
PhishBuster/
│
├── phishbuster.py                  ← Main CLI entry point (run this)
├── requirements.txt                ← All Python dependencies
├── README.md
├── LICENSE
├── .gitignore
├── sample_urls.txt                 ← Test URLs to try right away
│
├── phishbuster/                    ← Core package
│   ├── __init__.py
│   ├── analyzer.py                 ← Orchestrates all modules
│   ├── cli/
│   │   └── display.py              ← Rich colored terminal output
│   ├── modules/
│   │   ├── url_analyzer.py         ← URL heuristic analysis
│   │   ├── domain_analyzer.py      ← WHOIS, DNS, SSL
│   │   ├── content_analyzer.py     ← HTML & JavaScript analysis
│   │   ├── blacklist_checker.py    ← PhishTank lookup
│   │   └── ml_predictor.py         ← ML model inference
│   ├── scoring/
│   │   └── risk_engine.py          ← Weighted score calculator
│   └── utils/
│       └── safe_fetch.py           ← Sandboxed async HTTP fetcher
│
├── ml/
│   ├── train.py                    ← Model training script
│   ├── models/                     ← Saved .pkl files after training
│   └── dataset/                    ← Place training CSVs here
│
└── tests/
    └── test_phishbuster.py         ← Unit tests (pytest)
```

---

## ⚡ Installation & Usage

---

### 🐉 Kali Linux (Recommended for cybersecurity work)

Kali Linux comes with Python 3 and Git pre-installed. Open a terminal:

```bash
# 1. Clone the repository
git clone https://github.com/BlackDragon05/PhishBuster.git
cd PhishBuster

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install all dependencies
pip install -r requirements.txt

# 4. Run your first scan
python3 phishbuster.py -u https://google.com
```

**Every time you open a new terminal to use PhishBuster:**
```bash
cd PhishBuster
source venv/bin/activate
python3 phishbuster.py -u <URL>
```

---

### 🐧 Ubuntu / Debian / Parrot OS

```bash
# Install prerequisites
sudo apt update
sudo apt install python3 python3-pip python3-venv git -y

# Clone and setup
git clone https://github.com/BlackDragon05/PhishBuster.git
cd PhishBuster
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run
python3 phishbuster.py -u https://example.com
```

---

### 🪟 Windows

```cmd
:: Requires Python 3.11+ from python.org and Git from git-scm.com

git clone https://github.com/BlackDragon05/PhishBuster.git
cd PhishBuster
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

python phishbuster.py -u https://example.com
```

---

### 🍎 macOS

```bash
# Install Homebrew if needed: https://brew.sh
brew install python3 git

git clone https://github.com/BlackDragon05/PhishBuster.git
cd PhishBuster
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

python3 phishbuster.py -u https://example.com
```

---

## 📖 Commands & Examples

### Scan a single URL
```bash
python3 phishbuster.py -u https://google.com
```

### Scan a suspicious-looking URL
```bash
python3 phishbuster.py -u http://paypal-secure-login.verify-account.xyz
```

### Get raw JSON output
```bash
python3 phishbuster.py -u https://example.com --json
```

### Batch scan from a file (one URL per line)
```bash
python3 phishbuster.py -f sample_urls.txt
```

### Batch scan and save results
```bash
python3 phishbuster.py -f sample_urls.txt --output results.json
```

### Fast scan — skip content fetch
```bash
python3 phishbuster.py -u https://example.com --no-content
```

### Scan without ML model
```bash
python3 phishbuster.py -u https://example.com --no-ml
```

### Custom timeout
```bash
python3 phishbuster.py -u https://example.com --timeout 15
```

### Help and version
```bash
python3 phishbuster.py --help
python3 phishbuster.py --version
```

---

### All Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-u`, `--url` | Single URL to analyze | — |
| `-f`, `--file` | Text file with one URL per line | — |
| `--json` | Print raw JSON output | Off |
| `--output FILE` | Save results to a JSON file | — |
| `--no-content` | Skip HTML content fetch (faster) | Off |
| `--no-ml` | Skip ML model prediction | Off |
| `--timeout N` | HTTP request timeout in seconds | 10 |
| `--version` | Show version | — |
| `--help` | Show help | — |

---

## 🤖 Training the ML Model (Optional)

The tool works out of the box without ML using rule-based scoring. To enable
the ML prediction layer for higher accuracy, follow these steps.

### Step 1 — Download the datasets

**PhishTank dataset (phishing URLs):**
1. Go to https://phishtank.com/developer_info.php
2. Download `verified_online.csv`
3. Rename and place it at: `ml/dataset/phishtank.csv`

**Tranco dataset (legitimate domains):**
1. Go to https://tranco-list.eu
2. Download the latest top-1M list
3. Rename and place it at: `ml/dataset/tranco_1m.csv`

### Step 2 — Run the training script
```bash
source venv/bin/activate
python3 ml/train.py
```

Training takes roughly 2–5 minutes and prints accuracy, precision, recall,
and a feature importance chart when complete. The model saves automatically
to `ml/models/`.

### Step 3 — Use PhishBuster with ML active
```bash
python3 phishbuster.py -u https://suspicious-site.xyz
```

The ML confidence score will now appear in every scan result.

---

## 🧪 Running Tests

```bash
source venv/bin/activate
pytest tests/ -v
```

All 8 tests should pass.

---

## 📊 Exit Codes (for scripting)

| Code | Meaning |
|------|---------|
| `0` | Safe |
| `1` | Suspicious |
| `2` | Phishing |

Bash automation example:
```bash
python3 phishbuster.py -u "$URL"
if [ $? -eq 2 ]; then
  echo "PHISHING DETECTED — $URL"
fi
```

---

## 🔒 Ethical Use & Disclaimer

This tool is developed for **educational and research purposes only**.

✅ Acceptable:
- Analyzing URLs you own or have explicit permission to test
- Academic cybersecurity research and final-year projects
- CTF (Capture the Flag) challenges
- Security awareness training

❌ Not acceptable:
- Unauthorized scanning of third-party systems
- Any illegal or malicious activity

The authors are not responsible for any misuse of this tool.

---

## 🛣️ Roadmap

- [x] URL heuristic analysis
- [x] Domain / WHOIS / SSL analysis
- [x] Webpage content analysis
- [x] PhishTank blacklist integration
- [x] Random Forest ML model
- [x] Batch URL scanning
- [x] JSON export
- [x] Kali Linux support
- [ ] FastAPI REST backend
- [ ] Web dashboard (React)
- [ ] Browser extension (Chrome/Firefox)
- [ ] VirusTotal API integration
- [ ] Google Safe Browsing API
- [ ] Docker container

---

## 👥 Authors

| Name | Role | GitHub |
|------|------|--------|
| **Anand** | Lead Developer & Researcher | [@BlackDragon05](https://github.com/BlackDragon05) |
| **Vikrant Yadav** | Co-Developer & Researcher | — |

*Cybersecurity Research Project — Final Year*

---

## 📄 License

Licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

<div align="center">

Made with ❤️ for the cybersecurity community by Anand & Vikrant Yadav

⭐ **Star this repo if PhishBuster helped you!**

</div>
