# 🛡️ Web Security Scanner v2.0

**Bộ công cụ quét lỗ hổng bảo mật web toàn diện** - Comprehensive Web Vulnerability Scanner

Công cụ quét tự động các lỗ hổng bảo mật web phổ biến theo OWASP Top 10, tạo báo cáo chi tiết và hướng dẫn khắc phục.

---

## 🌟 Tính Năng Chính

✅ **15 Security Scanners** - Bao phủ OWASP Top 10 và hơn thế nữa
✅ **CLI Thống Nhất** - Chạy tất cả scanners qua một command duy nhất
✅ **Multi-Format Reports** - JSON, Markdown, HTML, CSV
✅ **Modular Architecture** - Dễ dàng thêm scanners mới
✅ **Rate Limiting** - Tránh spam và bypass WAF
✅ **Detailed Remediation** - Hướng dẫn fix từng bước với code examples

---

## 📋 Danh Sách Scanners

### 🔴 Critical Vulnerabilities

| Scanner | Lỗ hổng | CVSS | Mô tả |
|---------|---------|------|-------|
| `xss` | Cross-Site Scripting | 7.5 | Reflected, Stored, DOM-based XSS |
| `sqli` | SQL Injection | 9.8 | Error-based, Boolean-based blind SQLi |
| `csrf` | Cross-Site Request Forgery | 6.5 | CSRF token validation, SameSite cookies |
| `path-traversal` | Directory Traversal | 7.5 | LFI/RFI, arbitrary file access |

### 🟠 High Severity

| Scanner | Lỗ hổng | CVSS | Mô tả |
|---------|---------|------|-------|
| `clickjacking` | Clickjacking | 5.3 | X-Frame-Options, CSP frame-ancestors |
| `open-redirect` | Open Redirect | 6.1 | Unvalidated redirects |
| `ssl` | SSL/TLS Issues | 7.5 | Certificate expiry, weak ciphers, old TLS |
| `sri` | Subresource Integrity | 5.3 | Missing SRI for external resources |

### 🟡 Medium Severity

| Scanner | Lỗ hổng | CVSS | Mô tả |
|---------|---------|------|-------|
| `headers` | Security Headers | 5.0 | HSTS, CSP, X-Content-Type-Options, etc. |
| `cors` | CORS Misconfiguration | 6.5 | Wildcard ACAO, credentials exposure |
| `cookies` | Insecure Cookies | 5.3 | Secure, HttpOnly, SameSite attributes |
| `mixed-content` | Mixed Content | 4.3 | HTTP resources in HTTPS pages |
| `rate-limit` | No Rate Limiting | 5.3 | Brute-force protection |

### 🔵 Low / Informational

| Scanner | Lỗ hổng | CVSS | Mô tả |
|---------|---------|------|-------|
| `options` | OPTIONS Method | 0.0 | HTTP method disclosure |
| `dir-enum` | Directory Enumeration | 3.0 | Exposed directories and files |

---

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/ngoquytuan/scan_loHongBaoMatweb.git
cd scan_loHongBaoMatweb

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Scan với TẤT CẢ scanners
python main.py --url https://example.com --group all

# Scan chỉ các lỗ hổng Critical
python main.py --url https://example.com --group critical

# Scan specific scanners
python main.py --url https://example.com --modules xss,sqli,csrf

# Generate HTML report
python main.py --url https://example.com --group all --format html --output report.html

# Quiet mode (less output)
python main.py --url https://example.com --group all --quiet
```

### List Available Options

```bash
# List all scanners
python main.py --list

# Help
python main.py --help
```

---

## 📚 Documentation

### CLI Usage

```
usage: main.py [-h] --url URL [--modules MODULES] [--group {all,critical,headers,config,injection,info}]
               [--output OUTPUT] [--format {json,markdown,html,csv}] [--quiet] [--list]

options:
  --url URL, -u URL            Target URL to scan (required)
  --modules MODULES, -m        Comma-separated list of scanners
  --group GROUP, -g            Predefined scanner group
  --output OUTPUT, -o          Output file path
  --format FORMAT, -f          Output format: json, markdown, html, csv
  --quiet, -q                  Quiet mode (less output)
  --list, -l                   List all available scanners
```

### Scanner Groups

| Group | Scanners | Use Case |
|-------|----------|----------|
| `all` | All 15 scanners | Comprehensive security audit |
| `critical` | xss, sqli, csrf, path-traversal | Priority vulnerabilities |
| `headers` | headers, cors, clickjacking, sri | HTTP security headers |
| `config` | ssl, cookies, options, mixed-content | Configuration issues |
| `injection` | xss, sqli, path-traversal | Injection vulnerabilities |
| `info` | dir-enum, rate-limit, open-redirect | Information disclosure |

### Individual Scanner Usage

Mỗi scanner cũng có thể chạy độc lập:

```bash
# XSS Scanner
python scanners/scanXSS.py https://example.com

# SQL Injection
python scanners/scanSQLi.py https://example.com

# Security Headers
python scanners/scanSecurityHeaders.py https://example.com
```

---

## 📁 Project Structure

```
websec-scanner/
│
├── main.py                      # CLI chính - chạy multiple scanners
│
├── core/                        # Core utilities
│   ├── utils.py                 # Utilities (requests, parsers, rate limiting)
│   ├── report.py                # Report generator (JSON, MD, HTML, CSV)
│   └── payloads/                # Attack payloads
│       ├── xss.txt
│       ├── sqli.txt
│       ├── path_traversal.txt
│       └── directories.txt
│
├── scanners/                    # Individual scanners
│   ├── scanXSS.py              # XSS scanner
│   ├── scanSQLi.py             # SQL Injection scanner
│   ├── scanPathTraversal.py    # Path Traversal scanner
│   ├── scanOpenRedirect.py     # Open Redirect scanner
│   ├── scanRateLimit.py        # Rate Limiting checker
│   ├── scanDirEnum.py          # Directory Enumeration
│   ├── scanCSRF.py             # CSRF scanner
│   ├── scanSecurityHeaders.py  # Security Headers checker
│   ├── scanCORS.py             # CORS scanner
│   ├── scanSSL.py              # SSL/TLS scanner
│   ├── scanMixedContent.py     # Mixed Content detector
│   ├── scanCookies.py          # Cookie Security checker
│   ├── scanSRI.py              # SRI scanner
│   ├── scanClickjacking2.py    # Clickjacking scanner
│   └── scanOptions.py          # HTTP OPTIONS scanner
│
├── README.md                    # This file
├── README_SCANNERS.md           # Detailed scanner documentation
└── requirements.txt             # Python dependencies
```

---

## 💻 Examples

### Example 1: Full Security Audit

```bash
python main.py \
  --url https://myapp.com \
  --group all \
  --format html \
  --output full_audit.html
```

**Output:**
- Comprehensive HTML report với tất cả findings
- Executive summary với overall security score
- Detailed findings từ 15 scanners
- Remediation recommendations

### Example 2: Pre-Deployment Check

```bash
# Check critical vulnerabilities trước khi deploy
python main.py \
  --url https://staging.myapp.com \
  --group critical \
  --format json \
  --output pre_deploy_check.json
```

### Example 3: Header Compliance Check

```bash
# Verify security headers theo compliance requirements
python main.py \
  --url https://myapp.com \
  --group headers \
  --format markdown \
  --output headers_report.md
```

### Example 4: Custom Scanner Selection

```bash
# Chỉ chạy specific scanners
python main.py \
  --url https://myapp.com \
  --modules xss,csrf,headers,ssl \
  --format csv \
  --output custom_scan.csv
```

---

## 📊 Report Formats

### JSON Report

```json
{
  "scan_time": "2024-01-15T10:30:00",
  "scan_duration": "0:05:23",
  "summary": {
    "total_scanners": 15,
    "vulnerable_count": 3,
    "safe_count": 12,
    "overall_score": 78.5,
    "max_cvss": 7.5,
    "critical_count": 0,
    "high_count": 1,
    "medium_count": 2,
    "low_count": 0
  },
  "results": [...]
}
```

### Markdown Report

Báo cáo Markdown bao gồm:
- Executive summary
- Issues by severity
- Detailed findings for each scanner
- Remediation recommendations
- Risk prioritization matrix

### HTML Report

Interactive HTML report với:
- Color-coded severity badges
- Sortable tables
- Expandable sections
- Print-friendly layout

### CSV Report

Flat CSV file cho:
- Excel import
- Database storage
- Custom analysis

---

## 🎯 Workflow Khuyến Nghị

### 1. Development Phase

```bash
# Quick scan during development
python main.py --url http://localhost:3000 --group critical --quiet
```

### 2. Staging Environment

```bash
# Comprehensive scan before production
python main.py \
  --url https://staging.myapp.com \
  --group all \
  --format html \
  --output staging_audit.html
```

### 3. Production Monitoring

```bash
# Regular monthly audits
python main.py \
  --url https://myapp.com \
  --group all \
  --format json \
  --output monthly_audit_$(date +%Y%m).json
```

### 4. CI/CD Integration

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run security scan
        run: |
          python main.py \
            --url ${{ secrets.STAGING_URL }} \
            --group critical \
            --format json \
            --output scan_results.json

      - name: Check for critical vulnerabilities
        run: |
          CRITICAL=$(jq '.summary.critical_count' scan_results.json)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "❌ Critical vulnerabilities found!"
            exit 1
          fi
```

---

## 🔧 Advanced Features

### Custom Payloads

Thêm payloads riêng vào `core/payloads/`:

```txt
# core/payloads/custom_xss.txt
<custom_payload>alert(1)</custom_payload>
```

### Rate Limiting Configuration

Modify `core/utils.py`:

```python
# Adjust rate limits
rate_limiter = RateLimiter(max_requests_per_second=10)
```

### Adding New Scanners

1. Create scanner file in `scanners/`:

```python
# scanners/scanMyVuln.py
from core.utils import ScannerUtils

class MyVulnScanner:
    def __init__(self, url):
        self.url = url
        self.results = {
            'scanner_name': 'My Vuln Scanner',
            # ...
        }

    def scan(self):
        # Scan logic
        self.analyze_risk()
        return True

    def analyze_risk(self):
        # Risk analysis
        pass
```

2. Register in `main.py`:

```python
SCANNERS = {
    # ...
    'my-vuln': ('scanners.scanMyVuln', 'MyVulnScanner'),
}
```

---

## 📈 Security Score Calculation

### Overall Score (0-100)

```
Overall Score = Average(All Scanner Protection Scores)
```

### Individual Scanner Scores

Mỗi scanner tính điểm riêng dựa trên:
- Severity của vulnerabilities found
- Number of issues
- Configuration quality
- Best practices compliance

### CVSS Scoring

CVSS v3.1 được sử dụng cho severity classification:
- **9.0-10.0:** Critical
- **7.0-8.9:** High
- **4.0-6.9:** Medium
- **0.1-3.9:** Low
- **0.0:** Informational

---

## 🐛 Troubleshooting

### Connection Errors

```bash
# Increase timeout
# Edit core/utils.py
timeout=20  # Default is 10
```

### WAF/Rate Limiting Blocks

```bash
# Decrease rate limit
# Edit main.py or individual scanner
RateLimiter(max_requests_per_second=3)
```

### SSL Certificate Errors

```bash
# Disable SSL verification (NOT recommended for production)
# Edit core/utils.py
verify=False
```

### Import Errors

```bash
# Ensure correct Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
python main.py --url https://example.com --group all
```

---

## 🤝 Contributing

Contributions welcome! To add a new scanner:

1. Fork repository
2. Create scanner in `scanners/` following existing structure
3. Add payloads to `core/payloads/` if needed
4. Register scanner in `main.py`
5. Add documentation
6. Submit PR

---

## 📄 License

MIT License - Free to use and modify

---

## ⚠️ Legal Disclaimer

**IMPORTANT:**

- Chỉ sử dụng tool này để quét websites bạn sở hữu hoặc có permission
- Quét websites không có permission là **bất hợp pháp**
- Tool này for educational và authorized security testing purposes only
- Authors không chịu trách nhiệm cho việc sử dụng sai mục đích

---

## 🎓 Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)

---

## 📞 Support

- Issues: [GitHub Issues](https://github.com/ngoquytuan/scan_loHongBaoMatweb/issues)
- Docs: [README_SCANNERS.md](README_SCANNERS.md)

---

**Happy Scanning! 🔍🛡️**

_Made with ❤️ for Security Engineers and Developers_
