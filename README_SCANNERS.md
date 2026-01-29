# 🛡️ Bộ Công Cụ Quét Lỗ Hổng Bảo Mật Web

Bộ công cụ quét lỗ hổng bảo mật web toàn diện, tạo báo cáo chi tiết và hướng dẫn khắc phục.

## 📋 Danh Sách Các Scanner

### 1. **scanSRI.py** - Subresource Integrity Scanner
Quét lỗi thiếu SRI (Subresource Integrity) cho external resources (JS/CSS từ CDN).

**Lỗ hổng phát hiện:**
- Thiếu integrity attribute cho script/link tags
- External resources không có SRI protection
- CDN resources có thể bị compromise

**Cách sử dụng:**
```bash
python3 scanSRI.py https://example.com
```

---

### 2. **scanClickjacking2.py** - Clickjacking Scanner
Quét lỗ hổng Clickjacking (thiếu X-Frame-Options / CSP frame-ancestors).

**Lỗ hổng phát hiện:**
- Thiếu X-Frame-Options header
- Thiếu CSP frame-ancestors directive
- Website có thể bị nhúng vào iframe độc hại

**Cách sử dụng:**
```bash
python3 scanClickjacking2.py https://example.com
```

---

### 3. **scanOptions.py** - HTTP OPTIONS Method Scanner
Quét lỗi cấu hình HTTP OPTIONS method.

**Lỗ hổng phát hiện:**
- Tiết lộ danh sách HTTP methods
- Methods nguy hiểm được phép (PUT, DELETE, TRACE)
- Information disclosure

**Cách sử dụng:**
```bash
python3 scanOptions.py https://example.com
```

---

### 4. **scanCSRF.py** - CSRF Protection Scanner
Quét lỗ hổng Cross-Site Request Forgery.

**Lỗ hổng phát hiện:**
- POST forms thiếu CSRF token
- Cookies thiếu SameSite attribute
- Không có CSRF protection headers

**Cách sử dụng:**
```bash
python3 scanCSRF.py https://example.com
```

---

### 5. **scanSecurityHeaders.py** - Security Headers Scanner
Quét các security headers còn thiếu hoặc cấu hình sai.

**Headers kiểm tra:**
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- X-XSS-Protection

**Cách sử dụng:**
```bash
python3 scanSecurityHeaders.py https://example.com
```

---

### 6. **scanCORS.py** - CORS Configuration Scanner
Quét cấu hình CORS không an toàn.

**Lỗ hổng phát hiện:**
- ACAO wildcard (*)
- Reflect arbitrary origins
- ACAO = null
- Allow-Credentials với ACAO không an toàn

**Cách sử dụng:**
```bash
python3 scanCORS.py https://example.com
```

---

### 7. **scanSSL.py** - SSL/TLS Security Scanner
Quét lỗ hổng SSL/TLS và certificate issues.

**Lỗ hổng phát hiện:**
- Certificate hết hạn
- TLS version cũ (TLSv1.0, TLSv1.1, SSLv3)
- Weak cipher suites
- SSL/TLS configuration issues

**Cách sử dụng:**
```bash
python3 scanSSL.py https://example.com
```

---

### 8. **scanMixedContent.py** - Mixed Content Scanner
Quét lỗi Mixed Content (HTTP resources trong HTTPS page).

**Lỗ hổng phát hiện:**
- HTTP scripts trong HTTPS page (Active Mixed Content)
- HTTP images/media trong HTTPS page (Passive Mixed Content)
- HTTP iframes, stylesheets

**Cách sử dụng:**
```bash
python3 scanMixedContent.py https://example.com
```

---

### 9. **scanCookies.py** - Cookie Security Scanner
Quét cấu hình Cookie không an toàn.

**Lỗ hổng phát hiện:**
- Thiếu Secure flag (trên HTTPS)
- Thiếu HttpOnly flag
- Thiếu SameSite attribute
- Cookie configuration issues

**Cách sử dụng:**
```bash
python3 scanCookies.py https://example.com
```

---

## 🚀 Cài Đặt

### Requirements:

```bash
pip install requests beautifulsoup4
```

Hoặc:

```bash
pip install -r requirements.txt
```

### Tạo file requirements.txt:

```txt
requests>=2.28.0
beautifulsoup4>=4.11.0
```

---

## 📖 Hướng Dẫn Sử Dụng Chung

### Cách 1: Chạy từng scanner

```bash
# Scanner cụ thể
python3 scanCSRF.py https://example.com

# Với tham số từ command line
python3 scanSecurityHeaders.py https://example.com
```

### Cách 2: Chạy tất cả scanners

Tạo script `scan_all.sh`:

```bash
#!/bin/bash

URL=$1

if [ -z "$URL" ]; then
    echo "Usage: ./scan_all.sh <URL>"
    exit 1
fi

echo "🔍 Scanning $URL với tất cả scanners..."

python3 scanSRI.py "$URL"
python3 scanClickjacking2.py "$URL"
python3 scanOptions.py "$URL"
python3 scanCSRF.py "$URL"
python3 scanSecurityHeaders.py "$URL"
python3 scanCORS.py "$URL"
python3 scanSSL.py "$URL"
python3 scanMixedContent.py "$URL"
python3 scanCookies.py "$URL"

echo "✅ Hoàn tất! Kiểm tra các file report_*.md"
```

Chạy:
```bash
chmod +x scan_all.sh
./scan_all.sh https://example.com
```

---

## 📊 Output Format

Mỗi scanner tạo ra:

1. **Console Output:**
   - Real-time scanning progress
   - Tóm tắt kết quả
   - Điểm bảo mật (0-100)
   - CVSS score

2. **Markdown Report:**
   - Phân tích chi tiết
   - Quick test commands
   - So sánh có/không có lỗi
   - Kịch bản tấn công thực tế
   - Hướng dẫn khắc phục từng bước
   - Code examples (Nginx, Apache, Node.js, etc.)
   - Verify commands

**Ví dụ tên file report:**
- `csrf_report_example.com_20240315_143022.md`
- `security_headers_report_example.com_20240315_143030.md`

---

## 🎯 Workflow Khuyến Nghị

### Bước 1: Scan toàn bộ
```bash
./scan_all.sh https://your-website.com
```

### Bước 2: Review reports
- Đọc từng report `.md` file
- Prioritize theo CVSS score và risk level
- Focus vào High/Critical issues trước

### Bước 3: Fix issues
- Follow hướng dẫn khắc phục trong report
- Test trên staging environment
- Deploy lên production

### Bước 4: Verify
- Chạy lại scanners để verify
- Điểm bảo mật phải tăng lên
- Tất cả High/Critical issues phải = 0

### Bước 5: Regular scans
- Weekly: Quick scan các critical scanners
- Monthly: Full scan tất cả
- After major changes: Full scan

---

## 🔥 Priority Matrix

### 🔴 Critical (Fix Immediately):
1. **scanSSL.py** - Certificate expired, weak TLS
2. **scanCSRF.py** - No CSRF protection
3. **scanSecurityHeaders.py** - Missing HSTS, CSP
4. **scanMixedContent.py** - Active mixed content (scripts)

### ⚠️ High (Fix Soon):
1. **scanClickjacking2.py** - No X-Frame-Options
2. **scanCORS.py** - Wildcard CORS
3. **scanCookies.py** - Missing Secure/HttpOnly
4. **scanSRI.py** - No SRI for CDN resources

### ℹ️ Medium/Low (Fix When Possible):
1. **scanOptions.py** - OPTIONS method disclosure
2. **scanMixedContent.py** - Passive mixed content (images)

---

## 📈 Security Score Calculation

Mỗi scanner tính điểm từ 0-100:

- **90-100:** ✅ Excellent - Bảo mật tốt
- **70-89:** ⚠️ Good - Còn một số vấn đề nhỏ
- **50-69:** ⚠️ Fair - Cần cải thiện
- **0-49:** 🔴 Poor - Nguy hiểm, cần fix ngay

**Overall Security Score:**
```
Total Score = Average(All Scanner Scores)
```

---

## 🔗 Online Tools Bổ Sung

Sau khi fix, verify bằng online tools:

1. **SecurityHeaders.com**
   - https://securityheaders.com/
   - Comprehensive security headers check

2. **Mozilla Observatory**
   - https://observatory.mozilla.org/
   - Overall security scan + recommendations

3. **SSL Labs**
   - https://www.ssllabs.com/ssltest/
   - Detailed SSL/TLS analysis

4. **CSP Evaluator**
   - https://csp-evaluator.withgoogle.com/
   - Validate CSP policy

---

## 📝 Best Practices

### 1. **Scan Before Deploy:**
```bash
# Pre-deployment checklist
./scan_all.sh https://staging.example.com
# Fix all High/Critical issues
# Deploy to production
./scan_all.sh https://example.com
```

### 2. **CI/CD Integration:**
```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Security Headers Scan
        run: python3 scanSecurityHeaders.py ${{ secrets.STAGING_URL }}
      - name: CSRF Scan
        run: python3 scanCSRF.py ${{ secrets.STAGING_URL }}
```

### 3. **Regular Audits:**
- Monthly full scans
- After dependency updates
- Before major releases
- After security incidents

### 4. **Documentation:**
- Lưu tất cả reports
- Track security score over time
- Document fixes và decisions
- Share với team

---

## 🐛 Troubleshooting

### Lỗi: "Module not found"
```bash
pip install requests beautifulsoup4
```

### Lỗi: "Connection timeout"
```bash
# Tăng timeout trong code hoặc check network
# Hoặc thử URL khác
```

### Lỗi: "Permission denied"
```bash
chmod +x *.py
chmod +x scan_all.sh
```

### Website chặn scanner:
- Một số website có WAF/rate limiting
- Thêm delay giữa requests
- Sử dụng user-agent header
- Contact website owner nếu cần

---

## 📚 References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Mozilla Web Security](https://infosec.mozilla.org/guidelines/web_security)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)

---

## 🤝 Contributing

Muốn thêm scanner mới?

1. Follow cấu trúc của scanners hiện có
2. Include chi tiết:
   - Scan function
   - Risk analysis
   - Markdown report generator
   - Quick test commands
   - Remediation guide
3. Test kỹ với nhiều websites
4. Update README này

---

## 📄 License

MIT License - Free to use and modify

---

## 👨‍💻 Author

Created for security testing and educational purposes.

**⚠️ Legal Notice:**
Chỉ sử dụng các tools này để scan websites bạn sở hữu hoặc có permission.
Scan websites mà không có permission là bất hợp pháp.

---

## 🎓 Learning Resources

Muốn tìm hiểu sâu hơn về web security?

1. **OWASP:**
   - [OWASP Top 10](https://owasp.org/www-project-top-ten/)
   - [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)

2. **PortSwigger Web Security Academy:**
   - https://portswigger.net/web-security

3. **HackerOne:**
   - https://www.hackerone.com/hackers/hacker101

4. **Bug Bounty Platforms:**
   - HackerOne
   - Bugcrowd
   - Synack

---

**Happy Scanning! 🔍🛡️**
