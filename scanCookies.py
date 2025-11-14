#!/usr/bin/env python3
"""
.\scanCookies.py
Cookie Security Scanner
Quét lỗi cấu hình Cookie không an toàn
"""

import requests
import sys
from datetime import datetime
from urllib.parse import urlparse

class CookieSecurityScanner:
    def __init__(self, url):
        self.url = self.normalize_url(url)
        self.domain = urlparse(self.url).netloc
        self.is_https = self.url.startswith('https://')
        self.scan_time = datetime.now()
        self.results = {}

    def normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    def scan_cookies(self):
        print(f"\n{'='*70}")
        print(f"🔍 ĐANG QUÉT: {self.url}")
        print(f"{'='*70}\n")

        try:
            print("📤 Test 1: Gửi request và lấy cookies...")
            response = requests.get(self.url, timeout=10, allow_redirects=True)

            print(f"   ✓ Status: {response.status_code}")

            # Parse cookies từ Set-Cookie headers
            print("\n📤 Test 2: Phân tích Set-Cookie headers...")
            cookies = self.parse_cookies(response)
            self.results['cookies'] = cookies

            if not cookies:
                print("   ℹ️ Không có Set-Cookie headers trong response")
                self.results['has_cookies'] = False
            else:
                print(f"   ✓ Tìm thấy {len(cookies)} cookies")
                self.results['has_cookies'] = True

                for cookie in cookies:
                    print(f"\n   Cookie: {cookie['name']}")
                    print(f"     • Secure: {cookie['secure']}")
                    print(f"     • HttpOnly: {cookie['httponly']}")
                    print(f"     • SameSite: {cookie['samesite'] or 'KHÔNG CÓ'}")
                    print(f"     • Domain: {cookie['domain'] or 'KHÔNG CÓ'}")
                    print(f"     • Path: {cookie['path']}")

            self.analyze_risk()

            print(f"\n{'='*70}")
            print(f"✅ QUÉT HOÀN TẤT")
            print(f"{'='*70}\n")

            return True

        except Exception as e:
            print(f"❌ LỖI: {str(e)}")
            return False

    def parse_cookies(self, response):
        cookies = []

        # Get all Set-Cookie headers (can be multiple)
        set_cookie_headers = response.headers.get_list('Set-Cookie') if hasattr(response.headers, 'get_list') else []

        # Fallback: requests library format
        if not set_cookie_headers:
            for cookie in response.cookies:
                cookie_data = {
                    'name': cookie.name,
                    'value': cookie.value[:20] + '...' if len(cookie.value) > 20 else cookie.value,
                    'domain': cookie.domain,
                    'path': cookie.path,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('HttpOnly') if hasattr(cookie, 'has_nonstandard_attr') else False,
                    'samesite': cookie.get_nonstandard_attr('SameSite') if hasattr(cookie, 'get_nonstandard_attr') else None
                }
                cookies.append(cookie_data)

        return cookies

    def analyze_risk(self):
        if not self.results.get('has_cookies'):
            self.results['is_vulnerable'] = False
            self.results['risk_level'] = 'Info'
            self.results['cvss_score'] = 0.0
            self.results['protection_score'] = 100
            self.results['assessment'] = 'ℹ️ Không có cookies để kiểm tra'
            self.results['issues'] = []
            self.results['protections'] = ['Không sử dụng cookies']
            return

        cookies = self.results['cookies']
        issues = []
        protections = []
        score = 100

        for cookie in cookies:
            name = cookie['name']

            # Check Secure flag
            if self.is_https and not cookie['secure']:
                issues.append(f"Cookie '{name}': THIẾU Secure flag (trên HTTPS)")
                score -= 15
            elif cookie['secure']:
                protections.append(f"Cookie '{name}': CÓ Secure flag")

            # Check HttpOnly flag
            if not cookie['httponly']:
                issues.append(f"Cookie '{name}': THIẾU HttpOnly flag")
                score -= 15
            else:
                protections.append(f"Cookie '{name}': CÓ HttpOnly flag")

            # Check SameSite
            if not cookie['samesite']:
                issues.append(f"Cookie '{name}': THIẾU SameSite attribute")
                score -= 20
            elif cookie['samesite'].lower() not in ['strict', 'lax']:
                issues.append(f"Cookie '{name}': SameSite = {cookie['samesite']} (nên dùng Strict/Lax)")
                score -= 10
            else:
                protections.append(f"Cookie '{name}': CÓ SameSite = {cookie['samesite']}")

        self.results['protection_score'] = max(0, score)
        self.results['issues'] = issues
        self.results['protections'] = protections
        self.results['is_vulnerable'] = len(issues) > 0

        if score < 40:
            self.results['risk_level'] = 'High'
            self.results['cvss_score'] = 5.3
            self.results['assessment'] = '🔴 COOKIES CẤU HÌNH KHÔNG AN TOÀN'
        elif score < 70:
            self.results['risk_level'] = 'Medium'
            self.results['cvss_score'] = 4.0
            self.results['assessment'] = '⚠️ COOKIES CẦN CẢI THIỆN'
        else:
            self.results['risk_level'] = 'Low'
            self.results['cvss_score'] = 0.0
            self.results['assessment'] = '✅ COOKIES ĐƯỢC CẤU HÌNH TỐT'

    def generate_markdown_report(self):
        report = f"""# 🍪 Phân tích: "Insecure Cookie Configuration"

**Ngày:** {self.scan_time.strftime('%d/%m/%Y %H:%M:%S')}
**Website:** {self.url}
**Phân loại:** {"🔴 Issues Found" if self.results['is_vulnerable'] else "✅ Secure"}

---

## 🧪 Kết quả quét

"""

        if not self.results.get('has_cookies'):
            report += "ℹ️ Website không set cookies trong response.\n\n"
        else:
            cookies = self.results['cookies']
            report += f"**Tổng số cookies:** {len(cookies)}\n\n"

            report += "| Cookie Name | Secure | HttpOnly | SameSite | Status |\n"
            report += "|-------------|--------|----------|----------|--------|\n"

            for cookie in cookies:
                secure_icon = "✅" if cookie['secure'] else "❌"
                httponly_icon = "✅" if cookie['httponly'] else "❌"
                samesite_val = cookie['samesite'] or "❌ None"
                samesite_icon = "✅" if cookie['samesite'] and cookie['samesite'].lower() in ['strict', 'lax'] else "❌"

                # Overall status
                if cookie['secure'] and cookie['httponly'] and cookie['samesite']:
                    status = "✅ Secure"
                else:
                    status = "❌ Issues"

                report += f"| `{cookie['name']}` | {secure_icon} | {httponly_icon} | {samesite_val} {samesite_icon} | {status} |\n"

        report += f"""

---

## 📊 Đánh giá

**Điểm bảo mật:** {self.results['protection_score']}/100
**Rủi ro:** {self.results['risk_level']}
**CVSS:** {self.results['cvss_score']}

"""

        if self.results.get('issues'):
            report += "### ❌ Vấn đề:\n\n"
            for issue in self.results['issues']:
                report += f"- {issue}\n"

        if self.results.get('protections'):
            report += "\n### ✅ Bảo vệ:\n\n"
            for prot in self.results['protections']:
                report += f"- {prot}\n"

        report += """

---

## 💡 Giải thích Cookie Attributes

### Secure Flag:
- **Mục đích:** Cookie chỉ gửi qua HTTPS
- **Rủi ro nếu thiếu:** Cookie có thể bị đánh cắp qua HTTP (MITM)

### HttpOnly Flag:
- **Mục đích:** Ngăn JavaScript đọc cookie (document.cookie)
- **Rủi ro nếu thiếu:** XSS attack có thể đánh cắp session cookie

### SameSite Attribute:
- **Strict:** Cookie chỉ gửi khi request từ cùng site (bảo mật cao nhất)
- **Lax:** Cookie gửi khi navigate đến site (balance UX và bảo mật)
- **None:** Cookie luôn gửi (phải có Secure flag)
- **Rủi ro nếu thiếu:** CSRF attacks

---

## 🔧 Khắc phục

### Node.js (Express):

```javascript
const session = require('express-session');

app.use(session({
  secret: 'your-secret-key',
  cookie: {
    secure: true,        // Chỉ HTTPS
    httpOnly: true,      // Không thể đọc bằng JS
    sameSite: 'strict',  // CSRF protection
    maxAge: 3600000      // 1 hour
  }
}));

// Set cookie manually
res.cookie('session', value, {
  secure: true,
  httpOnly: true,
  sameSite: 'strict'
});
```

### PHP:

```php
session_start([
    'cookie_secure' => true,
    'cookie_httponly' => true,
    'cookie_samesite' => 'Strict'
]);

// Set cookie
setcookie(
    'session',
    $value,
    [
        'expires' => time() + 3600,
        'path' => '/',
        'domain' => '.example.com',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Strict'
    ]
);
```

### Nginx (modify existing cookies):

```nginx
proxy_cookie_path / "/; Secure; HttpOnly; SameSite=Strict";
```

### Apache:

```apache
# Modify Set-Cookie headers
Header edit Set-Cookie ^(.*)$ "$1; Secure; HttpOnly; SameSite=Strict"
```

---

## 🧪 Kiểm tra

### Browser DevTools:

```javascript
// F12 → Console
// Xem cookies
document.cookie

// Cookies có HttpOnly sẽ KHÔNG hiển thị ở đây (tốt!)
```

### Chrome DevTools:

```
F12 → Application → Cookies → Select domain
→ Xem cột Secure, HttpOnly, SameSite
```

### curl:

```bash
curl -I """ + self.url + """ | grep -i "set-cookie"
```

---

**Prepared by:** Cookie Security Scanner
**Scan Time:** {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}
"""
        return report

    def save_report(self, filename=None):
        if filename is None:
            timestamp = self.scan_time.strftime('%Y%m%d_%H%M%S')
            filename = f"cookie_report_{self.domain}_{timestamp}.md"

        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(self.generate_markdown_report())
            print(f"✅ Đã lưu báo cáo: {filename}")
            return filename
        except Exception as e:
            print(f"❌ Lỗi: {str(e)}")
            return None

def main():
    print("="*70)
    print("🛡️  COOKIE SECURITY SCANNER")
    print("="*70 + "\n")

    url = sys.argv[1] if len(sys.argv) > 1 else input("🔍 Nhập URL: ").strip()
    if not url:
        print("❌ Vui lòng nhập URL!")
        return

    scanner = CookieSecurityScanner(url)

    if not scanner.scan_cookies():
        return

    print("\n" + "="*70)
    print("📊 TÓM TẮT")
    print("="*70)
    print(f"Website: {scanner.url}")
    print(f"Đánh giá: {scanner.results['assessment']}")
    print(f"Điểm bảo mật: {scanner.results['protection_score']}/100")

    if scanner.results.get('has_cookies'):
        print(f"Số cookies: {len(scanner.results['cookies'])}")

    if scanner.results.get('is_vulnerable'):
        print("\n⚠️ PHÁT HIỆN VẤN ĐỀ!")
        for issue in scanner.results.get('issues', []):
            print(f"  ❌ {issue}")
    else:
        print("\n✅ Cookies được cấu hình tốt!")

    print("="*70 + "\n")

    save = input("💾 Lưu báo cáo? (y/n): ").strip().lower()
    if save in ['y', 'yes', 'có']:
        scanner.save_report()

if __name__ == "__main__":
    main()
