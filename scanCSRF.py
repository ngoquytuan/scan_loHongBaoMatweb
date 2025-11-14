#!/usr/bin/env python3
"""
.\scanCSRF.py
Cross-Site Request Forgery (CSRF) Scanner & Report Generator
Quét lỗi thiếu CSRF protection và tạo báo cáo chi tiết về các vấn đề bảo mật
"""

import requests
import sys
from datetime import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import re

class CSRFSecurityScanner:
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

    def scan_csrf(self):
        """Quét CSRF protection"""
        print(f"\n{'='*70}")
        print(f"🔍 ĐANG QUÉT: {self.url}")
        print(f"{'='*70}\n")

        try:
            # Test GET request để lấy HTML
            print("📤 Test 1: Gửi GET request để kiểm tra forms...")
            response = requests.get(self.url, timeout=10, allow_redirects=True)

            self.results['status_code'] = response.status_code
            self.results['headers'] = dict(response.headers)
            self.results['html_content'] = response.text

            print(f"   ✓ Status Code: {response.status_code}")
            print(f"   ✓ Content Length: {len(response.text)} bytes")

            # Kiểm tra CSRF headers
            print("\n📤 Test 2: Kiểm tra CSRF protection headers...")
            csrf_headers = {
                'X-CSRF-Token': response.headers.get('X-CSRF-Token'),
                'X-XSRF-Token': response.headers.get('X-XSRF-Token'),
                'CSRF-Token': response.headers.get('CSRF-Token')
            }

            self.results['csrf_headers'] = {k: v for k, v in csrf_headers.items() if v}

            for header, value in csrf_headers.items():
                if value:
                    print(f"   ✅ {header}: {value[:20]}...")
                else:
                    print(f"   ❌ {header}: KHÔNG CÓ")

            # Parse HTML để tìm forms
            print("\n📤 Test 3: Phân tích HTML forms...")
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            print(f"   ✓ Tìm thấy {len(forms)} forms")

            # Phân tích từng form
            self.results['forms'] = self.analyze_forms(forms)

            # Kiểm tra SameSite cookies
            print("\n📤 Test 4: Kiểm tra SameSite cookie attribute...")
            self.results['cookies'] = self.check_samesite_cookies(response.headers)

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

    def analyze_forms(self, forms):
        """Phân tích forms để kiểm tra CSRF token"""
        form_analysis = {
            'total': len(forms),
            'with_csrf': 0,
            'without_csrf': 0,
            'get_forms': 0,
            'post_forms': 0,
            'details': []
        }

        csrf_patterns = [
            r'csrf[_-]?token',
            r'_csrf',
            r'xsrf[_-]?token',
            r'_xsrf',
            r'authenticity[_-]?token',
            r'__requestverificationtoken'
        ]

        for idx, form in enumerate(forms, 1):
            method = (form.get('method', 'GET')).upper()
            action = form.get('action', '')

            if method == 'GET':
                form_analysis['get_forms'] += 1
            else:
                form_analysis['post_forms'] += 1

            # Tìm CSRF token trong form
            has_csrf = False
            csrf_field_name = None

            inputs = form.find_all('input')
            for inp in inputs:
                name = inp.get('name', '').lower()
                input_type = inp.get('type', '').lower()

                # Kiểm tra xem có khớp với pattern CSRF không
                for pattern in csrf_patterns:
                    if re.search(pattern, name, re.IGNORECASE):
                        has_csrf = True
                        csrf_field_name = inp.get('name')
                        break

                if has_csrf:
                    break

            if has_csrf:
                form_analysis['with_csrf'] += 1
                status = "✅"
                print(f"   ✅ Form {idx} ({method}): CÓ CSRF token ({csrf_field_name})")
            else:
                if method == 'POST' or method == 'PUT' or method == 'DELETE':
                    form_analysis['without_csrf'] += 1
                    status = "❌"
                    print(f"   ❌ Form {idx} ({method}): THIẾU CSRF token")
                else:
                    status = "ℹ️"
                    print(f"   ℹ️ Form {idx} ({method}): GET form (không cần CSRF)")

            form_analysis['details'].append({
                'index': idx,
                'method': method,
                'action': action,
                'has_csrf': has_csrf,
                'csrf_field': csrf_field_name,
                'status': status,
                'inputs_count': len(inputs)
            })

        return form_analysis

    def check_samesite_cookies(self, headers):
        """Kiểm tra SameSite attribute của cookies"""
        cookie_info = {
            'has_cookies': False,
            'cookies_with_samesite': 0,
            'cookies_without_samesite': 0,
            'details': []
        }

        set_cookie_headers = []
        for key, value in headers.items():
            if key.lower() == 'set-cookie':
                set_cookie_headers.append(value)

        if not set_cookie_headers:
            print("   ℹ️ Không có Set-Cookie headers trong response")
            return cookie_info

        cookie_info['has_cookies'] = True

        for cookie_str in set_cookie_headers:
            # Parse cookie
            parts = cookie_str.split(';')
            cookie_name = parts[0].split('=')[0].strip() if parts else 'Unknown'

            has_samesite = 'samesite' in cookie_str.lower()
            has_secure = 'secure' in cookie_str.lower()
            has_httponly = 'httponly' in cookie_str.lower()

            if has_samesite:
                cookie_info['cookies_with_samesite'] += 1
                print(f"   ✅ Cookie '{cookie_name}': CÓ SameSite")
            else:
                cookie_info['cookies_without_samesite'] += 1
                print(f"   ❌ Cookie '{cookie_name}': THIẾU SameSite")

            # Lấy giá trị SameSite nếu có
            samesite_value = None
            if has_samesite:
                for part in parts:
                    if 'samesite' in part.lower():
                        samesite_value = part.split('=')[1].strip() if '=' in part else 'True'
                        break

            cookie_info['details'].append({
                'name': cookie_name,
                'has_samesite': has_samesite,
                'samesite_value': samesite_value,
                'has_secure': has_secure,
                'has_httponly': has_httponly
            })

        return cookie_info

    def analyze_risk(self):
        """Phân tích mức độ rủi ro"""
        forms = self.results.get('forms', {})
        cookies = self.results.get('cookies', {})

        self.results['is_vulnerable'] = False
        self.results['risk_level'] = 'Low'
        self.results['cvss_score'] = 0.0
        self.results['protection_score'] = 0

        score = 0
        issues = []
        protections = []

        # Đánh giá forms
        total_forms = forms.get('total', 0)
        post_forms = forms.get('post_forms', 0)
        forms_with_csrf = forms.get('with_csrf', 0)
        forms_without_csrf = forms.get('without_csrf', 0)

        if total_forms == 0:
            score += 50
            protections.append("Không có forms trên trang")
        else:
            if post_forms == 0:
                score += 40
                protections.append("Không có POST forms (chỉ GET forms)")
            else:
                if forms_without_csrf == 0:
                    score += 50
                    protections.append(f"Tất cả {post_forms} POST forms đều có CSRF token")
                else:
                    ratio = forms_with_csrf / post_forms if post_forms > 0 else 0
                    score += int(ratio * 50)
                    issues.append(f"{forms_without_csrf}/{post_forms} POST forms THIẾU CSRF token")

        # Đánh giá cookies
        if cookies.get('has_cookies'):
            total_cookies = cookies['cookies_with_samesite'] + cookies['cookies_without_samesite']
            if cookies['cookies_without_samesite'] == 0:
                score += 50
                protections.append(f"Tất cả {total_cookies} cookies đều có SameSite attribute")
            else:
                ratio = cookies['cookies_with_samesite'] / total_cookies if total_cookies > 0 else 0
                score += int(ratio * 50)
                issues.append(f"{cookies['cookies_without_samesite']}/{total_cookies} cookies THIẾU SameSite")
        else:
            score += 25
            protections.append("Không có cookies được set")

        # Đánh giá CSRF headers
        if self.results.get('csrf_headers'):
            protections.append(f"Có CSRF headers: {', '.join(self.results['csrf_headers'].keys())}")

        self.results['protection_score'] = min(score, 100)
        self.results['issues'] = issues
        self.results['protections'] = protections

        # Đánh giá tổng quan
        if score < 40:
            self.results['is_vulnerable'] = True
            self.results['risk_level'] = 'High'
            self.results['cvss_score'] = 6.5
            self.results['assessment'] = '🔴 DỄ BỊ TẤNÔNG CSRF - Thiếu protection'
        elif score < 70:
            self.results['is_vulnerable'] = True
            self.results['risk_level'] = 'Medium'
            self.results['cvss_score'] = 4.3
            self.results['assessment'] = '⚠️ BẢO VỆ YẾU - Cần tăng cường CSRF protection'
        else:
            self.results['is_vulnerable'] = False
            self.results['risk_level'] = 'Low'
            self.results['cvss_score'] = 0.0
            self.results['assessment'] = '✅ ĐƯỢC BẢO VỆ TỐT - An toàn trước CSRF'

    def generate_markdown_report(self):
        """Tạo báo cáo Markdown chi tiết"""

        report = f"""# 🔐 Phân tích kỹ thuật: "Cross-Site Request Forgery (CSRF) Vulnerability"

**Ngày phân tích:** {self.scan_time.strftime('%d/%m/%Y %H:%M:%S')}
**Website:** {self.url}
**Domain:** {self.domain}
**Phân loại:** {"🔴 Vulnerability Detected" if self.results['is_vulnerable'] else "✅ Protected"}

---

## 🚀 Quick Test Commands (Copy & Paste)

### Test nhanh bằng browser (30 giây):

```bash
# Mở Developer Tools (F12) trong Chrome/Firefox
# → Console → chạy lệnh:

// Kiểm tra forms có CSRF token không
document.querySelectorAll('form').forEach((form, i) => {{
  const method = form.method.toUpperCase();
  const csrfInput = form.querySelector('input[name*="csrf" i], input[name*="token" i], input[name="_xsrf"]');

  if (method === 'POST' || method === 'PUT' || method === 'DELETE') {{
    if (!csrfInput) {{
      console.error(`❌ Form ${{i+1}} (${{method}}): THIẾU CSRF token`);
    }} else {{
      console.log(`✅ Form ${{i+1}} (${{method}}): CÓ CSRF token (${{csrfInput.name}})`);
    }}
  }}
}});

// Kiểm tra cookies có SameSite không
document.cookie.split(';').forEach(c => {{
  console.log('Cookie:', c.trim());
}});
```

### Test bằng curl:

```bash
# Kiểm tra response headers
curl -I {self.url} | grep -i "csrf\|xsrf"

# Kiểm tra cookies
curl -I {self.url} | grep -i "set-cookie"
```

---

## 📚 1. Tham chiếu chuẩn kỹ thuật

- **OWASP Top 10 2021:** A01:2021 – Broken Access Control
- **CWE-352:** Cross-Site Request Forgery (CSRF)
- **CAPEC-62:** Cross Site Request Forgery
- **OWASP CSRF Prevention Cheat Sheet**

### CSRF là gì?

**Cross-Site Request Forgery (CSRF)** là kỹ thuật tấn công buộc người dùng đã authenticated thực hiện các hành động không mong muốn trên web application.

**Cách hoạt động:**

1. Nạn nhân đăng nhập vào website tin cậy (ví dụ: bank.com)
2. Website lưu session cookie trong browser
3. Nạn nhân truy cập trang độc hại (evil.com) - trong khi vẫn còn session
4. Trang độc hại gửi request đến bank.com
5. Browser tự động attach cookies → Request được xác thực
6. Hành động độc hại được thực hiện (chuyển tiền, đổi password, etc.)

**Ví dụ tấn công:**

```html
<!-- Trang của attacker: evil.com -->
<html>
<body>
  <h1>Xem ảnh mèo dễ thương!</h1>
  <img src="https://bank.com/transfer?to=attacker&amount=1000000" style="display:none">

  <!-- Hoặc dùng form tự động submit -->
  <form action="https://bank.com/transfer" method="POST" id="csrf-form">
    <input type="hidden" name="to" value="attacker">
    <input type="hidden" name="amount" value="1000000">
  </form>
  <script>
    document.getElementById('csrf-form').submit();
  </script>
</body>
</html>
```

**Kết quả:** Nạn nhân vừa chuyển 1 triệu đồng cho attacker mà không hề biết!

---

## 🧪 2. Kết quả kiểm tra thực tế

### Test 1: CSRF Protection Headers

```bash
curl -I {self.url}
```

**CSRF Headers phát hiện:**

"""

        if self.results.get('csrf_headers'):
            report += "```http\n"
            for header, value in self.results['csrf_headers'].items():
                report += f"{header}: {value[:50]}...\n"
            report += "```\n\n✅ Có CSRF headers được thiết lập\n\n"
        else:
            report += "```\n(Không có CSRF headers)\n```\n\n❌ Không có CSRF headers trong response\n\n"

        # Forms analysis
        forms = self.results.get('forms', {})
        report += f"""### Test 2: HTML Forms Analysis

**Tổng số forms:** {forms.get('total', 0)}
**GET forms:** {forms.get('get_forms', 0)}
**POST forms:** {forms.get('post_forms', 0)}
**Forms CÓ CSRF token:** {forms.get('with_csrf', 0)}
**Forms THIẾU CSRF token:** {forms.get('without_csrf', 0)}

"""

        # Chi tiết từng form
        form_details = forms.get('details', [])
        if form_details:
            report += "| Form | Method | Action | CSRF Token | Status |\n"
            report += "|------|--------|--------|------------|--------|\n"

            for form in form_details:
                action_short = form['action'][:40] + "..." if len(form['action']) > 40 else form['action'] or '(current page)'
                csrf_status = f"✅ {form['csrf_field']}" if form['has_csrf'] else "❌ Thiếu"
                report += f"| Form {form['index']} | {form['method']} | `{action_short}` | {csrf_status} | {form['status']} |\n"

        # Cookies analysis
        cookies = self.results.get('cookies', {})
        report += f"""

### Test 3: Cookie SameSite Attribute

**Có cookies:** {"✅ Có" if cookies.get('has_cookies') else "❌ Không"}
"""

        if cookies.get('has_cookies'):
            report += f"""**Cookies CÓ SameSite:** {cookies.get('cookies_with_samesite', 0)}
**Cookies THIẾU SameSite:** {cookies.get('cookies_without_samesite', 0)}

"""

            cookie_details = cookies.get('details', [])
            if cookie_details:
                report += "| Cookie Name | SameSite | Secure | HttpOnly | Status |\n"
                report += "|-------------|----------|--------|----------|--------|\n"

                for cookie in cookie_details:
                    samesite_val = f"✅ {cookie['samesite_value']}" if cookie['has_samesite'] else "❌ Thiếu"
                    secure = "✅" if cookie['has_secure'] else "❌"
                    httponly = "✅" if cookie['has_httponly'] else "❌"
                    status = "✅" if cookie['has_samesite'] else "❌"
                    report += f"| `{cookie['name']}` | {samesite_val} | {secure} | {httponly} | {status} |\n"

        report += """

---

## 📊 3. So sánh: Có lỗi vs Không có lỗi

### ❌ Trường hợp CÓ LỖ HỔNG (nguy hiểm):

```html
<!-- Form không có CSRF token -->
<form action="/transfer" method="POST">
  <input name="to" value="recipient">
  <input name="amount" value="100">
  <button type="submit">Transfer</button>
</form>
```

**Rủi ro thực tế:**

1. **Chuyển tiền trái phép:**
   ```html
   <!-- Trang attacker -->
   <form action="https://bank.com/transfer" method="POST">
     <input type="hidden" name="to" value="attacker">
     <input type="hidden" name="amount" value="999999">
   </form>
   <script>document.forms[0].submit();</script>
   ```

2. **Thay đổi mật khẩu:**
   ```html
   <form action="https://victim.com/change-password" method="POST">
     <input type="hidden" name="new_password" value="hacked123">
   </form>
   <script>document.forms[0].submit();</script>
   ```

3. **Xóa tài khoản:**
   ```html
   <img src="https://victim.com/delete-account?confirm=yes">
   ```

### ✅ Trường hợp AN TOÀN (có CSRF protection):

```html
<!-- Form có CSRF token -->
<form action="/transfer" method="POST">
  <input type="hidden" name="_csrf" value="a7f3c9b2e1d4f8a6">
  <input name="to" value="recipient">
  <input name="amount" value="100">
  <button type="submit">Transfer</button>
</form>
```

**Bảo vệ:**
- Server tạo unique token cho mỗi session/request
- Token được nhúng vào form
- Server verify token trước khi xử lý request
- Request từ bên ngoài không có token → bị reject

"""

        # Trường hợp hiện tại
        report += f"""### {"✅ Trường hợp AN TOÀN" if not self.results['is_vulnerable'] else "🔴 Trường hợp HIỆN TẠI"} (website đang kiểm tra):

**Phát hiện:**
"""

        if not self.results['is_vulnerable']:
            for prot in self.results.get('protections', []):
                report += f"- ✅ {prot}\n"
        else:
            for issue in self.results.get('issues', []):
                report += f"- ❌ {issue}\n"

        report += """

---

## 🎯 4. Kịch bản tấn công thực tế

### Kịch bản 1: Banking CSRF Attack

**Bước 1:** Nạn nhân đăng nhập vào nganhang.com

**Bước 2:** Attacker gửi email chứa link độc hại hoặc quảng cáo

**Bước 3:** Nạn nhân click vào link → Mở trang evil.com

**Bước 4:** Trang evil.com tự động gửi request:

```html
<form action="https://nganhang.com/api/transfer" method="POST" id="csrf">
  <input type="hidden" name="to_account" value="attacker_account">
  <input type="hidden" name="amount" value="50000000">
  <input type="hidden" name="description" value="Chuyen tien">
</form>
<script>
  document.getElementById('csrf').submit();
</script>
```

**Kết quả:** 50 triệu đồng bị chuyển đi trong vài giây!

### Kịch bản 2: Social Media Account Takeover

```html
<!-- Trang attacker -->
<img src="https://facebook.com/settings/password/change?new=hacked123&confirm=hacked123">
<img src="https://facebook.com/settings/email/change?email=attacker@evil.com">
<img src="https://facebook.com/page/123/admin/add?user=attacker">
```

**Impact:**
- Đổi password
- Đổi email
- Thêm admin vào page
- Đăng bài spam
- Gửi tin nhắn lừa đảo

### Kịch bản 3: E-commerce Order Manipulation

```javascript
// Attacker's page
fetch('https://shop.com/api/cart/add', {
  method: 'POST',
  credentials: 'include', // Tự động gửi cookies
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    product_id: 999,
    quantity: 100,
    shipping_address: 'attacker_address'
  })
});

fetch('https://shop.com/api/checkout', {
  method: 'POST',
  credentials: 'include'
});
```

**Kết quả:** Đơn hàng bị đặt tự động, ship đến địa chỉ attacker

---

## 📋 5. Bảng đánh giá bảo vệ

| Tiêu chí | Kết quả | Đánh giá | Điểm |
|----------|---------|----------|------|
"""

        # Forms protection
        forms = self.results.get('forms', {})
        post_forms = forms.get('post_forms', 0)
        forms_with_csrf = forms.get('with_csrf', 0)

        if post_forms == 0:
            report += "| POST Forms | ℹ️ Không có | Không cần CSRF token | N/A |\n"
        else:
            coverage = int((forms_with_csrf / post_forms) * 100) if post_forms > 0 else 0
            status = "✅" if coverage == 100 else "❌"
            report += f"| POST Forms CSRF Token | {status} {forms_with_csrf}/{post_forms} | {coverage}% coverage | {coverage}/50 |\n"

        # Cookies SameSite
        cookies = self.results.get('cookies', {})
        if cookies.get('has_cookies'):
            total_cookies = cookies['cookies_with_samesite'] + cookies['cookies_without_samesite']
            coverage = int((cookies['cookies_with_samesite'] / total_cookies) * 100) if total_cookies > 0 else 0
            status = "✅" if coverage == 100 else "❌"
            report += f"| Cookies SameSite | {status} {cookies['cookies_with_samesite']}/{total_cookies} | {coverage}% coverage | {coverage}/50 |\n"
        else:
            report += "| Cookies SameSite | ℹ️ Không có cookies | N/A | 25/50 |\n"

        score = self.results['protection_score']
        report += f"\n**Tổng điểm bảo vệ:** {score}/100\n\n"

        if score >= 90:
            report += "✅ **Đánh giá:** BẢO VỆ TỐT - CSRF protection đầy đủ\n"
        elif score >= 50:
            report += "⚠️ **Đánh giá:** BẢO VỆ TRUNG BÌNH - Cần tăng cường\n"
        else:
            report += "🔴 **Đánh giá:** BẢO VỆ YẾU - Dễ bị tấn công CSRF\n"

        if self.results.get('issues'):
            report += "\n### Vấn đề phát hiện:\n\n"
            for issue in self.results['issues']:
                report += f"- ❌ {issue}\n"

        if self.results.get('protections'):
            report += "\n### Điểm mạnh:\n\n"
            for prot in self.results['protections']:
                report += f"- ✅ {prot}\n"

        report += """

---

## 🔧 6. Biện pháp khắc phục

"""

        if self.results['is_vulnerable']:
            report += "### 🔴 CẦN KHẮC PHỤC NGAY\n\n"
        else:
            report += "### ✅ Đã được bảo vệ tốt, có thể tăng cường thêm\n\n"

        report += """### Option A: CSRF Token (Backend Implementation)

**Node.js (Express + csurf):**
```javascript
const csrf = require('csurf');
const cookieParser = require('cookie-parser');

app.use(cookieParser());
app.use(csrf({ cookie: true }));

// Render form với CSRF token
app.get('/form', (req, res) => {
  res.render('form', { csrfToken: req.csrfToken() });
});

// Verify CSRF token (tự động bởi middleware)
app.post('/submit', (req, res) => {
  // CSRF đã được verify
  res.send('Success');
});
```

**Template (EJS/Pug):**
```html
<form method="POST" action="/submit">
  <input type="hidden" name="_csrf" value="<%= csrfToken %>">
  <!-- Other inputs -->
  <button type="submit">Submit</button>
</form>
```

**Django:**
```python
# settings.py
MIDDLEWARE = [
    ...
    'django.middleware.csrf.CsrfViewMiddleware',
]

# Template
<form method="POST">
  {% csrf_token %}
  <!-- Other inputs -->
  <button type="submit">Submit</button>
</form>
```

**Laravel (PHP):**
```php
<!-- Blade template -->
<form method="POST" action="/submit">
  @csrf
  <!-- Other inputs -->
  <button type="submit">Submit</button>
</form>
```

**Ruby on Rails:**
```ruby
# Controller
class ApplicationController < ActionController::Base
  protect_from_forgery with: :exception
end

# View (ERB)
<%= form_with url: "/submit", method: :post do |f| %>
  <%= f.hidden_field :authenticity_token, value: form_authenticity_token %>
  <!-- Other inputs -->
  <%= f.submit "Submit" %>
<% end %>
```

### Option B: SameSite Cookies

**Node.js (Express):**
```javascript
const session = require('express-session');

app.use(session({
  secret: 'your-secret-key',
  cookie: {
    httpOnly: true,
    secure: true, // Chỉ HTTPS
    sameSite: 'strict' // Hoặc 'lax'
  }
}));

// Set cookie manually
res.cookie('session', value, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 3600000 // 1 hour
});
```

**Nginx:**
```nginx
# Thêm SameSite vào Set-Cookie headers
proxy_cookie_path / "/; SameSite=Strict; Secure";
```

**Apache (.htaccess):**
```apache
# Không support trực tiếp, cần implement ở backend
```

**SameSite values:**
- `Strict`: Cookie chỉ gửi khi request từ cùng site (bảo mật nhất)
- `Lax`: Cookie gửi khi navigate đến site (balance giữa bảo mật và UX)
- `None`: Cookie luôn gửi (cần có Secure attribute)

### Option C: Custom Headers (API)

**Frontend (JavaScript/Fetch):**
```javascript
// Get CSRF token từ meta tag hoặc cookie
const csrfToken = document.querySelector('meta[name="csrf-token"]').content;

// Gửi trong header
fetch('/api/endpoint', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrfToken
  },
  body: JSON.stringify(data)
});
```

**Backend validation:**
```javascript
app.use((req, res, next) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    const token = req.headers['x-csrf-token'];
    const sessionToken = req.session.csrfToken;

    if (!token || token !== sessionToken) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
  }
  next();
});
```

### Option D: Double Submit Cookie Pattern

```javascript
// Backend: Set CSRF token vào cookie
res.cookie('XSRF-TOKEN', generateToken(), {
  httpOnly: false, // JavaScript cần đọc được
  secure: true,
  sameSite: 'strict'
});

// Frontend: Đọc cookie và gửi trong header
const csrfToken = document.cookie
  .split('; ')
  .find(row => row.startsWith('XSRF-TOKEN='))
  .split('=')[1];

fetch('/api/endpoint', {
  method: 'POST',
  headers: {
    'X-XSRF-TOKEN': csrfToken
  },
  body: JSON.stringify(data)
});

// Backend: So sánh cookie với header
app.use((req, res, next) => {
  const cookieToken = req.cookies['XSRF-TOKEN'];
  const headerToken = req.headers['x-xsrf-token'];

  if (cookieToken !== headerToken) {
    return res.status(403).send('CSRF token mismatch');
  }
  next();
});
```

**⚠️ Lưu ý quan trọng:**

1. **CSRF token phải:**
   - Unpredictable (dùng cryptographically strong random)
   - Unique per session hoặc per request
   - Được validate ở server-side

2. **SameSite cookies:**
   - `Strict`: Bảo mật cao nhưng có thể ảnh hưởng UX
   - `Lax`: Balance tốt cho hầu hết use cases
   - Luôn kết hợp với `Secure` và `HttpOnly`

3. **Testing:**
   - Test kỹ các flows: login, payment, profile update
   - Verify không ảnh hưởng legitimate users
   - Test với nhiều browsers

---

## ✅ 7. Kiểm tra lại sau khi khắc phục

### Bước 1: Kiểm tra CSRF token trong forms

```javascript
// Browser Console
document.querySelectorAll('form[method="POST"], form[method="post"]').forEach((form, i) => {
  const csrf = form.querySelector('input[name*="csrf" i], input[name*="token" i]');
  if (csrf) {
    console.log(`✅ Form ${i+1}: Có CSRF token (${csrf.name})`);
  } else {
    console.error(`❌ Form ${i+1}: THIẾU CSRF token`);
  }
});
```

### Bước 2: Test CSRF protection thực tế

**Tạo file test-csrf.html:**

```html
<!DOCTYPE html>
<html>
<head><title>CSRF Test</title></head>
<body>
  <h1>CSRF Attack Simulation</h1>
  <form action=\"""" + self.url + """/some-action" method="POST" id="csrf-test">
    <input type="hidden" name="param" value="malicious_value">
    <button type="submit">Test CSRF (Manual)</button>
  </form>

  <script>
    // Auto-submit test (để test protection)
    // document.getElementById('csrf-test').submit();
  </script>

  <p>
    ✅ Nếu request bị reject (403/400) = CSRF protection hoạt động<br>
    ❌ Nếu request thành công = VẪN CÒN LỖI
  </p>
</body>
</html>
```

### Bước 3: Kiểm tra SameSite cookies

```bash
# Chrome DevTools
# F12 → Application → Cookies
# Xem cột "SameSite" phải có giá trị (Strict/Lax)

# Hoặc dùng curl
curl -I """ + self.url + """ | grep -i "set-cookie"
# Kết quả phải có: SameSite=Strict hoặc SameSite=Lax
```

### Bước 4: Automated testing

```javascript
// Playwright/Puppeteer test
const { test, expect } = require('@playwright/test');

test('All POST forms have CSRF token', async ({ page }) => {
  await page.goto('""" + self.url + """');

  const formsWithoutCSRF = await page.evaluate(() => {
    return Array.from(document.querySelectorAll('form'))
      .filter(form => {
        const method = form.method.toUpperCase();
        if (method !== 'POST') return false;

        const csrf = form.querySelector('input[name*="csrf" i]');
        return !csrf;
      })
      .length;
  });

  expect(formsWithoutCSRF).toBe(0);
});
```

### Bước 5: Security scan

```bash
# OWASP ZAP
# Tools → Options → Active Scan → Policy
# Enable "Cross Site Request Forgery"

# Burp Suite
# Scanner → Scan Configuration
# Enable "CSRF Token Missing"

# Scan lại bằng tool này
python3 scanCSRF.py """ + self.url + """
```

---

## 📊 8. Kết luận và khuyến nghị

### Đánh giá tổng quan:

"""

        if self.results['is_vulnerable']:
            report += f"""🔴 **Website CÓ LỖ HỔNG CSRF**

**Điểm bảo vệ:** {self.results['protection_score']}/100
**Mức độ rủi ro:** {self.results['risk_level']}
**CVSS Score:** {self.results['cvss_score']}

**Vấn đề phát hiện:**
"""
            for issue in self.results.get('issues', []):
                report += f"- ❌ {issue}\n"

            report += """
**Tác động:**
- Attacker có thể thực hiện hành động trái phép thay mặt user
- Chuyển tiền, thay đổi thông tin, xóa dữ liệu
- Vi phạm OWASP Top 10
- Fail security compliance (PCI-DSS, SOC 2)

**Hành động khuyến nghị:**
1. 🔴 **KHẨN CẤP** - Implement CSRF token cho tất cả POST forms
2. 🔴 **QUAN TRỌNG** - Thêm SameSite attribute cho cookies
3. 🧪 **TEST KỸ** - Verify không ảnh hưởng user experience
4. ✅ **VERIFY** - Scan lại và test thực tế
5. 📝 **MONITOR** - Setup alerts cho CSRF attempts
"""
        else:
            report += f"""✅ **Website ĐÃ ĐƯỢC BẢO VỆ TỐT**

**Điểm bảo vệ:** {self.results['protection_score']}/100
**Mức độ rủi ro:** {self.results['risk_level']}

**Bảo vệ hiện tại:**
"""
            for prot in self.results.get('protections', []):
                report += f"- ✅ {prot}\n"

            report += """
**Đánh giá:**
- Website có CSRF protection tốt
- Tuân thủ OWASP security best practices
- An toàn trước tấn công CSRF

**Hành động khuyến nghị:**
1. ✅ **MAINTAIN** - Duy trì implementation hiện tại
2. 🔄 **UPDATE** - Luôn áp dụng CSRF cho features mới
3. 📊 **MONITOR** - Regular security scan (quarterly)
4. 📝 **DOCUMENT** - Lưu báo cáo cho audit
"""

        report += """

---

## 🔗 References

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-352: Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)
- [MDN: SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
- [OWASP Testing Guide - CSRF](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery)

---

**Prepared by:** CSRF Security Scanner
**Scan Time:** """ + self.scan_time.strftime('%Y-%m-%d %H:%M:%S') + """
**Report Version:** 1.0
**Tool Version:** 1.0.0
"""

        return report

    def save_report(self, filename=None):
        """Lưu báo cáo ra file"""
        if filename is None:
            timestamp = self.scan_time.strftime('%Y%m%d_%H%M%S')
            filename = f"csrf_report_{self.domain}_{timestamp}.md"

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
    print("🛡️  CSRF (Cross-Site Request Forgery) SCANNER")
    print("="*70)
    print("Công cụ quét lỗi CSRF và tạo báo cáo chi tiết")
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
    scanner = CSRFSecurityScanner(url)

    # Chạy scan
    success = scanner.scan_csrf()

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

    forms = scanner.results.get('forms', {})
    print(f"\nForms:")
    print(f"  • Total: {forms.get('total', 0)}")
    print(f"  • POST forms: {forms.get('post_forms', 0)}")
    print(f"  • Có CSRF token: {forms.get('with_csrf', 0)}")
    print(f"  • Thiếu CSRF token: {forms.get('without_csrf', 0)}")

    print("\n" + "-"*70)
    if scanner.results['is_vulnerable']:
        print("🔴 PHÁT HIỆN LỖ HỔNG - Cần khắc phục!")
        print("\nVấn đề:")
        for issue in scanner.results.get('issues', []):
            print(f"  ❌ {issue}")
    else:
        print("✅ AN TOÀN - Đã được bảo vệ tốt!")
        if scanner.results.get('protections'):
            print("\nĐiểm mạnh:")
            for prot in scanner.results.get('protections', []):
                print(f"  ✅ {prot}")

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
1. Implement CSRF tokens cho tất cả POST/PUT/DELETE forms
2. Thêm SameSite attribute cho cookies
3. Test kỹ không ảnh hưởng functionality
4. Scan lại để verify fix
        """)
    else:
        print("""
1. Maintain CSRF protection cho features mới
2. Regular security scan
3. Tiếp tục quét các lỗi bảo mật khác
        """)

    print("="*70 + "\n")

if __name__ == "__main__":
    main()
