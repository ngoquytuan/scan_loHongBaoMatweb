#!/usr/bin/env python3
"""
.\scanClickjacking.py
Clickjacking Vulnerability Scanner & Report Generator
Quét lỗi Clickjacking (thiếu hoặc cấu hình sai X-Frame-Options / CSP frame-ancestors)
và tạo báo cáo chi tiết
"""

import requests
import sys
from datetime import datetime
from urllib.parse import urlparse

class ClickjackingScanner:
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
    
    def scan_clickjacking(self):
        """Quét lỗ hổng Clickjacking"""
        print(f"\n{'='*70}")
        print(f"🔍 ĐANG QUÉT: {self.url}")
        print(f"{'='*70}\n")
        
        try:
            # Test GET request để lấy headers
            print("📤 Test 1: Gửi GET request để kiểm tra headers...")
            response = requests.get(self.url, timeout=10, allow_redirects=True)
            
            self.results['status_code'] = response.status_code
            self.results['headers'] = dict(response.headers)
            
            # Kiểm tra X-Frame-Options
            x_frame_options = response.headers.get('X-Frame-Options', None)
            self.results['x_frame_options'] = x_frame_options
            
            print(f"   ✓ Status Code: {response.status_code}")
            print(f"   ✓ X-Frame-Options: {x_frame_options or '❌ KHÔNG CÓ'}")
            
            # Kiểm tra CSP frame-ancestors
            print("\n📤 Test 2: Kiểm tra Content-Security-Policy...")
            csp = response.headers.get('Content-Security-Policy', None)
            self.results['csp'] = csp
            
            frame_ancestors = None
            if csp:
                # Tìm frame-ancestors trong CSP
                csp_lower = csp.lower()
                if 'frame-ancestors' in csp_lower:
                    # Trích xuất giá trị frame-ancestors
                    parts = csp.split(';')
                    for part in parts:
                        if 'frame-ancestors' in part.lower():
                            frame_ancestors = part.strip()
                            break
            
            self.results['frame_ancestors'] = frame_ancestors
            print(f"   ✓ CSP Header: {csp[:100] + '...' if csp and len(csp) > 100 else csp or '❌ KHÔNG CÓ'}")
            print(f"   ✓ Frame-Ancestors: {frame_ancestors or '❌ KHÔNG CÓ'}")
            
            # Test thực tế với iframe
            print("\n📤 Test 3: Kiểm tra khả năng embed trong iframe...")
            self.results['iframe_test'] = self.test_iframe_embedding()
            
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
    
    def test_iframe_embedding(self):
        """Test khả năng embed trong iframe"""
        print("   → Kiểm tra xem website có thể bị nhúng vào iframe không...")
        
        # Đánh giá dựa trên headers
        x_frame = self.results.get('x_frame_options', '').upper() if self.results.get('x_frame_options') else ''
        frame_anc = self.results.get('frame_ancestors', '').lower() if self.results.get('frame_ancestors') else ''
        
        can_embed = True
        reason = []
        
        # Kiểm tra X-Frame-Options
        if x_frame:
            if 'DENY' in x_frame:
                can_embed = False
                reason.append("X-Frame-Options: DENY chặn hoàn toàn")
            elif 'SAMEORIGIN' in x_frame:
                can_embed = False
                reason.append("X-Frame-Options: SAMEORIGIN chỉ cho phép cùng domain")
        
        # Kiểm tra CSP frame-ancestors
        if frame_anc:
            if "'none'" in frame_anc:
                can_embed = False
                reason.append("CSP frame-ancestors 'none' chặn hoàn toàn")
            elif "'self'" in frame_anc and "'none'" not in frame_anc:
                can_embed = False
                reason.append("CSP frame-ancestors 'self' chỉ cho phép cùng domain")
        
        if can_embed:
            print("   ⚠️ CÓ THỂ BỊ EMBED - Dễ bị tấn công Clickjacking!")
            return {
                'can_embed': True,
                'risk': 'HIGH',
                'reason': 'Không có header bảo vệ chống clickjacking'
            }
        else:
            print(f"   ✅ ĐƯỢC BẢO VỆ - {reason[0]}")
            return {
                'can_embed': False,
                'risk': 'LOW',
                'reason': ', '.join(reason)
            }
    
    def analyze_risk(self):
        """Phân tích mức độ rủi ro"""
        x_frame = self.results.get('x_frame_options')
        frame_anc = self.results.get('frame_ancestors')
        iframe_test = self.results.get('iframe_test', {})
        
        # Xác định có lỗ hổng không
        self.results['is_vulnerable'] = False
        self.results['risk_level'] = 'Low'
        self.results['cvss_score'] = 0.0
        self.results['protection_score'] = 0
        
        # Tính điểm bảo vệ (0-100)
        score = 0
        issues = []
        protections = []
        
        # Kiểm tra X-Frame-Options
        if x_frame:
            x_frame_upper = x_frame.upper()
            if 'DENY' in x_frame_upper:
                score += 50
                protections.append("X-Frame-Options: DENY (tốt nhất)")
            elif 'SAMEORIGIN' in x_frame_upper:
                score += 40
                protections.append("X-Frame-Options: SAMEORIGIN (tốt)")
            else:
                score += 10
                issues.append("X-Frame-Options có giá trị không chuẩn")
        else:
            issues.append("Thiếu header X-Frame-Options")
        
        # Kiểm tra CSP frame-ancestors
        if frame_anc:
            if "'none'" in frame_anc.lower():
                score += 50
                protections.append("CSP frame-ancestors 'none' (tốt nhất)")
            elif "'self'" in frame_anc.lower():
                score += 40
                protections.append("CSP frame-ancestors 'self' (tốt)")
            else:
                score += 20
                issues.append("CSP frame-ancestors không tối ưu")
        else:
            if not self.results.get('csp'):
                issues.append("Thiếu hoàn toàn Content-Security-Policy")
            else:
                issues.append("CSP không có frame-ancestors directive")
        
        self.results['protection_score'] = min(score, 100)
        self.results['issues'] = issues
        self.results['protections'] = protections
        
        # Đánh giá tổng quan
        if score < 40:
            self.results['is_vulnerable'] = True
            self.results['risk_level'] = 'High'
            self.results['cvss_score'] = 5.3
            self.results['assessment'] = '🔴 DỄ BỊ TẤN CÔNG CLICKJACKING - Thiếu header bảo vệ'
        elif score < 70:
            self.results['is_vulnerable'] = True
            self.results['risk_level'] = 'Medium'
            self.results['cvss_score'] = 4.3
            self.results['assessment'] = '⚠️ BẢO VỆ YẾU - Cần tăng cường thêm'
        else:
            self.results['is_vulnerable'] = False
            self.results['risk_level'] = 'Low'
            self.results['cvss_score'] = 0.0
            self.results['assessment'] = '✅ ĐƯỢC BẢO VỆ TỐT - An toàn trước Clickjacking'
    
    def generate_markdown_report(self):
        """Tạo báo cáo Markdown chi tiết"""
        
        report = f"""# 🔒 Phân biệt kỹ thuật: "Clickjacking Vulnerability"

**Ngày phân tích:** {self.scan_time.strftime('%d/%m/%Y %H:%M:%S')}  
**Website:** {self.url}  
**Domain:** {self.domain}  
**Phân loại:** {"🔴 Vulnerability Detected" if self.results['is_vulnerable'] else "✅ Protected"}

---

## 🚀 Quick Test Commands (Copy & Paste)

### Test nhanh bằng curl (30 giây):

```bash
# Test tất cả headers bảo mật
curl -I {self.url} | grep -i "x-frame\|content-security"

# Hoặc test từng cái:
curl -I {self.url} | grep -i "x-frame-options"
curl -I {self.url} | grep -i "content-security-policy"
```

**Kết quả tốt (được bảo vệ):**
```
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'
```

**Kết quả xấu (có lỗ hổng):**
```
(không có output - thiếu headers)
```

### Verify sau khi fix:

```bash
# 1. Kiểm tra headers
curl -I {self.url} | grep -i "x-frame-options"

# 2. Test đầy đủ
curl -v {self.url} 2>&1 | grep -i "frame"

# 3. Scan lại bằng tool
python3 scanClickjacking.py {self.url}
```

---

## 📚 1. Tham chiếu chuẩn kỹ thuật

- **OWASP Top 10 2021:** A05:2021 – Security Misconfiguration
- **CWE-1021:** Improper Restriction of Rendered UI Layers or Frames
- **CAPEC-103:** Clickjacking Attack Pattern
- **RFC 7034:** HTTP Header Field X-Frame-Options
- **CSP Level 3:** frame-ancestors directive

### Clickjacking là gì?

**Clickjacking** (UI Redressing) là kỹ thuật tấn công lừa người dùng click vào một phần tử web bị ẩn/che giấu bằng cách:

1. Attacker tạo một trang web độc hại
2. Nhúng trang nạn nhân vào `<iframe>` trong suốt
3. Đặt các phần tử lừa đảo phía trên iframe
4. Người dùng tưởng click vào nút hợp lệ nhưng thực tế click vào iframe ẩn

**Ví dụ tấn công:**

```html
<!-- Trang của attacker: evil.com -->
<html>
<head>
<style>
  #target-iframe {{
    position: absolute;
    opacity: 0.01; /* Gần như vô hình */
    z-index: 1;
  }}
  #fake-button {{
    position: absolute;
    z-index: 0;
    /* Đặt chính xác dưới nút "Delete Account" của iframe */
  }}
</style>
</head>
<body>
  <button id="fake-button">🎁 Nhấn để nhận quà</button>
  <iframe id="target-iframe" src="https://victim.com/settings"></iframe>
</body>
</html>
```

**Kết quả:** Người dùng tưởng nhấn "Nhận quà" nhưng thực tế xóa tài khoản!

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
        important_headers = ['Server', 'X-Frame-Options', 'Content-Security-Policy', 
                            'Strict-Transport-Security', 'X-Content-Type-Options']
        
        for header in important_headers:
            if header in self.results['headers']:
                value = self.results['headers'][header]
                if len(value) > 100:
                    value = value[:97] + "..."
                report += f"{header}: {value}\n"
            else:
                if header in ['X-Frame-Options', 'Content-Security-Policy']:
                    report += f"{header}: ❌ KHÔNG CÓ\n"
        
        report += "```\n\n"
        
        # Phân tích chi tiết
        report += "**Phân tích chi tiết:**\n\n"
        
        # Bảng so sánh Expected vs Actual
        report += "### 🎯 So sánh: Mong đợi vs Thực tế\n\n"
        report += "| Header | Mong đợi (Secure) | Thực tế | Status |\n"
        report += "|--------|-------------------|---------|--------|\n"
        
        x_frame_actual = self.results['x_frame_options'] if self.results['x_frame_options'] else '❌ KHÔNG CÓ'
        x_frame_status = '✅' if self.results['x_frame_options'] else '❌'
        report += f"| X-Frame-Options | `DENY` hoặc `SAMEORIGIN` | `{x_frame_actual}` | {x_frame_status} |\n"
        
        frame_anc_actual = self.results['frame_ancestors'] if self.results['frame_ancestors'] else '❌ KHÔNG CÓ'
        frame_anc_status = '✅' if self.results['frame_ancestors'] else '❌'
        report += f"| CSP frame-ancestors | `frame-ancestors 'none'` | `{frame_anc_actual}` | {frame_anc_status} |\n"
        
        hsts_actual = self.results['headers'].get('Strict-Transport-Security', '❌ Không có')
        hsts_status = '✅' if 'Strict-Transport-Security' in self.results['headers'] else '⚠️'
        report += f"| HSTS | `max-age=31536000` | `{hsts_actual}` | {hsts_status} |\n"
        
        report += f"\n**Quick test command để verify:**\n\n"
        report += "```bash\n"
        report += f"curl -I {self.url} | grep -i \"x-frame\\|content-security\\|strict-transport\"\n"
        report += "```\n\n"
        report += "**Chi tiết từng header:**\n\n"
        
        # X-Frame-Options
        if self.results['x_frame_options']:
            report += f"✅ **X-Frame-Options:** `{self.results['x_frame_options']}`\n"
            if 'DENY' in self.results['x_frame_options'].upper():
                report += "   - Bảo vệ tối đa: Chặn hoàn toàn việc nhúng vào iframe\n"
            elif 'SAMEORIGIN' in self.results['x_frame_options'].upper():
                report += "   - Bảo vệ tốt: Chỉ cho phép nhúng từ cùng domain\n"
        else:
            report += "❌ **X-Frame-Options:** KHÔNG CÓ\n"
            report += "   - Rủi ro: Website có thể bị nhúng vào iframe của attacker\n"
        
        report += "\n"
        
        # CSP frame-ancestors
        if self.results['frame_ancestors']:
            report += f"✅ **CSP frame-ancestors:** `{self.results['frame_ancestors']}`\n"
            if "'none'" in self.results['frame_ancestors'].lower():
                report += "   - Bảo vệ tối đa: Chặn hoàn toàn việc nhúng vào iframe\n"
            elif "'self'" in self.results['frame_ancestors'].lower():
                report += "   - Bảo vệ tốt: Chỉ cho phép nhúng từ cùng domain\n"
        else:
            report += "❌ **CSP frame-ancestors:** KHÔNG CÓ\n"
            if not self.results['csp']:
                report += "   - Rủi ro: Không có Content-Security-Policy header\n"
            else:
                report += "   - Rủi ro: CSP không có directive frame-ancestors\n"
        
        report += "\n### Test 2: Khả năng nhúng vào iframe\n\n"
        
        iframe_test = self.results.get('iframe_test', {})
        if iframe_test.get('can_embed'):
            report += "🔴 **KẾT QUẢ:** Website CÓ THỂ BỊ NHÚNG vào iframe\n\n"
            report += f"**Lý do:** {iframe_test.get('reason', 'Không có header bảo vệ')}\n\n"
            report += "**Demo tấn công:**\n\n"
            report += "```html\n"
            report += f"<!-- Trang attacker có thể nhúng {self.domain} -->\n"
            report += f'<iframe src="{self.url}" style="opacity:0.01"></iframe>\n'
            report += "```\n\n"
        else:
            report += "✅ **KẾT QUẢ:** Website ĐƯỢC BẢO VỆ khỏi việc nhúng iframe\n\n"
            report += f"**Lý do:** {iframe_test.get('reason', 'Có header bảo vệ')}\n\n"
        
        report += """---

## 📊 3. So sánh: Có lỗi vs Không có lỗi

### ❌ Trường hợp CÓ LỖ HỔNG (ví dụ):

```http
HTTP/1.1 200 OK
Server: nginx/1.18.0
Content-Type: text/html
(Không có X-Frame-Options)
(Không có Content-Security-Policy)
```

**Rủi ro thực tế:**

1. **Phishing tài khoản:**
   - Attacker nhúng trang đăng nhập vào iframe trong suốt
   - Người dùng nhập username/password tưởng là trang thật
   - Thông tin bị đánh cắp

2. **Thao túng hành động:**
   - Nhúng trang thanh toán/chuyển tiền
   - Lừa người dùng click "Xác nhận" bằng nút giả mạo
   - Tiền bị chuyển đi ngoài ý muốn

3. **Social engineering:**
   - Nhúng nút "Like" Facebook, "Follow" Twitter
   - Người dùng vô tình tương tác với nội dung độc hại

"""
        
        # Trường hợp hiện tại
        report += f"""### {"✅ Trường hợp AN TOÀN" if not self.results['is_vulnerable'] else "🔴 Trường hợp HIỆN TẠI"} (website đang kiểm tra):

```http
HTTP/1.1 {self.results['status_code']} {self._get_status_text(self.results['status_code'])}
Server: {self.results['headers'].get('Server', 'N/A')}
"""
        
        if self.results['x_frame_options']:
            report += f"X-Frame-Options: {self.results['x_frame_options']}\n"
        
        if self.results['frame_ancestors']:
            report += f"Content-Security-Policy: {self.results['frame_ancestors']}\n"
        
        if not self.results['x_frame_options'] and not self.results['frame_ancestors']:
            report += "(Không có header bảo vệ chống clickjacking)\n"
        
        report += "```\n\n"
        
        if not self.results['is_vulnerable']:
            report += """**Bảo vệ tốt:**
- ✅ Có header bảo vệ chống clickjacking
- ✅ Website không thể bị nhúng vào iframe của attacker
- ✅ Người dùng được bảo vệ khỏi tấn công UI redressing

"""
        else:
            report += """**Vấn đề:**
- 🔴 Thiếu hoặc cấu hình sai header bảo vệ
- 🔴 Website có thể bị nhúng vào iframe
- 🔴 Người dùng dễ bị lừa thực hiện hành động ngoài ý muốn

"""
        
        report += """---

## 🎯 4. Kịch bản tấn công thực tế

### Kịch bản 1: Đánh cắp like Facebook

```html
<!-- evil.com/free-iphone.html -->
<html>
<head>
<style>
  iframe { opacity: 0; position: absolute; }
  #fake-btn { font-size: 30px; color: red; }
</style>
</head>
<body>
  <h1>🎁 Click để nhận iPhone 15 miễn phí!</h1>
  <button id="fake-btn">NHẬN NGAY</button>
  <iframe src="https://facebook.com/BadPageWithLikeButton"></iframe>
</body>
</html>
```

**Kết quả:** Nạn nhân vô tình "Like" trang lừa đảo

### Kịch bản 2: Chuyển tiền banking

```html
<!-- evil.com/lottery.html -->
<html>
<style>
  #bank-iframe {
    position: absolute;
    width: 100%;
    height: 100%;
    opacity: 0.0001;
    z-index: 2;
  }
</style>
<body>
  <h1>🎰 Quay số trúng thưởng!</h1>
  <button style="font-size:50px">QUAY NGAY</button>
  <iframe id="bank-iframe" src="https://bank.com/transfer?to=attacker&amount=10000000"></iframe>
</body>
</html>
```

**Kết quả:** Nạn nhân tưởng quay số nhưng thực tế bấm "Xác nhận chuyển tiền"

---

## 📋 5. Bảng đánh giá bảo vệ

| Tiêu chí | Kết quả | Đánh giá | Điểm |
|----------|---------|----------|------|
"""
        
        # X-Frame-Options
        if self.results['x_frame_options']:
            x_frame_upper = self.results['x_frame_options'].upper()
            if 'DENY' in x_frame_upper:
                report += f"| X-Frame-Options | ✅ DENY | Bảo vệ tối đa | 50/50 |\n"
            elif 'SAMEORIGIN' in x_frame_upper:
                report += f"| X-Frame-Options | ✅ SAMEORIGIN | Bảo vệ tốt | 40/50 |\n"
            else:
                report += f"| X-Frame-Options | ⚠️ {self.results['x_frame_options']} | Không chuẩn | 10/50 |\n"
        else:
            report += f"| X-Frame-Options | ❌ KHÔNG CÓ | Thiếu bảo vệ | 0/50 |\n"
        
        # CSP frame-ancestors
        if self.results['frame_ancestors']:
            if "'none'" in self.results['frame_ancestors'].lower():
                report += f"| CSP frame-ancestors | ✅ 'none' | Bảo vệ tối đa | 50/50 |\n"
            elif "'self'" in self.results['frame_ancestors'].lower():
                report += f"| CSP frame-ancestors | ✅ 'self' | Bảo vệ tốt | 40/50 |\n"
            else:
                report += f"| CSP frame-ancestors | ⚠️ Có nhưng không tối ưu | Cần cải thiện | 20/50 |\n"
        else:
            report += f"| CSP frame-ancestors | ❌ KHÔNG CÓ | Thiếu bảo vệ | 0/50 |\n"
        
        # Tổng điểm
        score = self.results['protection_score']
        report += f"\n**Tổng điểm bảo vệ:** {score}/100\n\n"
        
        if score >= 80:
            report += "✅ **Đánh giá:** BẢO VỆ TỐT - An toàn trước clickjacking\n"
        elif score >= 50:
            report += "⚠️ **Đánh giá:** BẢO VỆ TRUNG BÌNH - Cần tăng cường\n"
        else:
            report += "🔴 **Đánh giá:** BẢO VỆ YẾU - Dễ bị tấn công\n"
        
        report += f"\n### Vấn đề phát hiện:\n\n"
        for issue in self.results.get('issues', []):
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
            report += "### ✅ Đã được bảo vệ tốt, nhưng có thể tăng cường thêm\n\n"
        
        report += """### Option A: Thêm X-Frame-Options (Khuyến nghị cho tất cả trình duyệt)

**Nginx:**
```nginx
# /etc/nginx/sites-available/your-site
server {
    ...
    add_header X-Frame-Options "DENY" always;
    # Hoặc nếu cần embed nội bộ:
    # add_header X-Frame-Options "SAMEORIGIN" always;
}
```

**Apache:**
```apache
# .htaccess hoặc httpd.conf
Header always set X-Frame-Options "DENY"
# Hoặc:
# Header always set X-Frame-Options "SAMEORIGIN"
```

**Node.js (Express):**
```javascript
// app.js
const helmet = require('helmet');
app.use(helmet.frameguard({ action: 'deny' }));
// Hoặc:
// app.use(helmet.frameguard({ action: 'sameorigin' }));
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
            key: 'X-Frame-Options',
            value: 'DENY',
          },
        ],
      },
    ]
  },
}
```

### Option B: Thêm CSP frame-ancestors (Chuẩn hiện đại, ưu tiên hơn)

**Nginx:**
```nginx
add_header Content-Security-Policy "frame-ancestors 'none';" always;
# Hoặc cho phép embed nội bộ:
# add_header Content-Security-Policy "frame-ancestors 'self';" always;
# Hoặc cho phép domain cụ thể:
# add_header Content-Security-Policy "frame-ancestors 'self' https://trusted-site.com;" always;
```

**Apache:**
```apache
Header always set Content-Security-Policy "frame-ancestors 'none';"
```

**Vercel (vercel.json):**
```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "Content-Security-Policy",
          "value": "frame-ancestors 'none';"
        },
        {
          "key": "X-Frame-Options",
          "value": "DENY"
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
  newHeaders.set('X-Frame-Options', 'DENY')
  newHeaders.set('Content-Security-Policy', "frame-ancestors 'none';")
  
  return new Response(response.body, {
    status: response.status,
    headers: newHeaders
  })
}
```

### Option C: Kết hợp cả hai (Khuyến nghị tốt nhất)

```nginx
# Nginx - Bảo vệ tối đa
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "frame-ancestors 'none'; default-src 'self';" always;
```

**⚠️ Lưu ý quan trọng:**

1. **DENY vs SAMEORIGIN:**
   - `DENY`: Chặn hoàn toàn, không ai có thể nhúng (an toàn nhất)
   - `SAMEORIGIN`: Chỉ cho phép cùng domain nhúng (nếu cần iframe nội bộ)

2. **Test kỹ trước khi deploy:**
   ```bash
   # Test sau khi cấu hình
   curl -I https://your-site.com | grep -i "frame"
   ```

3. **Kiểm tra không ảnh hưởng tính năng:**
   - Nếu website có embed video/map từ bên ngoài: vẫn OK
   - Nếu website cần được nhúng vào iframe partner: dùng SAMEORIGIN hoặc whitelist domain

---

## ✅ 7. Kiểm tra lại sau khi khắc phục

### Bước 1: Kiểm tra bằng curl

```bash
# Kiểm tra X-Frame-Options
curl -I """ + self.url + """ | grep -i "x-frame-options"
# Kết quả mong đợi: X-Frame-Options: DENY

# Kiểm tra CSP
curl -I """ + self.url + """ | grep -i "content-security-policy"
# Kết quả mong đợi: Content-Security-Policy: frame-ancestors 'none'
```

### Bước 2: Test thực tế với HTML

Tạo file `test-iframe.html`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking Test</title>
</head>
<body>
    <h1>Test Clickjacking Protection</h1>
    <iframe src=\"""" + self.url + """\" width="800" height="600"></iframe>
    <p>Nếu iframe trống hoặc hiển thị lỗi = ĐÃ ĐƯỢC BẢO VỆ ✅</p>
    <p>Nếu iframe hiển thị website bình thường = VẪN CÒN LỖI ❌</p>
</body>
</html>
```

Mở file trong browser và kiểm tra:
- ✅ Nếu iframe trống/lỗi → **Đã fix thành công**
- ❌ Nếu iframe hiển thị website → **Chưa fix hoặc fix sai**

### Bước 3: Scan lại bằng tool

```bash
# Chạy lại scanner này
python3 scanClickjacking.py """ + self.url + """

# Hoặc dùng online tools
# https://securityheaders.com/?q=""" + self.url + """
# https://observatory.mozilla.org/
```

### Bước 4: Kiểm tra bằng Browser DevTools

1. Mở website trong Chrome/Firefox
2. F12 → Console
3. Chạy lệnh:
```javascript
// Kiểm tra headers
fetch(window.location.href).then(r => {
  console.log('X-Frame-Options:', r.headers.get('x-frame-options'));
  console.log('CSP:', r.headers.get('content-security-policy'));
});
```

---

## 📊 8. Kết luận và khuyến nghị

### Đánh giá tổng quan:

"""
        
        if self.results['is_vulnerable']:
            report += f"""🔴 **Website CÓ LỖ HỔNG CLICKJACKING**

**Điểm bảo vệ:** {self.results['protection_score']}/100
**Mức độ rủi ro:** {self.results['risk_level']}
**CVSS Score:** {self.results['cvss_score']}

**Vấn đề phát hiện:**
"""
            for issue in self.results.get('issues', []):
                report += f"- ❌ {issue}\n"
            
            report += """
**Tác động:**
- Người dùng có thể bị lừa thực hiện hành động ngoài ý muốn
- Dễ bị tấn công phishing, social engineering
- Vi phạm OWASP Top 10 (A05:2021)
- Có thể fail audit bảo mật (PCI-DSS, ISO 27001)

**Hành động khuyến nghị:**
1. 🔴 **KHẨN CẤP** - Thêm header bảo vệ ngay (Option C - mục 6)
2. 🧪 **TEST KỸ** - Kiểm tra không ảnh hưởng tính năng
3. ✅ **VERIFY** - Scan lại bằng tool hoặc manual test
4. 📝 **DOCUMENT** - Ghi nhận vào change log
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
- Website không thể bị nhúng vào iframe của attacker
- Tuân thủ chuẩn bảo mật OWASP
- An toàn trước tấn công UI redressing

**Hành động khuyến nghị:**
1. ✅ **MAINTAIN** - Duy trì cấu hình hiện tại
2. 📊 **MONITOR** - Giám sát định kỳ (quarterly)
3. 📝 **DOCUMENT** - Lưu báo cáo này cho audit
"""
        
        if self.results['protection_score'] < 100:
            report += """
### 🎯 Cải thiện thêm (optional):

- Thêm cả X-Frame-Options và CSP frame-ancestors (defense in depth)
- Implement CSP đầy đủ (không chỉ frame-ancestors)
- Thêm HSTS header nếu chưa có
- Regular security scan (monthly/quarterly)
"""
        
        report += """
---

## 🧪 9. Manual Testing Guide

### Test 1: Basic curl check (10 giây)

```bash
curl -I {self.url} | grep -i "x-frame\|content-security"
```

**Giải thích:**
- `curl -I` : Chỉ lấy headers (không download content)
- `grep -i` : Tìm kiếm không phân biệt hoa/thường
- `x-frame\|content-security` : Tìm cả 2 headers

### Test 2: Verbose mode (xem chi tiết)

```bash
curl -v {self.url} 2>&1 | head -30
```

**Xem kỹ từng bước:**
1. TLS handshake
2. HTTP request headers
3. HTTP response headers ← Quan trọng nhất!

### Test 3: Lưu headers vào file

```bash
curl -I {self.url} > headers.txt
cat headers.txt | grep -i "frame\|security"
```

### Test 4: Test từ nhiều locations

```bash
# Test trực tiếp (bypass CDN)
curl -I --resolve {self.domain}:443:YOUR_SERVER_IP https://{self.domain}

# Test qua Cloudflare/CDN
curl -I {self.url}

# So sánh 2 kết quả
```

### Test 5: Browser DevTools (Manual)

1. Mở {self.url} trong Chrome/Firefox
2. F12 → Network tab
3. Reload trang
4. Click vào request đầu tiên
5. Xem tab "Headers" → "Response Headers"
6. Tìm: `X-Frame-Options` và `Content-Security-Policy`

### Test 6: Online Tools

```bash
# SecurityHeaders.com
https://securityheaders.com/?q={self.url}

# Mozilla Observatory
https://observatory.mozilla.org/analyze/{self.domain}

# Hardenize
https://www.hardenize.com/report/{self.domain}
```

### Test 7: Automated scan lại

```bash
# Scan lại sau khi fix
python3 scanClickjacking.py {self.url}

# Nmap (nếu có)
nmap --script http-security-headers -p 443 {self.domain}
```

---

## 🔍 Phụ lục: Chi tiết kỹ thuật

### Response Headers đầy đủ:

```http
"""
        
        for header, value in self.results['headers'].items():
            report += f"{header}: {value}\n"
        
        report += "```\n\n"
        
        report += """### Browser Compatibility

| Header | Chrome | Firefox | Safari | Edge | IE11 |
|--------|--------|---------|--------|------|------|
| X-Frame-Options | ✅ | ✅ | ✅ | ✅ | ✅ |
| CSP frame-ancestors | ✅ | ✅ | ✅ | ✅ | ❌ |

**Lưu ý:** IE11 không hỗ trợ CSP frame-ancestors, nên cần giữ X-Frame-Options

### References

- [OWASP Clickjacking Defense](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- [RFC 7034 - X-Frame-Options](https://tools.ietf.org/html/rfc7034)
- [CSP Level 3 Spec](https://www.w3.org/TR/CSP3/#directive-frame-ancestors)
- [MDN - X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)

---

**Prepared by:** Clickjacking Security Scanner  
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
            filename = f"clickjacking_report_{self.domain}_{timestamp}.md"
        
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
    print("🛡️  CLICKJACKING VULNERABILITY SCANNER")
    print("="*70)
    print("Công cụ quét lỗi Clickjacking và tạo báo cáo chi tiết")
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
    scanner = ClickjackingScanner(url)
    
    # Chạy scan
    success = scanner.scan_clickjacking()
    
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
        print("✅ AN TOÀN - Đã được bảo vệ tốt!")
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
2. Chọn Option phù hợp với hạ tầng của bạn
3. Test kỹ trước khi deploy production
4. Chạy lại tool này để verify đã fix thành công

📝 Khuyến nghị: Thêm cả X-Frame-Options và CSP frame-ancestors
        """)
    else:
        print("""
1. Lưu báo cáo này để tham khảo cho audit
2. Duy trì cấu hình bảo mật hiện tại
3. Giám sát định kỳ (quarterly security scan)
4. Tiếp tục quét các lỗi bảo mật khác
        """)
    
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
