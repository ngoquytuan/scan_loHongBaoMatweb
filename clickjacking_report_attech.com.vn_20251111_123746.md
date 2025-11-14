# 🔒 Phân biệt kỹ thuật: "Clickjacking Vulnerability"

**Ngày phân tích:** 11/11/2025 12:37:46  
**Website:** https://attech.com.vn  
**Domain:** attech.com.vn  
**Phân loại:** 🔴 Vulnerability Detected

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
  #target-iframe {
    position: absolute;
    opacity: 0.01; /* Gần như vô hình */
    z-index: 1;
  }
  #fake-button {
    position: absolute;
    z-index: 0;
    /* Đặt chính xác dưới nút "Delete Account" của iframe */
  }
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
curl -I https://attech.com.vn
```

**Phản hồi:**

```http
HTTP/1.1 200 OK
Server: Apache/2
X-Frame-Options: SAMEORIGIN
Content-Security-Policy: ❌ KHÔNG CÓ
```

**Phân tích chi tiết:**

✅ **X-Frame-Options:** `SAMEORIGIN`
   - Bảo vệ tốt: Chỉ cho phép nhúng từ cùng domain

❌ **CSP frame-ancestors:** KHÔNG CÓ
   - Rủi ro: Không có Content-Security-Policy header

### Test 2: Khả năng nhúng vào iframe

✅ **KẾT QUẢ:** Website ĐƯỢC BẢO VỆ khỏi việc nhúng iframe

**Lý do:** X-Frame-Options: SAMEORIGIN chỉ cho phép cùng domain

---

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

### 🔴 Trường hợp HIỆN TẠI (website đang kiểm tra):

```http
HTTP/1.1 200 OK
Server: Apache/2
X-Frame-Options: SAMEORIGIN
```

**Vấn đề:**
- 🔴 Thiếu hoặc cấu hình sai header bảo vệ
- 🔴 Website có thể bị nhúng vào iframe
- 🔴 Người dùng dễ bị lừa thực hiện hành động ngoài ý muốn

---

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
| X-Frame-Options | ✅ SAMEORIGIN | Bảo vệ tốt | 40/50 |
| CSP frame-ancestors | ❌ KHÔNG CÓ | Thiếu bảo vệ | 0/50 |

**Tổng điểm bảo vệ:** 40/100

🔴 **Đánh giá:** BẢO VỆ YẾU - Dễ bị tấn công

### Vấn đề phát hiện:

- ❌ Thiếu hoàn toàn Content-Security-Policy

### Điểm mạnh:

- ✅ X-Frame-Options: SAMEORIGIN (tốt)


---

## 🔧 6. Biện pháp khắc phục

### 🔴 CẦN KHẮC PHỤC NGAY

### Option A: Thêm X-Frame-Options (Khuyến nghị cho tất cả trình duyệt)

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
curl -I https://attech.com.vn | grep -i "x-frame-options"
# Kết quả mong đợi: X-Frame-Options: DENY

# Kiểm tra CSP
curl -I https://attech.com.vn | grep -i "content-security-policy"
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
    <iframe src="https://attech.com.vn" width="800" height="600"></iframe>
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
python3 scanClickjacking.py https://attech.com.vn

# Hoặc dùng online tools
# https://securityheaders.com/?q=https://attech.com.vn
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

🔴 **Website CÓ LỖ HỔNG CLICKJACKING**

**Điểm bảo vệ:** 40/100
**Mức độ rủi ro:** Medium
**CVSS Score:** 4.3

**Vấn đề phát hiện:**
- ❌ Thiếu hoàn toàn Content-Security-Policy

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

### 🎯 Cải thiện thêm (optional):

- Thêm cả X-Frame-Options và CSP frame-ancestors (defense in depth)
- Implement CSP đầy đủ (không chỉ frame-ancestors)
- Thêm HSTS header nếu chưa có
- Regular security scan (monthly/quarterly)

---

## 🔍 Phụ lục: Chi tiết kỹ thuật

### Response Headers đầy đủ:

```http
Date: Tue, 11 Nov 2025 05:36:58 GMT
Server: Apache/2
X-Powered-By: PHP/5.6.40
Vary: Accept-Encoding,Cookie,User-Agent
X-Frame-Options: SAMEORIGIN
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
X-Pingback: https://attech.com.vn/xmlrpc.php
Link: <https://attech.com.vn/>; rel=shortlink
Content-Encoding: gzip
Set-Cookie: PHPSESSID=bbe52mo1g41sbu8hiprk416qf3; path=/
Keep-Alive: timeout=2, max=100
Connection: Keep-Alive
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8
```

### Browser Compatibility

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
**Scan Time:** 2025-11-11 12:37:46  
**Report Version:** 1.0  
**Tool Version:** 1.0.0
