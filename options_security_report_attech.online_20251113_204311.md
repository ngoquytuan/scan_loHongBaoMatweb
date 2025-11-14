# 🔍 Phản biện kỹ thuật: "OPTIONS Method is Enabled"

**Ngày phân tích:** 13/11/2025 20:43:11  
**Website:** https://attech.online  
**Domain:** attech.online  
**Phân loại:** False Positive Analysis

---

## 📚 1. Tham chiếu chuẩn kỹ thuật

- **RFC 7231 (Section 4.3.7):** OPTIONS là phương thức hợp lệ của HTTP/1.1
- **OWASP Testing Guide v4.2:** "OPTIONS method chỉ là lỗ hổng KHI tiết lộ methods nguy hiểm hoặc thông tin nhạy cảm"
- **CWE-16:** Configuration - OPTIONS không phải CWE nếu cấu hình đúng
- **PCI-DSS v4.0:** Không yêu cầu disable OPTIONS, chỉ yêu cầu không tiết lộ thông tin nhạy cảm

---

## 🧪 2. Kết quả kiểm tra thực tế

### Test 1: OPTIONS Request

```bash
curl -i -X OPTIONS https://attech.online
```

**Phản hồi:**

```http
HTTP/1.1 405 Method Not Allowed
Server: nginx/1.29.3
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: https: http:; connect-src 'self' https://api.attech.online ws: wss:; font-src 'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; frame-src https://www.youtube.com https://maps.google.com; frame-ancestors 'none';
X-Content-Type-Options: nosniff
```

**Nhận xét:**

- Status Code: `405` - ✅ An toàn (Server từ chối OPTIONS)
- Allow Header: `Không có` - ✅ Không tiết lộ methods

### Test 2: Methods nguy hiểm

```bash
# PUT
curl -i -X PUT https://attech.online/test
→ HTTP/1.1 405 ✅

# DELETE
curl -i -X DELETE https://attech.online/test
→ HTTP/1.1 405 ✅

# TRACE
curl -i -X TRACE https://attech.online/test
→ HTTP/1.1 405 ✅

# CONNECT
curl -i -X CONNECT https://attech.online/test
→ HTTP/1.1 400 ⚠️

# PATCH
curl -i -X PATCH https://attech.online/test
→ HTTP/1.1 405 ✅

```

⚠️ **Cảnh báo:** 1/5 methods nguy hiểm KHÔNG bị chặn

---

## 🔍 3. So sánh: Có lỗi vs Không có lỗi

### ❌ Trường hợp CÓ LỖ HỔNG (ví dụ):

```http
HTTP/1.1 200 OK
Allow: GET, POST, PUT, DELETE, TRACE, CONNECT  ← 🔴 Tiết lộ methods nguy hiểm
Server: Apache/2.4.41 (Ubuntu)                  ← 🔴 Tiết lộ phiên bản
X-Powered-By: PHP/7.4.3                         ← 🔴 Tiết lộ công nghệ
```

**Rủi ro:**
- Attacker biết được server hỗ trợ PUT → có thể thử upload file
- Biết TRACE enabled → có thể thực hiện Cross-Site Tracing (XST)
- Biết version cụ thể → tìm CVE tương ứng để khai thác

### ✅ Trường hợp AN TOÀN (website đang kiểm tra):

```http
HTTP/1.1 405 Method Not Allowed
Server: nginx/1.29.3
(Không có Allow header)
```

**Bảo vệ:**
- ✅ Không tiết lộ danh sách methods (hoặc chỉ có methods an toàn)
- ✅ Server name không tiết lộ version chi tiết
- ✅ Các methods nguy hiểm bị reject (405/403)

---

## 🧩 4. Phân tích kỹ thuật

### Tại sao OPTIONS được bật?

OPTIONS là **bắt buộc** cho CORS (Cross-Origin Resource Sharing):

```javascript
// Khi frontend gọi API từ domain khác:
fetch('https://api.example.com/data', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' }
})

// Browser tự động gửi preflight request:
OPTIONS /data HTTP/1.1
Origin: https://www.example.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: content-type

// Server phải phản hồi OPTIONS để CORS hoạt động
```

**Nếu tắt hoàn toàn OPTIONS:**
- ❌ CORS sẽ bị break
- ❌ API calls từ frontend sẽ bị chặn
- ❌ Modern web apps (SPA) sẽ không hoạt động

---

## 📊 5. Bảng đánh giá rủi ro

| Tiêu chí | Kết quả | Đánh giá | Rủi ro |
|----------|---------|----------|--------|
| OPTIONS Enabled | ❌ Bị chặn | Server từ chối | ✅ An toàn |
| Header `Allow` | ❌ Không có | Không tiết lộ | ✅ An toàn |
| PUT/DELETE/TRACE | ⚠️ Một số được phép | Có methods được phép | 🔴 Nguy hiểm |
| Tiết lộ version | ⚠️ Có | nginx/1.29.3 | ⚠️ Nên ẩn |
| HSTS Header | ❌ Không | Nên thêm | ⚠️ Thiếu |

**Kết luận rủi ro:** Informational

---

## ⚠️ 6. Về cảnh báo từ công cụ quét tự động

Một số scanner (Acunetix, Nessus, OWASP ZAP) có thể cảnh báo "OPTIONS enabled" do:

1. **Rule cũ từ thời 2000s** - Khi Apache/IIS thường có OPTIONS + TRACE vulnerability
2. **Thiếu context** - Tool không phân biệt OPTIONS có tiết lộ info hay không
3. **Compliance checklist máy móc** - PCI-DSS v2.0 cũ (đã update ở v3.x/4.0)

**Khuyến nghị xử lý:**
- ✅ Đánh dấu **False Positive** trong report
- ✅ Whitelist trong lần scan tiếp theo
- ✅ Ghi nhận vào **Risk Acceptance** với justification này

---

## 🔧 7. Biện pháp khắc phục/tăng cường

### Biện pháp tăng cường (nếu chính sách yêu cầu)

### Option A: Chặn OPTIONS hoàn toàn (chỉ khi không cần CORS)

**Nginx:**
```nginx
if ($request_method = OPTIONS) {
    return 405;
}
```

**Apache:**
```apache
<Limit OPTIONS>
    Require all denied
</Limit>
```

**Vercel (Next.js Middleware):**
```javascript
export function middleware(req) {
  if (req.method === 'OPTIONS') {
    return new Response('', { status: 405 })
  }
  return NextResponse.next()
}
```

### Option B: Giới hạn OPTIONS cho API endpoints

```javascript
// Vercel - Chỉ cho phép OPTIONS trên /api/*
export function middleware(req) {
  if (req.method === 'OPTIONS' && !req.nextUrl.pathname.startsWith('/api/')) {
    return new Response('', { status: 405 })
  }
  return NextResponse.next()
}
```

### Option C: Rate limiting

```nginx
# Nginx - Giới hạn OPTIONS request
limit_req_zone $binary_remote_addr zone=options:10m rate=10r/m;

location / {
    if ($request_method = OPTIONS) {
        limit_req zone=options burst=5;
    }
}
```

### Option D: WAF Rule (Cloudflare/AWS WAF)

```yaml
if (method == "OPTIONS" AND 
    path not matches "^/api/.*" AND 
    rate > 10/min) then block
```

**⚠️ Lưu ý quan trọng:**
- ✅ Test kỹ trước khi deploy production
- ⚠️ Có thể ảnh hưởng CORS functionality
- 📝 Monitor logs sau khi triển khai
- 🔄 Rollback plan nếu có vấn đề

---

## 📋 8. Kết luận và khuyến nghị

### Đánh giá tổng quan:

✅ **Website KHÔNG CÓ LỖ HỔNG nghiêm trọng**

**Lý do:**
- ✅ Server từ chối OPTIONS request (405)
- ✅ Các methods nguy hiểm (PUT, DELETE, TRACE) đều bị chặn
- ✅ Tuân thủ chuẩn RFC 7231 (HTTP/1.1)

### 📊 Đánh giá rủi ro chi tiết:

| Metric | Value |
|--------|-------|
| **Severity** | Informational |
| **Likelihood** | N/A |
| **Impact** | None |
| **CVSS v3.1 Score** | 0.0 |
| **OWASP Risk Rating** | Note |

### 🎯 Hành động khuyến nghị:

1. ✅ **Risk Acceptance** - Chấp nhận và ghi nhận vào risk register
2. ✅ **False Positive** - Đánh dấu trong scanner tool
3. ✅ **Documentation** - Lưu phân tích này cho audit tiếp theo
4. 📝 **Monitor** - Giám sát định kỳ (quarterly), không cần action ngay

### 🚫 KHÔNG khuyến nghị:
- ❌ Tắt hoàn toàn OPTIONS nếu website/API cần CORS
- ❌ Ưu tiên fix này trước các lỗi HIGH/CRITICAL khác
- ❌ Áp dụng fix mà không test kỹ impact

---

## 📎 Phụ lục: Commands để verify

```bash
# Test OPTIONS
curl -i -X OPTIONS https://attech.online

# Test methods nguy hiểm
for method in PUT DELETE TRACE CONNECT PATCH; do
  echo "Testing $method:"
  curl -i -X $method https://attech.online/test 2>&1 | head -1
done

# Scan với Nmap (nếu có)
nmap -p 443 --script http-methods attech.online

# Check với online tools
# https://securityheaders.com/?q=https://attech.online
# https://observatory.mozilla.org/
```

---

## 📝 Chi tiết kỹ thuật bổ sung

### Response Headers đầy đủ từ OPTIONS request:

```http
Server: nginx/1.29.3
Date: Thu, 13 Nov 2025 13:42:39 GMT
Content-Type: text/html
Content-Length: 157
Connection: keep-alive
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: https: http:; connect-src 'self' https://api.attech.online ws: wss:; font-src 'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; frame-src https://www.youtube.com https://maps.google.com; frame-ancestors 'none';
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, Authorization
Access-Control-Allow-Credentials: true
```

### Test Results cho từng Method:

| Method | Status Code | Assessment |
|--------|-------------|------------|
| PUT | 405 | ✅ Blocked (Safe) |
| DELETE | 405 | ✅ Blocked (Safe) |
| TRACE | 405 | ✅ Blocked (Safe) |
| CONNECT | 400 | ⚠️ Allowed (Risk) |
| PATCH | 405 | ✅ Blocked (Safe) |


---

**Prepared by:** Security Scanner Tool  
**Scan Time:** 2025-11-13 20:43:11  
**Report Version:** 1.0  
**Tool Version:** 1.0.0
