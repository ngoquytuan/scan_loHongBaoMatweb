
# 🧾 **BÁO CÁO TỔNG HỢP CÁC LỖI BẢO MẬT PHÁT HIỆN**

**Website:** *(điền domain của bạn)*
**Người thực hiện kiểm thử:** *(điền tên / đơn vị)*
**Ngày:** *(điền ngày báo cáo)*

---

## ⚠️ 1. Clickjacking Vulnerability — Missing or Misconfigured X-Frame-Options / CSP Frame-Ancestors

### Mô tả

Trang web không có hoặc cấu hình sai header bảo vệ chống clickjacking (`X-Frame-Options`, `Content-Security-Policy: frame-ancestors`).
Điều này cho phép attacker nhúng trang vào `<iframe>` trên site khác và lừa người dùng click vào các nút/đường dẫn bị che giấu.

### Rủi ro

* Người dùng có thể bị thao túng thực hiện hành động ngoài ý muốn.
* Dẫn đến tấn công **Clickjacking**, đặc biệt nguy hiểm với trang đăng nhập hoặc thanh toán.

### Mức độ: **High**

### Khuyến nghị khắc phục

**Thêm các header bảo vệ:**

```http
Content-Security-Policy: frame-ancestors 'none';
X-Frame-Options: DENY
```

hoặc, nếu cần cho phép embed nội bộ:

```http
Content-Security-Policy: frame-ancestors 'self';
X-Frame-Options: SAMEORIGIN
```

**Ví dụ (Nginx):**

```nginx
add_header Content-Security-Policy "frame-ancestors 'none';" always;
add_header X-Frame-Options "DENY" always;
```

**Kiểm tra lại:**
`curl -I https://your.site` → phải thấy 2 header trên.

---

## ⚠️ 2. HTTP OPTIONS Method Enabled

### Mô tả

Server phản hồi với HTTP method `OPTIONS`, cho phép hiển thị danh sách các method hỗ trợ (`Allow: GET, POST, OPTIONS, PUT, DELETE, TRACE...`).
Dù `OPTIONS` là hợp lệ, nhưng nếu không cần thiết (đặc biệt cho website tĩnh), nên tắt để tránh rò rỉ thông tin.

### Rủi ro

* Tiết lộ thông tin nội bộ (phương thức hỗ trợ, debug endpoints).
* Có thể bị lợi dụng trong tấn công enumeration hoặc XST (Cross-Site Tracing).

### Mức độ: **Medium**

### Khuyến nghị khắc phục

**Trường hợp không cần CORS (site tĩnh):**

```nginx
if ($request_method = OPTIONS) {
    return 405;
}
```

**Trường hợp có API cần CORS:**
Giữ lại OPTIONS nhưng chỉ cho phép domain hợp lệ:

```nginx
if ($request_method = OPTIONS) {
    add_header Access-Control-Allow-Origin "https://yourdomain.com";
    add_header Access-Control-Allow-Methods "GET, POST, OPTIONS";
    add_header Access-Control-Allow-Headers "Authorization, Content-Type";
    return 204;
}
```

**Kiểm tra lại:**
`curl -i -X OPTIONS https://your.site` → không được liệt kê các method nguy hiểm (`PUT`, `DELETE`, `TRACE`).

---

## ⚠️ 3. Content Security Policy (CSP) Not Implemented

### Mô tả

Trang web không triển khai **Content-Security-Policy (CSP)** header.
CSP giúp trình duyệt chỉ tải nội dung (script, style, image, font...) từ nguồn được xác định — ngăn chặn XSS và code injection.

### Rủi ro

* Dễ bị tấn công **Cross-Site Scripting (XSS)**, **malicious script injection**.
* Nội dung có thể bị thay đổi hoặc chèn script độc hại từ CDN bên ngoài.

### Mức độ: **High**

### Khuyến nghị khắc phục

**Cấu hình CSP cơ bản:**

```http
Content-Security-Policy: default-src 'self'; frame-ancestors 'none';
```

**Nếu có dùng CDN hoặc Google Fonts:**

```http
Content-Security-Policy: 
  default-src 'self';
  script-src 'self' https://cdn.jsdelivr.net;
  style-src 'self' https://fonts.googleapis.com;
  font-src 'self' https://fonts.gstatic.com;
  img-src 'self' data:;
  frame-ancestors 'none';
```

**Kiểm tra:**
[https://csp-evaluator.withgoogle.com/](https://csp-evaluator.withgoogle.com/)
và [https://securityheaders.com/](https://securityheaders.com/)

---

## ⚠️ 4. Subresource Integrity (SRI) Not Implemented

### Mô tả

Các tệp JS/CSS tải từ CDN hoặc nguồn bên ngoài không có thuộc tính `integrity`.
Khi CDN bị tấn công, hacker có thể thay thế file bằng mã độc mà người dùng vẫn tải bình thường.

### Rủi ro

* Mã độc có thể được thực thi trên trình duyệt người dùng.
* Mất toàn bộ niềm tin về integrity của web frontend.

### Mức độ: **Medium**

### Khuyến nghị khắc phục

**Thêm thuộc tính `integrity` và `crossorigin` cho mọi JS/CSS từ CDN.**

**Ví dụ đúng:**

```html
<link rel="stylesheet"
      href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
      integrity="sha384-ENjdO4Dr2bkBIFxQpeoDp1zp5lQqkP1N2jD9vuM0u+Xzr49jvOIQa5ePQ8dNQy7M"
      crossorigin="anonymous">

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-kenU1KFdBIe4zVF0s0G1M5b4hcpxyD9F7jL+FZp6Y5Jz+L9ZZ0T+ZjvYzu+K6tbt"
        crossorigin="anonymous"></script>
```

**Tạo hash:**

* Dùng [https://www.srihash.org/](https://www.srihash.org/)
* Hoặc:

  ```bash
  curl https://cdn.jsdelivr.net/... | openssl dgst -sha384 -binary | openssl base64 -A
  ```

**Kết hợp CSP:**

```http
Content-Security-Policy: require-sri-for script style;
```

---

## 📋 **Tổng hợp mức độ và hướng xử lý**

| # | Lỗi bảo mật                                          | Mức độ | Trạng thái        | Hành động khuyến nghị                   |
| - | ---------------------------------------------------- | ------ | ----------------- | --------------------------------------- |
| 1 | Clickjacking (X-Frame-Options / CSP Frame-Ancestors) | High   | ⚠️ Chưa khắc phục | Thêm header CSP + X-Frame-Options       |
| 2 | OPTIONS Method Enabled                               | Medium | ⚠️ Chưa khắc phục | Giới hạn hoặc vô hiệu hóa OPTIONS       |
| 3 | CSP Not Implemented                                  | High   | ⚠️ Chưa khắc phục | Thêm Content-Security-Policy đầy đủ     |
| 4 | SRI Not Implemented                                  | Medium | ⚠️ Chưa khắc phục | Thêm thuộc tính integrity + crossorigin |

---

## ✅ **Kết luận**

Việc khắc phục 4 lỗi trên sẽ giúp:

* Tăng **điểm bảo mật** trên các công cụ như Mozilla Observatory, SecurityHeaders.com.
* Giảm nguy cơ bị khai thác XSS, clickjacking, code injection.
* Đáp ứng yêu cầu bảo mật trong **OWASP Top 10 (A05, A06, A07)**.

