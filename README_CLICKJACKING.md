# 🛡️ Bộ Công Cụ Quét Lỗi Clickjacking

Bộ công cụ hoàn chỉnh để kiểm tra, phát hiện và khắc phục lỗ hổng Clickjacking trên website.

## 📦 Nội dung

1. **scanClickjacking.py** - Script Python quét tự động và tạo báo cáo chi tiết
2. **test-clickjacking.html** - Tool test trực quan trên browser
3. **HUONGDAN_CLICKJACKING.md** - Hướng dẫn chi tiết cách sử dụng và khắc phục

## 🚀 Quick Start

### Cách 1: Sử dụng Python Script (Khuyến nghị cho báo cáo chi tiết)

```bash
# Cài đặt
pip install requests

# Chạy scan
python3 scanClickjacking.py https://your-website.com

# Hoặc nhập URL khi chạy
python3 scanClickjacking.py
```

**Output mẫu:**
```
======================================================================
🛡️  CLICKJACKING VULNERABILITY SCANNER
======================================================================

🔍 ĐANG QUÉT: https://example.com
...
📊 TÓM TẮT KẾT QUẢ
Website: https://example.com
Đánh giá: ✅ ĐƯỢC BẢO VỆ TỐT - An toàn trước Clickjacking
Mức độ rủi ro: Low
Điểm bảo vệ: 100/100
======================================================================
```

### Cách 2: Sử dụng HTML Test Tool (Test trực quan)

1. Mở file `test-clickjacking.html` trong browser
2. Nhập URL website cần test
3. Nhấn "Kiểm tra ngay"
4. Xem kết quả:
   - ✅ Iframe trống = Website được bảo vệ
   - ❌ Iframe hiển thị = Website có lỗ hổng

## 🔍 Clickjacking là gì?

**Clickjacking** (UI Redressing) là kỹ thuật tấn công lừa người dùng click vào các phần tử web bị ẩn bằng cách nhúng website nạn nhân vào `<iframe>` trong suốt.

### Ví dụ tấn công:

```html
<!-- Trang của attacker -->
<iframe src="https://victim.com" style="opacity: 0.01"></iframe>
<button>🎁 Nhấn nhận quà</button>
```

Người dùng tưởng nhấn "Nhận quà" nhưng thực tế đang nhấn vào nút "Xóa tài khoản" trong iframe!

## ⚠️ Kiểm tra nhanh website của bạn

### Test bằng Curl (30 giây)

```bash
curl -I https://your-website.com | grep -E "X-Frame-Options|Content-Security-Policy"
```

**Kết quả tốt (được bảo vệ):**
```
X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'
```

**Kết quả xấu (có lỗ hổng):**
```
(không có output hoặc thiếu headers)
```

## 🔧 Cách khắc phục (30 giây - 2 phút)

### Nginx (phổ biến nhất)

```nginx
# /etc/nginx/sites-available/your-site
server {
    ...
    add_header X-Frame-Options "DENY" always;
    add_header Content-Security-Policy "frame-ancestors 'none';" always;
}
```

**Apply:**
```bash
sudo nginx -t && sudo systemctl reload nginx
```

### Apache

```apache
# .htaccess hoặc httpd.conf
Header always set X-Frame-Options "DENY"
Header always set Content-Security-Policy "frame-ancestors 'none';"
```

**Apply:**
```bash
sudo systemctl reload apache2
```

### Vercel / Next.js

```json
// vercel.json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "Content-Security-Policy", "value": "frame-ancestors 'none';" }
      ]
    }
  ]
}
```

### Cloudflare Workers

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

## ✅ Kiểm tra lại sau khi fix

### 1. Test bằng Curl
```bash
curl -I https://your-website.com | grep "X-Frame-Options"
# Mong đợi: X-Frame-Options: DENY
```

### 2. Test bằng HTML Tool
Mở `test-clickjacking.html` → Nhập URL → Kiểm tra iframe trống

### 3. Scan lại bằng Python Script
```bash
python3 scanClickjacking.py https://your-website.com
# Mong đợi: Điểm 100/100
```

### 4. Test bằng Online Tools
- https://securityheaders.com
- https://observatory.mozilla.org

## 📊 Bảng so sánh các phương pháp bảo vệ

| Header | Tương thích | Độ mạnh | Khuyến nghị |
|--------|-------------|---------|-------------|
| X-Frame-Options: DENY | Tất cả browsers | ⭐⭐⭐⭐ | Dùng |
| X-Frame-Options: SAMEORIGIN | Tất cả browsers | ⭐⭐⭐ | Nếu cần embed nội bộ |
| CSP frame-ancestors 'none' | Modern browsers | ⭐⭐⭐⭐⭐ | Dùng (chuẩn mới) |
| CSP frame-ancestors 'self' | Modern browsers | ⭐⭐⭐⭐ | Nếu cần embed nội bộ |

**Khuyến nghị tốt nhất:** Dùng CẢ HAI để tương thích tối đa

```nginx
add_header X-Frame-Options "DENY" always;
add_header Content-Security-Policy "frame-ancestors 'none';" always;
```

## 🎯 Flow hoàn chỉnh để fix

```
1. SCAN
   ↓
   python3 scanClickjacking.py https://your-site.com
   ↓
   
2. PHÁT HIỆN LỖI?
   ↓
   Yes → Tiếp tục | No → Xong ✅
   ↓
   
3. THÊM HEADERS
   ↓
   Thêm X-Frame-Options + CSP vào config
   ↓
   
4. RESTART SERVICE
   ↓
   sudo systemctl reload nginx/apache2
   ↓
   
5. VERIFY
   ↓
   curl -I https://your-site.com | grep "X-Frame"
   ↓
   
6. TEST MANUAL
   ↓
   Mở test-clickjacking.html → Test
   ↓
   
7. SCAN LẠI
   ↓
   python3 scanClickjacking.py https://your-site.com
   ↓
   
8. ĐIỂM 100/100?
   ↓
   Yes → HOÀN TẤT ✅
```

## 🆘 Troubleshooting

### Vấn đề 1: Đã thêm header nhưng curl không thấy

**Nguyên nhân:**
- Chưa restart service
- CDN/Load balancer ghi đè
- Config bị override ở location khác

**Giải pháp:**
```bash
# 1. Kiểm tra config
sudo nginx -t

# 2. Restart (không phải reload)
sudo systemctl restart nginx

# 3. Test trực tiếp (bypass CDN)
curl -I https://your-server-ip -H "Host: your-domain.com"

# 4. Clear Cloudflare cache nếu dùng
```

### Vấn đề 2: Thêm header làm website bị lỗi

**Nguyên nhân:** Website cần được embed ở đâu đó (partner site, internal tools)

**Giải pháp:**
```nginx
# Thay DENY bằng SAMEORIGIN
add_header X-Frame-Options "SAMEORIGIN" always;

# Hoặc whitelist domain cụ thể
add_header Content-Security-Policy "frame-ancestors 'self' https://partner-site.com;" always;
```

### Vấn đề 3: Python script không chạy

```bash
# Cài requests
pip3 install requests

# Hoặc
pip3 install requests --break-system-packages

# Chạy với Python 3
python3 scanClickjacking.py
```

## 📁 Cấu trúc Files

```
clickjacking-toolkit/
├── scanClickjacking.py          # Script Python scan tự động
├── test-clickjacking.html       # HTML test tool
├── HUONGDAN_CLICKJACKING.md    # Hướng dẫn chi tiết
└── README.md                    # File này
```

## 📚 Tài liệu tham khảo

- [OWASP Clickjacking Defense](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- [RFC 7034 - X-Frame-Options](https://tools.ietf.org/html/rfc7034)
- [MDN - X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
- [CSP Level 3](https://www.w3.org/TR/CSP3/#directive-frame-ancestors)

## 🔒 Security Standards

Lỗi Clickjacking nằm trong:
- **OWASP Top 10 2021:** A05:2021 – Security Misconfiguration
- **CWE-1021:** Improper Restriction of Rendered UI Layers or Frames
- **PCI-DSS:** Requirement 6.5.10

## 💡 Tips

1. **Test trước deploy:** Luôn test trên staging trước
2. **Monitor logs:** Xem có request nào bị reject không
3. **Document:** Lưu lại lý do cấu hình (DENY vs SAMEORIGIN)
4. **Regular scan:** Scan lại mỗi quarter hoặc sau mỗi deployment
5. **Defense in depth:** Dùng cả X-Frame-Options VÀ CSP

## 📝 Checklist hoàn chỉnh

- [ ] Đã scan bằng Python script
- [ ] Đã test bằng HTML tool  
- [ ] Đã thêm X-Frame-Options header
- [ ] Đã thêm CSP frame-ancestors
- [ ] Đã restart web server
- [ ] Test bằng curl thấy headers
- [ ] Test bằng HTML tool thấy iframe bị chặn
- [ ] Scan lại → điểm 80-100/100
- [ ] Test trên production
- [ ] Verify không ảnh hưởng tính năng
- [ ] Clear CDN cache
- [ ] Lưu báo cáo vào docs
- [ ] Update security documentation
- [ ] Schedule quarterly rescan

## 🎓 Học thêm

### Các lỗi bảo mật khác cần check:
1. ✅ Clickjacking (đã có tool này)
2. Content Security Policy (CSP)
3. HTTP Strict Transport Security (HSTS)
4. X-Content-Type-Options
5. Referrer-Policy
6. Permissions-Policy

### Tools khác để scan:
```bash
# SecurityHeaders.com
curl https://securityheaders.com/?q=https://your-site.com

# Mozilla Observatory  
curl https://observatory.mozilla.org/

# Nmap HTTP methods
nmap --script http-security-headers your-site.com
```

## 📞 Support

Nếu gặp vấn đề:
1. Xem file `HUONGDAN_CLICKJACKING.md` 
2. Chạy lại với verbose mode
3. Check server logs
4. Test manual bằng HTML tool

## 📄 License

MIT License - Free to use

---

**Version:** 1.0.0  
**Last Updated:** 2024-11-11  
**Author:** Security Tools Team

✅ **Khuyến nghị:** Fix lỗi này ngay hôm nay! Chỉ mất 2-5 phút nhưng bảo vệ người dùng khỏi tấn công clickjacking.
