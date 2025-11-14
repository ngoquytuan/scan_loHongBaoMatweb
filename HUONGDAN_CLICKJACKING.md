# 🛡️ Hướng dẫn sử dụng scanClickjacking.py

## 📋 Mô tả

Script này giúp bạn:
- ✅ Quét lỗ hổng Clickjacking trên website
- ✅ Kiểm tra X-Frame-Options header
- ✅ Kiểm tra CSP frame-ancestors directive  
- ✅ Tạo báo cáo chi tiết với hướng dẫn khắc phục
- ✅ Hiển thị kết quả trực quan trên terminal

## 🚀 Cài đặt

### Yêu cầu
```bash
# Python 3.6+
python3 --version

# Thư viện requests
pip install requests
```

### Download script
```bash
# Tải về
curl -O https://your-url/scanClickjacking.py

# Hoặc copy từ file đã tạo
chmod +x scanClickjacking.py
```

## 💻 Cách sử dụng

### Cách 1: Nhập URL khi chạy
```bash
python3 scanClickjacking.py
# Sau đó nhập URL khi được hỏi
```

### Cách 2: Truyền URL qua tham số
```bash
python3 scanClickjacking.py https://example.com
```

### Cách 3: Quét nhiều website
```bash
# Tạo file urls.txt
cat > urls.txt << EOF
https://site1.com
https://site2.com
https://site3.com
EOF

# Quét từng site
while read url; do
  python3 scanClickjacking.py "$url"
  echo "---"
done < urls.txt
```

## 📊 Ví dụ output

### Ví dụ 1: Website CÓ LỖI (vulnerable)

```
======================================================================
🛡️  CLICKJACKING VULNERABILITY SCANNER
======================================================================

======================================================================
🔍 ĐANG QUÉT: https://vulnerable-site.com
======================================================================

📤 Test 1: Gửi GET request để kiểm tra headers...
   ✓ Status Code: 200
   ✓ X-Frame-Options: ❌ KHÔNG CÓ

📤 Test 2: Kiểm tra Content-Security-Policy...
   ✓ CSP Header: ❌ KHÔNG CÓ
   ✓ Frame-Ancestors: ❌ KHÔNG CÓ

📤 Test 3: Kiểm tra khả năng embed trong iframe...
   → Kiểm tra xem website có thể bị nhúng vào iframe không...
   ⚠️ CÓ THỂ BỊ EMBED - Dễ bị tấn công Clickjacking!

======================================================================
✅ QUÉT HOÀN TẤT
======================================================================

======================================================================
📊 TÓM TẮT KẾT QUẢ
======================================================================
Website: https://vulnerable-site.com
Đánh giá: 🔴 DỄ BỊ TẤN CÔNG CLICKJACKING - Thiếu header bảo vệ
Mức độ rủi ro: High
Điểm bảo vệ: 0/100
CVSS Score: 5.3

----------------------------------------------------------------------
🔴 PHÁT HIỆN LỖ HỔNG - Cần khắc phục!

Vấn đề:
  ❌ Thiếu header X-Frame-Options
  ❌ Thiếu hoàn toàn Content-Security-Policy
======================================================================

💾 Bạn có muốn lưu báo cáo chi tiết? (y/n): y
📝 Nhập tên file (Enter để dùng tên mặc định): 

✅ Đã lưu báo cáo: clickjacking_report_vulnerable-site.com_20241111_143022.md

======================================================================
🎯 BƯỚC TIẾP THEO
======================================================================

1. Đọc kỹ phần "Biện pháp khắc phục" trong báo cáo
2. Chọn Option phù hợp với hạ tầng của bạn
3. Test kỹ trước khi deploy production
4. Chạy lại tool này để verify đã fix thành công

📝 Khuyến nghị: Thêm cả X-Frame-Options và CSP frame-ancestors
```

### Ví dụ 2: Website AN TOÀN (protected)

```
======================================================================
🔍 ĐANG QUÉT: https://secure-site.com
======================================================================

📤 Test 1: Gửi GET request để kiểm tra headers...
   ✓ Status Code: 200
   ✓ X-Frame-Options: DENY

📤 Test 2: Kiểm tra Content-Security-Policy...
   ✓ CSP Header: default-src 'self'; frame-ancestors 'none';
   ✓ Frame-Ancestors: frame-ancestors 'none'

📤 Test 3: Kiểm tra khả năng embed trong iframe...
   → Kiểm tra xem website có thể bị nhúng vào iframe không...
   ✅ ĐƯỢC BẢO VỆ - X-Frame-Options: DENY chặn hoàn toàn

======================================================================
📊 TÓM TẮT KẾT QUẢ
======================================================================
Website: https://secure-site.com
Đánh giá: ✅ ĐƯỢC BẢO VỆ TỐT - An toàn trước Clickjacking
Mức độ rủi ro: Low
Điểm bảo vệ: 100/100
CVSS Score: 0.0

----------------------------------------------------------------------
✅ AN TOÀN - Đã được bảo vệ tốt!

Điểm mạnh:
  ✅ X-Frame-Options: DENY (tốt nhất)
  ✅ CSP frame-ancestors 'none' (tốt nhất)
```

## 🔧 Khắc phục lỗi Clickjacking

### Bước 1: Xác định loại server

```bash
# Kiểm tra server type
curl -I https://your-site.com | grep -i "server:"
```

### Bước 2: Thêm headers bảo vệ

#### Nginx
```nginx
# /etc/nginx/sites-available/your-site
server {
    listen 443 ssl;
    server_name your-site.com;
    
    # Chặn hoàn toàn clickjacking (khuyến nghị)
    add_header X-Frame-Options "DENY" always;
    add_header Content-Security-Policy "frame-ancestors 'none';" always;
    
    # Hoặc nếu cần embed nội bộ
    # add_header X-Frame-Options "SAMEORIGIN" always;
    # add_header Content-Security-Policy "frame-ancestors 'self';" always;
    
    location / {
        # Your config here
    }
}
```

**Restart Nginx:**
```bash
sudo nginx -t                  # Test config
sudo systemctl restart nginx   # Apply
```

#### Apache
```apache
# .htaccess hoặc /etc/apache2/sites-available/your-site.conf
<IfModule mod_headers.c>
    Header always set X-Frame-Options "DENY"
    Header always set Content-Security-Policy "frame-ancestors 'none';"
</IfModule>
```

**Restart Apache:**
```bash
sudo apache2ctl configtest    # Test config
sudo systemctl restart apache2 # Apply
```

#### Node.js (Express)
```javascript
// app.js
const helmet = require('helmet');

app.use(helmet.frameguard({ action: 'deny' }));
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "frame-ancestors 'none';");
  next();
});
```

#### Next.js
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
          {
            key: 'Content-Security-Policy',
            value: "frame-ancestors 'none';",
          },
        ],
      },
    ]
  },
}
```

#### Vercel (vercel.json)
```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        },
        {
          "key": "Content-Security-Policy",
          "value": "frame-ancestors 'none';"
        }
      ]
    }
  ]
}
```

#### Cloudflare Workers
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

### Bước 3: Kiểm tra lại

#### Manual test bằng curl
```bash
# Kiểm tra X-Frame-Options
curl -I https://your-site.com | grep -i "x-frame-options"
# Kết quả mong đợi: X-Frame-Options: DENY

# Kiểm tra CSP
curl -I https://your-site.com | grep -i "content-security-policy"
# Kết quả mong đợi: Content-Security-Policy: frame-ancestors 'none'
```

#### Test bằng HTML file
Tạo file `test-clickjacking.html`:
```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Clickjacking Protection Test</title>
    <style>
        body { font-family: Arial; padding: 20px; }
        iframe { 
            border: 2px solid #333; 
            width: 100%; 
            height: 600px;
            margin: 20px 0;
        }
        .status {
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }
        .protected { background: #d4edda; color: #155724; }
        .vulnerable { background: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <h1>🔒 Clickjacking Protection Test</h1>
    
    <div class="status protected">
        <strong>✅ PASS:</strong> Nếu iframe bên dưới TRỐNG hoặc hiển thị lỗi
        → Website đã được bảo vệ khỏi clickjacking
    </div>
    
    <div class="status vulnerable">
        <strong>❌ FAIL:</strong> Nếu iframe hiển thị website bình thường
        → Website vẫn còn lỗ hổng clickjacking
    </div>
    
    <h2>Test Iframe:</h2>
    <iframe src="https://YOUR-SITE.com" title="Clickjacking Test"></iframe>
    
    <script>
        // Check if iframe loaded
        const iframe = document.querySelector('iframe');
        iframe.onload = () => {
            try {
                const doc = iframe.contentDocument || iframe.contentWindow.document;
                console.log('❌ VULNERABLE - Iframe loaded successfully');
            } catch (e) {
                console.log('✅ PROTECTED - Cannot access iframe content');
            }
        };
        
        iframe.onerror = () => {
            console.log('✅ PROTECTED - Iframe blocked by X-Frame-Options');
        };
    </script>
</body>
</html>
```

Mở file trong browser:
- ✅ Nếu iframe trống = **ĐÃ FIX THÀNH CÔNG**
- ❌ Nếu iframe hiển thị website = **CHƯA FIX HOẶC FIX SAI**

#### Scan lại bằng tool
```bash
python3 scanClickjacking.py https://your-site.com
```

#### Kiểm tra bằng online tools
```bash
# Mở các link này:
https://securityheaders.com/?q=https://your-site.com
https://observatory.mozilla.org/analyze/your-site.com
```

## 🎯 Các lỗi thường gặp

### Lỗi 1: Header bị ghi đè
**Triệu chứng:** Đã thêm header nhưng vẫn không thấy

**Nguyên nhân:** 
- Load balancer/CDN ghi đè header
- Nginx location khác override
- Framework response middleware conflict

**Giải pháp:**
```nginx
# Nginx - Thêm always để đảm bảo luôn set
add_header X-Frame-Options "DENY" always;
```

### Lỗi 2: CSP bị conflict
**Triệu chứng:** Đã có CSP nhưng thêm frame-ancestors bị lỗi

**Giải pháp:**
```nginx
# Thêm vào CSP hiện có, không tạo header mới
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none'; script-src 'self' 'unsafe-inline';" always;
```

### Lỗi 3: Không restart service
**Giải pháp:**
```bash
# Luôn restart sau khi sửa config
sudo systemctl restart nginx
# Hoặc
sudo systemctl reload nginx
```

### Lỗi 4: Cache browser/CDN
**Giải pháp:**
```bash
# Test với curl thay vì browser
curl -I https://your-site.com

# Clear Cloudflare cache nếu dùng
# Hoặc test với incognito mode
```

## 📋 Checklist sau khi fix

- [ ] Đã thêm X-Frame-Options header
- [ ] Đã thêm CSP frame-ancestors directive
- [ ] Đã restart web server
- [ ] Test bằng curl thấy headers
- [ ] Test bằng HTML file thấy iframe bị chặn
- [ ] Scan lại bằng tool → điểm 80-100
- [ ] Test trên production (không chỉ staging)
- [ ] Clear cache CDN/browser
- [ ] Verify không ảnh hưởng tính năng
- [ ] Lưu báo cáo scan vào documentation

## 🆘 Hỗ trợ

Nếu gặp vấn đề:
1. Chạy script với verbose: `python3 scanClickjacking.py https://site.com`
2. Xem file báo cáo được tạo ra
3. Kiểm tra console logs: `curl -v https://your-site.com`
4. Test manual bằng HTML file

## 📚 Tài liệu tham khảo

- [OWASP Clickjacking](https://owasp.org/www-community/attacks/Clickjacking)
- [RFC 7034 - X-Frame-Options](https://tools.ietf.org/html/rfc7034)
- [CSP frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors)
- [SecurityHeaders.com](https://securityheaders.com)

---

**Version:** 1.0  
**Last Updated:** 2024-11-11
