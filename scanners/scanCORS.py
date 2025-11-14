#!/usr/bin/env python3
"""
.\scanCORS.py
CORS (Cross-Origin Resource Sharing) Security Scanner
Quét lỗi cấu hình CORS không an toàn
"""

import requests
import sys
from datetime import datetime
from urllib.parse import urlparse

class CORSSecurityScanner:
    def __init__(self, url):
        self.url = self.normalize_url(url)
        self.domain = urlparse(self.url).netloc
        self.scan_time = datetime.now()
        self.results = {}

    def normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    def scan_cors(self):
        print(f"\n{'='*70}")
        print(f"🔍 ĐANG QUÉT: {self.url}")
        print(f"{'='*70}\n")

        try:
            # Test 1: Request không có Origin header
            print("📤 Test 1: Request không có Origin...")
            response_no_origin = requests.get(self.url, timeout=10)
            self.results['no_origin'] = {
                'status': response_no_origin.status_code,
                'acao': response_no_origin.headers.get('Access-Control-Allow-Origin'),
                'acac': response_no_origin.headers.get('Access-Control-Allow-Credentials')
            }
            print(f"   ✓ Status: {response_no_origin.status_code}")
            print(f"   ✓ ACAO: {self.results['no_origin']['acao'] or 'Không có'}")

            # Test 2: Request với Origin = evil.com
            print("\n📤 Test 2: Request với Origin = evil.com...")
            headers = {'Origin': 'https://evil.com'}
            response_evil = requests.get(self.url, headers=headers, timeout=10)
            self.results['evil_origin'] = {
                'status': response_evil.status_code,
                'acao': response_evil.headers.get('Access-Control-Allow-Origin'),
                'acac': response_evil.headers.get('Access-Control-Allow-Credentials')
            }
            print(f"   ✓ Status: {response_evil.status_code}")
            print(f"   ✓ ACAO: {self.results['evil_origin']['acao'] or 'Không có'}")

            # Test 3: Request với Origin = null
            print("\n📤 Test 3: Request với Origin = null...")
            headers = {'Origin': 'null'}
            response_null = requests.get(self.url, headers=headers, timeout=10)
            self.results['null_origin'] = {
                'status': response_null.status_code,
                'acao': response_null.headers.get('Access-Control-Allow-Origin'),
                'acac': response_null.headers.get('Access-Control-Allow-Credentials')
            }
            print(f"   ✓ Status: {response_null.status_code}")
            print(f"   ✓ ACAO: {self.results['null_origin']['acao'] or 'Không có'}")

            # Test 4: OPTIONS preflight
            print("\n📤 Test 4: OPTIONS preflight request...")
            headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'Content-Type'
            }
            response_options = requests.options(self.url, headers=headers, timeout=10)
            self.results['preflight'] = {
                'status': response_options.status_code,
                'acao': response_options.headers.get('Access-Control-Allow-Origin'),
                'acam': response_options.headers.get('Access-Control-Allow-Methods'),
                'acah': response_options.headers.get('Access-Control-Allow-Headers'),
                'acac': response_options.headers.get('Access-Control-Allow-Credentials')
            }
            print(f"   ✓ Status: {response_options.status_code}")
            print(f"   ✓ Allow-Methods: {self.results['preflight']['acam'] or 'Không có'}")

            self.analyze_risk()

            print(f"\n{'='*70}")
            print(f"✅ QUÉT HOÀN TẤT")
            print(f"{'='*70}\n")

            return True

        except Exception as e:
            print(f"❌ LỖI: {str(e)}")
            return False

    def analyze_risk(self):
        self.results['is_vulnerable'] = False
        self.results['risk_level'] = 'Low'
        self.results['cvss_score'] = 0.0
        self.results['protection_score'] = 100

        issues = []
        protections = []

        # Kiểm tra wildcard ACAO - chỉ kiểm tra test results
        test_keys = ['no_origin', 'evil_origin', 'null_origin']
        for test_name in test_keys:
            if test_name not in self.results:
                continue
            test_result = self.results[test_name]

            # Ensure test_result is a dictionary before accessing
            if not isinstance(test_result, dict):
                continue

            acao = test_result.get('acao')
            acac = test_result.get('acac')

            if acao == '*':
                issues.append(f"ACAO wildcard (*) trong test {test_name}")
                self.results['is_vulnerable'] = True
                self.results['protection_score'] -= 30

            if acao and acao != self.domain and test_name == 'evil_origin':
                issues.append(f"Accept Origin từ evil.com")
                self.results['is_vulnerable'] = True
                self.results['protection_score'] -= 25

            if acao == 'null':
                issues.append(f"Accept Origin = null")
                self.results['is_vulnerable'] = True
                self.results['protection_score'] -= 20

            if acac == 'true' and (acao == '*' or acao not in [None, self.domain]):
                issues.append(f"Allow-Credentials=true với ACAO không an toàn")
                self.results['is_vulnerable'] = True
                self.results['protection_score'] -= 25

        self.results['protection_score'] = max(0, self.results['protection_score'])
        self.results['issues'] = issues
        self.results['protections'] = protections if not issues else ["Không có vấn đề CORS nghiêm trọng"]

        if self.results['protection_score'] < 50:
            self.results['risk_level'] = 'High'
            self.results['cvss_score'] = 6.5
            self.results['assessment'] = '🔴 CẤU HÌNH CORS KHÔNG AN TOÀN'
        elif self.results['protection_score'] < 80:
            self.results['risk_level'] = 'Medium'
            self.results['cvss_score'] = 4.3
            self.results['assessment'] = '⚠️ CORS CẦN CẢI THIỆN'
        else:
            self.results['risk_level'] = 'Low'
            self.results['cvss_score'] = 0.0
            self.results['assessment'] = '✅ CORS ĐƯỢC CẤU HÌNH AN TOÀN'

    def generate_markdown_report(self):
        report = f"""# 🔐 Phân tích: "CORS Misconfiguration Vulnerability"

**Ngày:** {self.scan_time.strftime('%d/%m/%Y %H:%M:%S')}
**Website:** {self.url}
**Phân loại:** {"🔴 Vulnerable" if self.results['is_vulnerable'] else "✅ Secure"}

---

## 🧪 Kết quả kiểm tra

### Test 1: Không có Origin
- ACAO: `{self.results['no_origin']['acao'] or 'Không có'}`
- ACAC: `{self.results['no_origin']['acac'] or 'Không có'}`

### Test 2: Origin = evil.com
- ACAO: `{self.results['evil_origin']['acao'] or 'Không có'}`
- ACAC: `{self.results['evil_origin']['acac'] or 'Không có'}`
- **Nguy hiểm nếu:** ACAO reflect evil.com

### Test 3: Origin = null
- ACAO: `{self.results['null_origin']['acao'] or 'Không có'}`
- **Nguy hiểm nếu:** ACAO = null

### Test 4: OPTIONS Preflight
- ACAO: `{self.results['preflight']['acao'] or 'Không có'}`
- ACAM: `{self.results['preflight']['acam'] or 'Không có'}`
- ACAH: `{self.results['preflight']['acah'] or 'Không có'}`

---

## 📊 Đánh giá

**Điểm bảo mật:** {self.results['protection_score']}/100
**Rủi ro:** {self.results['risk_level']}
**CVSS:** {self.results['cvss_score']}

"""

        if self.results.get('issues'):
            report += "### ❌ Vấn đề phát hiện:\n\n"
            for issue in self.results['issues']:
                report += f"- {issue}\n"
        else:
            report += "### ✅ Không phát hiện vấn đề nghiêm trọng\n"

        report += """

---

## 🔧 Biện pháp khắc phục

### Cấu hình CORS an toàn:

**Node.js (Express):**
```javascript
const cors = require('cors');

const whitelist = ['https://yourdomain.com', 'https://app.yourdomain.com'];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || whitelist.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true, // Chỉ khi cần cookies
  methods: ['GET', 'POST'], // Giới hạn methods
  allowedHeaders: ['Content-Type', 'Authorization']
}));
```

**Nginx:**
```nginx
# Chỉ cho phép origins cụ thể
set $cors_origin "";
if ($http_origin ~* "^https://(.*\\.)?yourdomain\\.com$") {
    set $cors_origin $http_origin;
}

add_header Access-Control-Allow-Origin $cors_origin always;
add_header Access-Control-Allow-Credentials "true" always;
add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;
add_header Access-Control-Allow-Headers "Content-Type, Authorization" always;
```

**⚠️ KHÔNG nên:**
- `Access-Control-Allow-Origin: *` với credentials
- Reflect Origin header mà không validate
- Allow Origin = null
- Wildcard trong subdomains không cẩn thận

---

**Prepared by:** CORS Security Scanner
**Scan Time:** {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}
"""
        return report

    def save_report(self, filename=None):
        if filename is None:
            timestamp = self.scan_time.strftime('%Y%m%d_%H%M%S')
            filename = f"cors_report_{self.domain}_{timestamp}.md"

        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(self.generate_markdown_report())
            print(f"✅ Đã lưu báo cáo: {filename}")
            return filename
        except Exception as e:
            print(f"❌ Lỗi: {str(e)}")
            return None

def main():
    print("="*70)
    print("🛡️  CORS SECURITY SCANNER")
    print("="*70 + "\n")

    url = sys.argv[1] if len(sys.argv) > 1 else input("🔍 Nhập URL: ").strip()
    if not url:
        print("❌ Vui lòng nhập URL!")
        return

    scanner = CORSSecurityScanner(url)

    if not scanner.scan_cors():
        print("❌ Quét thất bại!")
        return

    print("\n" + "="*70)
    print("📊 TÓM TẮT")
    print("="*70)
    print(f"Website: {scanner.url}")
    print(f"Đánh giá: {scanner.results['assessment']}")
    print(f"Điểm bảo mật: {scanner.results['protection_score']}/100")

    if scanner.results['is_vulnerable']:
        print("\n🔴 PHÁT HIỆN LỖ HỔNG!")
        for issue in scanner.results.get('issues', []):
            print(f"  ❌ {issue}")

    print("="*70 + "\n")

    save = input("💾 Lưu báo cáo? (y/n): ").strip().lower()
    if save in ['y', 'yes', 'có']:
        scanner.save_report()

if __name__ == "__main__":
    main()
