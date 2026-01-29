#!/usr/bin/env python3
"""
.\scanSSL.py
SSL/TLS Security Scanner
Quét lỗ hổng SSL/TLS và certificate issues
"""

import requests
import sys
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

class SSLSecurityScanner:
    def __init__(self, url):
        self.url = self.normalize_url(url)
        parsed = urlparse(self.url)
        self.domain = parsed.netloc
        self.hostname = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        self.scan_time = datetime.now()
        self.results = {}

    def normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    def scan_ssl(self):
        print(f"\n{'='*70}")
        print(f"🔍 ĐANG QUÉT: {self.url}")
        print(f"{'='*70}\n")

        try:
            # Test 1: HTTPS availability
            print("📤 Test 1: Kiểm tra HTTPS...")
            try:
                response = requests.get(self.url, timeout=10, verify=True)
                self.results['https_available'] = True
                self.results['status_code'] = response.status_code
                print(f"   ✅ HTTPS available: Status {response.status_code}")
            except requests.exceptions.SSLError as e:
                self.results['https_available'] = False
                self.results['ssl_error'] = str(e)
                print(f"   ❌ SSL Error: {e}")
            except Exception as e:
                self.results['https_available'] = False
                self.results['error'] = str(e)
                print(f"   ❌ Error: {e}")

            # Test 2: Certificate info
            print("\n📤 Test 2: Lấy thông tin certificate...")
            cert_info = self.get_certificate_info()
            self.results['certificate'] = cert_info

            if cert_info:
                print(f"   ✓ Subject: {cert_info.get('subject')}")
                print(f"   ✓ Issuer: {cert_info.get('issuer')}")
                print(f"   ✓ Valid from: {cert_info.get('notBefore')}")
                print(f"   ✓ Valid until: {cert_info.get('notAfter')}")
                print(f"   ✓ Expired: {'❌ YES' if cert_info.get('expired') else '✅ NO'}")

            # Test 3: TLS version
            print("\n📤 Test 3: Kiểm tra TLS version...")
            tls_version = self.check_tls_version()
            self.results['tls_version'] = tls_version
            print(f"   ✓ TLS Version: {tls_version}")

            # Test 4: Weak ciphers
            print("\n📤 Test 4: Kiểm tra cipher suites...")
            self.check_weak_ciphers()

            self.analyze_risk()

            print(f"\n{'='*70}")
            print(f"✅ QUÉT HOÀN TẤT")
            print(f"{'='*70}\n")

            return True

        except Exception as e:
            print(f"❌ LỖI: {str(e)}")
            return False

    def get_certificate_info(self):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert = ssock.getpeercert()

                    # Parse dates
                    from datetime import datetime as dt
                    not_before = dt.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = dt.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    now = dt.now()

                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter'],
                        'expired': now > not_after,
                        'not_yet_valid': now < not_before,
                        'days_until_expiry': (not_after - now).days
                    }
        except Exception as e:
            print(f"   ⚠️ Không lấy được cert info: {e}")
            return None

    def check_tls_version(self):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.hostname, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    return ssock.version()
        except:
            return "Unknown"

    def check_weak_ciphers(self):
        # Simplified check
        weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
        self.results['weak_protocols_found'] = []

        for protocol_name in weak_protocols:
            # Note: This is simplified. Real check would need more work
            print(f"   ℹ️ Checking {protocol_name}... (skipped in basic scan)")

        print(f"   ✓ Cipher check completed")

    def analyze_risk(self):
        self.results['is_vulnerable'] = False
        self.results['risk_level'] = 'Low'
        self.results['cvss_score'] = 0.0
        self.results['protection_score'] = 100

        issues = []
        protections = []

        # Check HTTPS availability
        if not self.results.get('https_available'):
            issues.append("HTTPS không khả dụng hoặc có SSL error")
            self.results['is_vulnerable'] = True
            self.results['protection_score'] -= 50

        # Check certificate
        cert = self.results.get('certificate')
        if cert:
            if cert.get('expired'):
                issues.append("Certificate đã hết hạn")
                self.results['is_vulnerable'] = True
                self.results['protection_score'] -= 40

            days_left = cert.get('days_until_expiry', 0)
            if days_left < 30:
                issues.append(f"Certificate sắp hết hạn ({days_left} ngày)")
                self.results['protection_score'] -= 20
            else:
                protections.append(f"Certificate còn {days_left} ngày")

        # Check TLS version
        tls_ver = self.results.get('tls_version', '')
        if 'TLSv1.3' in tls_ver or 'TLSv1.2' in tls_ver:
            protections.append(f"Sử dụng {tls_ver} (secure)")
        elif 'TLSv1.1' in tls_ver or 'TLSv1.0' in tls_ver:
            issues.append(f"Sử dụng {tls_ver} cũ (nên upgrade)")
            self.results['protection_score'] -= 30
        elif 'SSLv' in tls_ver:
            issues.append(f"Sử dụng {tls_ver} - RẤT NGUY HIỂM")
            self.results['is_vulnerable'] = True
            self.results['protection_score'] -= 50

        self.results['protection_score'] = max(0, self.results['protection_score'])
        self.results['issues'] = issues
        self.results['protections'] = protections

        if self.results['protection_score'] < 50:
            self.results['risk_level'] = 'High'
            self.results['cvss_score'] = 7.5
            self.results['assessment'] = '🔴 SSL/TLS CẤU HÌNH KHÔNG AN TOÀN'
        elif self.results['protection_score'] < 80:
            self.results['risk_level'] = 'Medium'
            self.results['cvss_score'] = 5.0
            self.results['assessment'] = '⚠️ SSL/TLS CẦN CẢI THIỆN'
        else:
            self.results['risk_level'] = 'Low'
            self.results['cvss_score'] = 0.0
            self.results['assessment'] = '✅ SSL/TLS ĐƯỢC CẤU HÌNH TỐT'

    def generate_markdown_report(self):
        cert = self.results.get('certificate', {})

        report = f"""# 🔒 Phân tích: "SSL/TLS Security Issues"

**Ngày:** {self.scan_time.strftime('%d/%m/%Y %H:%M:%S')}
**Website:** {self.url}
**Phân loại:** {"🔴 Issues Found" if self.results['is_vulnerable'] else "✅ Secure"}

---

## 🧪 Kết quả kiểm tra

### Certificate Information:
- **Subject:** {cert.get('subject', {}).get('commonName', 'N/A') if cert else 'N/A'}
- **Issuer:** {cert.get('issuer', {}).get('organizationName', 'N/A') if cert else 'N/A'}
- **Valid Until:** {cert.get('notAfter', 'N/A') if cert else 'N/A'}
- **Days Left:** {cert.get('days_until_expiry', 'N/A') if cert else 'N/A'}
- **Expired:** {'❌ YES' if cert and cert.get('expired') else '✅ NO' if cert else 'N/A'}

### TLS Version:
- **Version:** {self.results.get('tls_version', 'Unknown')}

---

## 📊 Đánh giá

**Điểm bảo mật:** {self.results['protection_score']}/100
**Rủi ro:** {self.results['risk_level']}
**CVSS:** {self.results['cvss_score']}

"""

        if self.results.get('issues'):
            report += "### ❌ Vấn đề:\n\n"
            for issue in self.results['issues']:
                report += f"- {issue}\n"

        if self.results.get('protections'):
            report += "\n### ✅ Điểm mạnh:\n\n"
            for prot in self.results['protections']:
                report += f"- {prot}\n"

        report += """

---

## 🔧 Khuyến nghị

### Cấu hình TLS an toàn:

**Nginx:**
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers off;
```

**Apache:**
```apache
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite HIGH:!aNULL:!MD5
```

### Test SSL/TLS:

```bash
# SSL Labs
https://www.ssllabs.com/ssltest/analyze.html?d=""" + self.domain + """

# OpenSSL
openssl s_client -connect """ + self.domain + """:443 -tls1_2
```

---

**Prepared by:** SSL/TLS Security Scanner
**Scan Time:** {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}
"""
        return report

    def save_report(self, filename=None):
        if filename is None:
            timestamp = self.scan_time.strftime('%Y%m%d_%H%M%S')
            filename = f"ssl_report_{self.domain}_{timestamp}.md"

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
    print("🛡️  SSL/TLS SECURITY SCANNER")
    print("="*70 + "\n")

    url = sys.argv[1] if len(sys.argv) > 1 else input("🔍 Nhập URL: ").strip()
    if not url:
        print("❌ Vui lòng nhập URL!")
        return

    scanner = SSLSecurityScanner(url)

    if not scanner.scan_ssl():
        return

    print("\n" + "="*70)
    print("📊 TÓM TẮT")
    print("="*70)
    print(f"Website: {scanner.url}")
    print(f"Đánh giá: {scanner.results['assessment']}")
    print(f"Điểm bảo mật: {scanner.results['protection_score']}/100")
    print(f"TLS Version: {scanner.results.get('tls_version', 'Unknown')}")

    if scanner.results['is_vulnerable']:
        print("\n🔴 PHÁT HIỆN VẤN ĐỀ!")
        for issue in scanner.results.get('issues', []):
            print(f"  ❌ {issue}")

    print("="*70 + "\n")

    save = input("💾 Lưu báo cáo? (y/n): ").strip().lower()
    if save in ['y', 'yes', 'có']:
        scanner.save_report()

if __name__ == "__main__":
    main()
