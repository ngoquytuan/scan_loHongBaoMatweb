#!/usr/bin/env python3
"""
.\scanMixedContent.py
Mixed Content Scanner
Quét lỗi Mixed Content (HTTP resources trong HTTPS page)
"""

import requests
import sys
from datetime import datetime
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import re

class MixedContentScanner:
    def __init__(self, url):
        self.url = self.normalize_url(url)
        self.domain = urlparse(self.url).netloc
        self.is_https = self.url.startswith('https://')
        self.scan_time = datetime.now()
        self.results = {}

    def normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    def scan_mixed_content(self):
        print(f"\n{'='*70}")
        print(f"🔍 ĐANG QUÉT: {self.url}")
        print(f"{'='*70}\n")

        if not self.is_https:
            print("⚠️ Website không sử dụng HTTPS - không có mixed content")
            self.results['is_https'] = False
            return True

        try:
            print("📤 Test 1: Lấy HTML content...")
            response = requests.get(self.url, timeout=10, verify=True)
            soup = BeautifulSoup(response.text, 'html.parser')

            print(f"   ✓ Status: {response.status_code}")
            print(f"   ✓ Content Length: {len(response.text)} bytes")

            # Scan các loại resources
            print("\n📤 Test 2: Quét images (img src)...")
            self.results['images'] = self.scan_resources(soup, 'img', 'src')

            print("\n📤 Test 3: Quét scripts (script src)...")
            self.results['scripts'] = self.scan_resources(soup, 'script', 'src')

            print("\n📤 Test 4: Quét stylesheets (link href)...")
            self.results['stylesheets'] = self.scan_link_resources(soup)

            print("\n📤 Test 5: Quét iframes...")
            self.results['iframes'] = self.scan_resources(soup, 'iframe', 'src')

            print("\n📤 Test 6: Quét video/audio...")
            self.results['media'] = self.scan_media_resources(soup)

            self.analyze_risk()

            print(f"\n{'='*70}")
            print(f"✅ QUÉT HOÀN TẤT")
            print(f"{'='*70}\n")

            return True

        except Exception as e:
            print(f"❌ LỖI: {str(e)}")
            return False

    def scan_resources(self, soup, tag, attr):
        elements = soup.find_all(tag)
        http_resources = []
        https_resources = []

        for elem in elements:
            url = elem.get(attr)
            if not url:
                continue

            # Normalize URL
            if url.startswith('//'):
                url = 'https:' + url
            elif url.startswith('/'):
                url = urljoin(self.url, url)

            if url.startswith('http://'):
                http_resources.append(url)
                print(f"   ❌ HTTP: {url[:60]}...")
            elif url.startswith('https://'):
                https_resources.append(url)

        total = len(http_resources) + len(https_resources)
        print(f"   ✓ Total: {total}, HTTPS: {len(https_resources)}, HTTP: {len(http_resources)}")

        return {
            'total': total,
            'http': http_resources,
            'https': https_resources,
            'http_count': len(http_resources),
            'https_count': len(https_resources)
        }

    def scan_link_resources(self, soup):
        links = soup.find_all('link', rel='stylesheet')
        http_resources = []
        https_resources = []

        for link in links:
            url = link.get('href')
            if not url:
                continue

            if url.startswith('//'):
                url = 'https:' + url
            elif url.startswith('/'):
                url = urljoin(self.url, url)

            if url.startswith('http://'):
                http_resources.append(url)
                print(f"   ❌ HTTP: {url[:60]}...")
            elif url.startswith('https://'):
                https_resources.append(url)

        total = len(http_resources) + len(https_resources)
        print(f"   ✓ Total: {total}, HTTPS: {len(https_resources)}, HTTP: {len(http_resources)}")

        return {
            'total': total,
            'http': http_resources,
            'https': https_resources,
            'http_count': len(http_resources),
            'https_count': len(https_resources)
        }

    def scan_media_resources(self, soup):
        http_resources = []
        https_resources = []

        for tag in ['video', 'audio']:
            elements = soup.find_all(tag)
            for elem in elements:
                url = elem.get('src')
                if url:
                    if url.startswith('http://'):
                        http_resources.append(url)
                    elif url.startswith('https://'):
                        https_resources.append(url)

                # Check source tags
                sources = elem.find_all('source')
                for source in sources:
                    url = source.get('src')
                    if url:
                        if url.startswith('http://'):
                            http_resources.append(url)
                        elif url.startswith('https://'):
                            https_resources.append(url)

        total = len(http_resources) + len(https_resources)
        print(f"   ✓ Total: {total}, HTTPS: {len(https_resources)}, HTTP: {len(http_resources)}")

        return {
            'total': total,
            'http': http_resources,
            'https': https_resources,
            'http_count': len(http_resources),
            'https_count': len(https_resources)
        }

    def analyze_risk(self):
        total_http = 0
        total_resources = 0

        for resource_type in ['images', 'scripts', 'stylesheets', 'iframes', 'media']:
            data = self.results.get(resource_type, {})
            total_http += data.get('http_count', 0)
            total_resources += data.get('total', 0)

        self.results['total_http'] = total_http
        self.results['total_resources'] = total_resources

        self.results['is_vulnerable'] = total_http > 0
        self.results['protection_score'] = 100 if total_http == 0 else max(0, 100 - (total_http * 5))

        issues = []
        protections = []

        if total_http > 0:
            issues.append(f"Phát hiện {total_http} HTTP resources trong HTTPS page")

            # Phân loại theo severity
            scripts_http = self.results['scripts']['http_count']
            iframes_http = self.results['iframes']['http_count']

            if scripts_http > 0:
                issues.append(f"Active Mixed Content: {scripts_http} HTTP scripts (NGUY HIỂM)")
                self.results['risk_level'] = 'High'
                self.results['cvss_score'] = 7.5
            elif iframes_http > 0:
                issues.append(f"Active Mixed Content: {iframes_http} HTTP iframes (NGUY HIỂM)")
                self.results['risk_level'] = 'High'
                self.results['cvss_score'] = 6.5
            else:
                issues.append(f"Passive Mixed Content: Images/Media qua HTTP")
                self.results['risk_level'] = 'Medium'
                self.results['cvss_score'] = 4.3
        else:
            protections.append(f"Tất cả {total_resources} resources đều dùng HTTPS")
            self.results['risk_level'] = 'Low'
            self.results['cvss_score'] = 0.0

        self.results['issues'] = issues
        self.results['protections'] = protections

        if total_http > 0:
            self.results['assessment'] = f'🔴 PHÁT HIỆN {total_http} MIXED CONTENT'
        else:
            self.results['assessment'] = '✅ KHÔNG CÓ MIXED CONTENT'

    def generate_markdown_report(self):
        report = f"""# 🔒 Phân tích: "Mixed Content Vulnerability"

**Ngày:** {self.scan_time.strftime('%d/%m/%Y %H:%M:%S')}
**Website:** {self.url}
**Phân loại:** {"🔴 Mixed Content Found" if self.results['is_vulnerable'] else "✅ Secure"}

---

## 🧪 Kết quả quét

"""

        for resource_type in ['scripts', 'stylesheets', 'images', 'iframes', 'media']:
            data = self.results.get(resource_type, {})
            http_count = data.get('http_count', 0)
            https_count = data.get('https_count', 0)
            status = "❌" if http_count > 0 else "✅"

            report += f"""### {resource_type.title()}
- Total: {data.get('total', 0)}
- HTTPS: {https_count}
- HTTP: {http_count} {status}

"""

            if http_count > 0:
                report += "**HTTP URLs:**\n"
                for url in data.get('http', [])[:5]:  # Show first 5
                    report += f"- `{url}`\n"
                if len(data.get('http', [])) > 5:
                    report += f"- ... và {len(data['http']) - 5} URLs khác\n"
                report += "\n"

        report += f"""

---

## 📊 Đánh giá

**Điểm bảo mật:** {self.results['protection_score']}/100
**Total HTTP Resources:** {self.results['total_http']}
**Rủi ro:** {self.results['risk_level']}
**CVSS:** {self.results['cvss_score']}

"""

        if self.results.get('issues'):
            report += "### ❌ Vấn đề:\n\n"
            for issue in self.results['issues']:
                report += f"- {issue}\n"

        if self.results.get('protections'):
            report += "\n### ✅ Bảo vệ:\n\n"
            for prot in self.results['protections']:
                report += f"- {prot}\n"

        report += """

---

## 🔧 Khắc phục

### 1. Chuyển URLs sang HTTPS:

```html
<!-- ❌ BAD -->
<script src="http://example.com/script.js"></script>
<img src="http://example.com/image.jpg">

<!-- ✅ GOOD -->
<script src="https://example.com/script.js"></script>
<img src="https://example.com/image.jpg">
```

### 2. Dùng protocol-relative URLs:

```html
<!-- Tự động dùng protocol của page -->
<script src="//example.com/script.js"></script>
<img src="//cdn.example.com/image.jpg">
```

### 3. Content Security Policy:

```nginx
# Block all mixed content
add_header Content-Security-Policy "upgrade-insecure-requests; block-all-mixed-content" always;
```

### 4. Meta tag (fallback):

```html
<meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">
```

---

**Prepared by:** Mixed Content Scanner
**Scan Time:** {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}
"""
        return report

    def save_report(self, filename=None):
        if filename is None:
            timestamp = self.scan_time.strftime('%Y%m%d_%H%M%S')
            filename = f"mixed_content_report_{self.domain}_{timestamp}.md"

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
    print("🛡️  MIXED CONTENT SCANNER")
    print("="*70 + "\n")

    url = sys.argv[1] if len(sys.argv) > 1 else input("🔍 Nhập URL: ").strip()
    if not url:
        print("❌ Vui lòng nhập URL!")
        return

    scanner = MixedContentScanner(url)

    if not scanner.scan_mixed_content():
        return

    print("\n" + "="*70)
    print("📊 TÓM TẮT")
    print("="*70)
    print(f"Website: {scanner.url}")
    print(f"Đánh giá: {scanner.results['assessment']}")
    print(f"HTTP Resources: {scanner.results.get('total_http', 0)}")
    print(f"Điểm bảo mật: {scanner.results['protection_score']}/100")

    if scanner.results.get('is_vulnerable'):
        print("\n🔴 PHÁT HIỆN MIXED CONTENT!")
        for issue in scanner.results.get('issues', []):
            print(f"  ❌ {issue}")

    print("="*70 + "\n")

    save = input("💾 Lưu báo cáo? (y/n): ").strip().lower()
    if save in ['y', 'yes', 'có']:
        scanner.save_report()

if __name__ == "__main__":
    main()
