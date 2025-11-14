#!/usr/bin/env python3
"""
scanDirEnum.py
Directory & File Enumeration Scanner
"""

import sys
import os
from datetime import datetime
from urllib.parse import urljoin

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.utils import ScannerUtils, RateLimiter

class DirEnumScanner:
    def __init__(self, url):
        self.url = ScannerUtils.normalize_url(url)
        self.domain = ScannerUtils.get_domain(url)
        self.scan_time = datetime.now()
        self.results = {
            'scanner_name': 'Directory Enumeration Scanner',
            'url': self.url,
            'scan_time': self.scan_time.isoformat()
        }
        self.rate_limiter = RateLimiter(max_requests_per_second=10)

    def scan(self, wordlist_size='small'):
        ScannerUtils.print_banner("Directory Enumeration Scanner")
        print(f"🔍 Target: {self.url}\n")

        try:
            print(f"📤 Enumerating directories (wordlist: {wordlist_size})...")
            found = self.enumerate_directories(wordlist_size)

            self.results['found_paths'] = found
            self.analyze_risk()

            print(f"\n{'='*70}\n✅ QUÉT HOÀN TẤT\n{'='*70}\n")
            return True

        except Exception as e:
            print(f"❌ Lỗi: {e}")
            return False

    def enumerate_directories(self, wordlist_size='small'):
        """Enumerate directories and files"""
        found_paths = []

        # Load wordlist
        wordlist = self.get_wordlist(wordlist_size)

        print(f"   Testing {len(wordlist)} paths...")

        for path in wordlist:
            self.rate_limiter.wait_if_needed()

            test_url = urljoin(self.url + '/', path)
            response = ScannerUtils.make_request(test_url, allow_redirects=False)

            if response:
                if response.status_code == 200:
                    print(f"      ✅ 200: {path}")
                    found_paths.append({
                        'path': path,
                        'status': 200,
                        'size': len(response.text)
                    })
                elif response.status_code == 403:
                    print(f"      ⚠️ 403: {path} (Forbidden - exists but no access)")
                    found_paths.append({
                        'path': path,
                        'status': 403,
                        'size': 0
                    })
                elif response.status_code == 301 or response.status_code == 302:
                    location = response.headers.get('Location', '')
                    print(f"      ↪️ {response.status_code}: {path} → {location}")
                    found_paths.append({
                        'path': path,
                        'status': response.status_code,
                        'redirect': location
                    })

        if not found_paths:
            print("   ℹ️ No paths found")

        return found_paths

    def get_wordlist(self, size='small'):
        """Get wordlist based on size"""
        # Try to load from file
        wordlist_file = f"directories.txt"
        payloads = ScannerUtils.load_payloads(wordlist_file)

        if payloads:
            if size == 'small':
                return payloads[:20]  # First 20
            elif size == 'medium':
                return payloads[:50]  # First 50
            else:
                return payloads  # All

        # Fallback: basic wordlist
        basic_wordlist = [
            'admin', 'backup', 'config', 'data', 'db',
            'test', 'tmp', 'uploads', 'files', 'images',
            '.git', '.env', 'robots.txt', 'sitemap.xml',
            'phpinfo.php', 'README.md', 'wp-admin', 'api'
        ]

        return basic_wordlist[:10] if size == 'small' else basic_wordlist

    def analyze_risk(self):
        found = self.results.get('found_paths', [])
        total_found = len(found)

        # Check for sensitive paths
        sensitive_patterns = ['.git', '.env', 'config', 'backup', 'admin', 'phpinfo']
        sensitive_found = [p for p in found if any(s in p['path'].lower() for s in sensitive_patterns)]

        self.results['is_vulnerable'] = len(sensitive_found) > 0
        self.results['total_found'] = total_found
        self.results['sensitive_found'] = len(sensitive_found)

        issues = []
        protections = []

        if sensitive_found:
            issues.append(f"{len(sensitive_found)} sensitive paths exposed")
            for path in sensitive_found:
                issues.append(f"Exposed: {path['path']} (HTTP {path['status']})")

        if total_found == 0:
            self.results['risk_level'] = 'Low'
            self.results['cvss_score'] = 0.0
            self.results['protection_score'] = 100
            self.results['assessment'] = '✅ NO EXPOSED PATHS'
            protections.append("No common paths found")
        elif len(sensitive_found) > 0:
            self.results['risk_level'] = 'High'
            self.results['cvss_score'] = 7.5
            self.results['protection_score'] = 20
            self.results['assessment'] = '🔴 SENSITIVE PATHS EXPOSED'
        else:
            self.results['risk_level'] = 'Low'
            self.results['cvss_score'] = 3.0
            self.results['protection_score'] = 70
            self.results['assessment'] = '⚠️ SOME PATHS EXPOSED'
            protections.append("No sensitive paths found")

        self.results['issues'] = issues
        self.results['protections'] = protections

    def save_report(self, filename=None):
        """Save detailed report"""
        if filename is None:
            timestamp = ScannerUtils.generate_timestamp()
            filename = f"direnum_report_{self.domain}_{timestamp}.md"

        report = f"""# 🔍 Directory Enumeration Scan Report

**Scan Time:** {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}
**Target:** {self.url}
**Assessment:** {self.results.get('assessment', 'Unknown')}

---

## Summary

- **Total Paths Found:** {self.results.get('total_found', 0)}
- **Sensitive Paths:** {self.results.get('sensitive_found', 0)}
- **Risk Level:** {self.results.get('risk_level', 'Unknown')}
- **CVSS Score:** {self.results.get('cvss_score', 0.0)}
- **Protection Score:** {self.results.get('protection_score', 0)}/100

---

## Found Paths

"""

        found_paths = self.results.get('found_paths', [])
        if found_paths:
            for path_info in found_paths:
                path = path_info.get('path', '')
                status = path_info.get('status', 0)
                size = path_info.get('size', 0)
                redirect = path_info.get('redirect', '')

                report += f"### {path}\n"
                report += f"- **Status:** {status}\n"
                if size > 0:
                    report += f"- **Size:** {size} bytes\n"
                if redirect:
                    report += f"- **Redirect:** {redirect}\n"
                report += "\n"
        else:
            report += "_No paths found_\n\n"

        report += """---

## Issues

"""
        issues = self.results.get('issues', [])
        if issues:
            for issue in issues:
                report += f"- {issue}\n"
        else:
            report += "_No issues detected_\n"

        report += """
---

## Remediation

### Disable Directory Listing

**Apache (.htaccess):**
```apache
Options -Indexes
```

**Nginx:**
```nginx
autoindex off;
```

### Remove Sensitive Files

```bash
# Remove version control
rm -rf .git .svn

# Remove config files from web root
rm .env config.yml database.yml

# Remove backup files
find . -name "*.bak" -delete
find . -name "*~" -delete
```

### Use robots.txt Wisely

**Note:** robots.txt does NOT provide security. Use proper access controls instead.

```
# robots.txt example
User-agent: *
Disallow: /admin/
Disallow: /private/
```

---

**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"✅ Report saved: {filename}")
            return filename
        except Exception as e:
            print(f"❌ Error saving report: {e}")
            return None

def main():
    url = sys.argv[1] if len(sys.argv) > 1 else input("🔍 Enter URL: ").strip()
    if url:
        scanner = DirEnumScanner(url)
        if scanner.scan(wordlist_size='small'):
            ScannerUtils.print_result_summary(scanner.results)

            # Ask to save report
            save = input("\n💾 Lưu báo cáo? (y/n): ").strip().lower()
            if save in ['y', 'yes', 'có']:
                scanner.save_report()

if __name__ == "__main__":
    main()
