#!/usr/bin/env python3
"""
scanXSS.py
Cross-Site Scripting (XSS) Vulnerability Scanner
Quét lỗ hổng XSS (Reflected, Stored, DOM-based)
"""

import sys
import os
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.utils import ScannerUtils, RateLimiter
from bs4 import BeautifulSoup

class XSSScanner:
    def __init__(self, url):
        self.url = ScannerUtils.normalize_url(url)
        self.domain = ScannerUtils.get_domain(url)
        self.scan_time = datetime.now()
        self.results = {
            'scanner_name': 'XSS Scanner',
            'url': self.url,
            'scan_time': self.scan_time.isoformat()
        }
        self.rate_limiter = RateLimiter(max_requests_per_second=5)

    def scan(self):
        """Main scan function"""
        ScannerUtils.print_banner("XSS (Cross-Site Scripting) Scanner")
        print(f"🔍 Target: {self.url}\n")

        try:
            # Test 1: Reflected XSS via URL parameters
            print("📤 Test 1: Reflected XSS via URL parameters...")
            reflected_vulns = self.test_reflected_xss()

            # Test 2: Reflected XSS via form inputs
            print("\n📤 Test 2: Reflected XSS via form inputs...")
            form_vulns = self.test_form_xss()

            # Test 3: DOM-based XSS
            print("\n📤 Test 3: DOM-based XSS patterns...")
            dom_vulns = self.test_dom_xss()

            self.results['reflected_xss'] = reflected_vulns
            self.results['form_xss'] = form_vulns
            self.results['dom_xss'] = dom_vulns

            self.analyze_risk()

            print(f"\n{'='*70}")
            print("✅ QUÉT HOÀN TẤT")
            print(f"{'='*70}\n")

            return True

        except Exception as e:
            print(f"❌ Lỗi: {e}")
            return False

    def test_reflected_xss(self):
        """Test reflected XSS via URL parameters"""
        vulnerabilities = []

        # Parse URL
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        if not params:
            print("   ℹ️ Không có URL parameters để test")
            return vulnerabilities

        # XSS payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'\"><script>alert(1)</script>",
            "javascript:alert(1)"
        ]

        for param_name in params.keys():
            print(f"   Testing parameter: {param_name}")

            for payload in payloads:
                self.rate_limiter.wait_if_needed()

                # Inject payload
                test_params = params.copy()
                test_params[param_name] = [payload]

                # Rebuild URL
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))

                response = ScannerUtils.make_request(test_url)

                if response and payload in response.text:
                    print(f"      ❌ VULNERABLE: Payload reflected in response")
                    vulnerabilities.append({
                        'type': 'Reflected XSS',
                        'parameter': param_name,
                        'payload': payload,
                        'url': test_url
                    })
                    break  # Found vuln, next parameter

        if not vulnerabilities:
            print("   ✅ No reflected XSS found in URL parameters")

        return vulnerabilities

    def test_form_xss(self):
        """Test XSS in form inputs"""
        vulnerabilities = []

        response = ScannerUtils.make_request(self.url)
        if not response:
            print("   ❌ Không thể lấy page content")
            return vulnerabilities

        forms = ScannerUtils.extract_forms(response.text, self.url)

        if not forms:
            print("   ℹ️ Không có forms để test")
            return vulnerabilities

        print(f"   Found {len(forms)} forms")

        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "'\"><script>alert(1)</script>"
        ]

        for form in forms:
            for input_field in form['inputs']:
                if input_field['type'] in ['submit', 'button', 'hidden']:
                    continue

                input_name = input_field['name']

                for payload in payloads[:2]:  # Limit to 2 payloads per field
                    self.rate_limiter.wait_if_needed()

                    # Prepare form data
                    form_data = {}
                    for inp in form['inputs']:
                        if inp['name'] == input_name:
                            form_data[inp['name']] = payload
                        else:
                            form_data[inp['name']] = inp['value'] or 'test'

                    # Submit form
                    if form['method'] == 'POST':
                        resp = ScannerUtils.make_request(
                            form['action'],
                            method='POST',
                            data=form_data
                        )
                    else:
                        resp = ScannerUtils.make_request(
                            form['action'],
                            method='GET',
                            params=form_data
                        )

                    if resp and payload in resp.text:
                        print(f"      ❌ VULNERABLE: {input_name}")
                        vulnerabilities.append({
                            'type': 'Form XSS',
                            'form_action': form['action'],
                            'parameter': input_name,
                            'payload': payload
                        })
                        break

        if not vulnerabilities:
            print("   ✅ No XSS found in forms")

        return vulnerabilities

    def test_dom_xss(self):
        """Test for DOM-based XSS patterns"""
        vulnerabilities = []

        response = ScannerUtils.make_request(self.url)
        if not response:
            return vulnerabilities

        # Patterns indicating potential DOM XSS
        dangerous_patterns = [
            r'document\.write\s*\(',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'document\.location',
            r'window\.location',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\('
        ]

        # Sources that may lead to XSS
        sources = [
            r'location\.hash',
            r'location\.search',
            r'document\.URL',
            r'document\.documentURI',
            r'document\.referrer'
        ]

        found_dangerous = []
        found_sources = []

        for pattern in dangerous_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                found_dangerous.append(pattern)

        for source in sources:
            if re.search(source, response.text, re.IGNORECASE):
                found_sources.append(source)

        if found_dangerous and found_sources:
            print(f"   ⚠️ Potential DOM-based XSS patterns detected")
            vulnerabilities.append({
                'type': 'Potential DOM XSS',
                'dangerous_sinks': found_dangerous,
                'sources': found_sources
            })
        else:
            print("   ✅ No obvious DOM XSS patterns")

        return vulnerabilities

    def analyze_risk(self):
        """Analyze vulnerabilities and calculate risk"""
        reflected = len(self.results.get('reflected_xss', []))
        form_xss = len(self.results.get('form_xss', []))
        dom_xss = len(self.results.get('dom_xss', []))

        total_vulns = reflected + form_xss + dom_xss

        self.results['is_vulnerable'] = total_vulns > 0
        self.results['total_vulnerabilities'] = total_vulns

        issues = []
        protections = []

        if reflected > 0:
            issues.append(f"{reflected} Reflected XSS vulnerabilities found")

        if form_xss > 0:
            issues.append(f"{form_xss} Form XSS vulnerabilities found")

        if dom_xss > 0:
            issues.append(f"{dom_xss} Potential DOM-based XSS patterns found")

        if total_vulns == 0:
            protections.append("No XSS vulnerabilities detected")
            self.results['risk_level'] = 'Low'
            self.results['cvss_score'] = 0.0
            self.results['protection_score'] = 100
            self.results['assessment'] = '✅ NO XSS VULNERABILITIES'
        elif total_vulns <= 2:
            self.results['risk_level'] = 'Medium'
            self.results['cvss_score'] = 6.1
            self.results['protection_score'] = 40
            self.results['assessment'] = '⚠️ XSS VULNERABILITIES FOUND'
        else:
            self.results['risk_level'] = 'High'
            self.results['cvss_score'] = 7.5
            self.results['protection_score'] = 20
            self.results['assessment'] = '🔴 MULTIPLE XSS VULNERABILITIES'

        self.results['issues'] = issues
        self.results['protections'] = protections

    def save_report(self, filename=None):
        """Save detailed report"""
        if filename is None:
            timestamp = ScannerUtils.generate_timestamp()
            filename = f"xss_report_{self.domain}_{timestamp}.md"

        # Generate report
        report = f"""# 🔴 XSS Vulnerability Scan Report

**Scan Time:** {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}
**Target:** {self.url}
**Assessment:** {self.results['assessment']}

---

## Vulnerabilities Found

### Reflected XSS: {len(self.results.get('reflected_xss', []))}
"""

        for vuln in self.results.get('reflected_xss', []):
            report += f"""
- **Parameter:** `{vuln['parameter']}`
- **Payload:** `{vuln['payload']}`
- **URL:** `{vuln['url']}`
"""

        report += f"""

### Form XSS: {len(self.results.get('form_xss', []))}
"""

        for vuln in self.results.get('form_xss', []):
            report += f"""
- **Form Action:** `{vuln['form_action']}`
- **Parameter:** `{vuln['parameter']}`
- **Payload:** `{vuln['payload']}`
"""

        report += f"""

### DOM-based XSS: {len(self.results.get('dom_xss', []))}
"""

        for vuln in self.results.get('dom_xss', []):
            report += f"""
- **Type:** {vuln['type']}
- **Dangerous Sinks:** {', '.join(vuln.get('dangerous_sinks', []))}
- **Sources:** {', '.join(vuln.get('sources', []))}
"""

        report += """

---

## Remediation

### Input Validation:
```javascript
// Sanitize user input
function sanitizeInput(input) {
  const div = document.createElement('div');
  div.textContent = input;
  return div.innerHTML;
}
```

### Output Encoding:
```javascript
// HTML entity encode
function encodeHTML(str) {
  return str.replace(/[&<>"']/g, function(m) {
    return {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    }[m];
  });
}
```

### Content Security Policy:
```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; object-src 'none';" always;
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
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("🔍 Enter URL to scan: ").strip()

    if not url:
        print("❌ Please provide a URL!")
        return

    scanner = XSSScanner(url)

    if not scanner.scan():
        return

    ScannerUtils.print_result_summary(scanner.results)

    save = input("💾 Save detailed report? (y/n): ").strip().lower()
    if save in ['y', 'yes', 'có']:
        scanner.save_report()

if __name__ == "__main__":
    main()
