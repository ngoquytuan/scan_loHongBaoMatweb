#!/usr/bin/env python3
"""
scanOpenRedirect.py
Open Redirect Vulnerability Scanner
"""

import sys
import os
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.utils import ScannerUtils

class OpenRedirectScanner:
    def __init__(self, url):
        self.url = ScannerUtils.normalize_url(url)
        self.domain = ScannerUtils.get_domain(url)
        self.scan_time = datetime.now()
        self.results = {
            'scanner_name': 'Open Redirect Scanner',
            'url': self.url,
            'scan_time': self.scan_time.isoformat()
        }

    def scan(self):
        ScannerUtils.print_banner("Open Redirect Scanner")
        print(f"🔍 Target: {self.url}\n")

        try:
            print("📤 Testing Open Redirect...")
            vulns = self.test_open_redirect()

            self.results['vulnerabilities'] = vulns
            self.analyze_risk()

            print(f"\n{'='*70}\n✅ QUÉT HOÀN TẤT\n{'='*70}\n")
            return True

        except Exception as e:
            print(f"❌ Lỗi: {e}")
            return False

    def test_open_redirect(self):
        vulnerabilities = []

        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        if not params:
            print("   ℹ️ No URL parameters")
            return vulnerabilities

        # Redirect payloads
        evil_domain = "evil.com"
        payloads = [
            f"https://{evil_domain}",
            f"//{evil_domain}",
            f"https://{evil_domain}/",
            f"@{evil_domain}",
            f"https://{evil_domain}%00",
            f"https://{evil_domain}%23",
            f"https://{evil_domain}%2F",
        ]

        # Common redirect parameter names
        redirect_params = ['redirect', 'url', 'next', 'return', 'returnUrl', 'continue', 'dest', 'destination', 'redir', 'redirect_uri']

        for param_name in params.keys():
            if param_name.lower() in redirect_params or 'redirect' in param_name.lower() or 'url' in param_name.lower():
                print(f"   Testing redirect parameter: {param_name}")

                for payload in payloads[:3]:  # Test first 3 payloads
                    test_params = params.copy()
                    test_params[param_name] = [payload]

                    new_query = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))

                    response = ScannerUtils.make_request(test_url, allow_redirects=False)

                    if response:
                        # Check Location header
                        location = response.headers.get('Location', '')
                        if evil_domain in location or location.startswith('//'):
                            print(f"      ❌ VULNERABLE: Redirects to {location}")
                            vulnerabilities.append({
                                'parameter': param_name,
                                'payload': payload,
                                'redirect_location': location
                            })
                            break

        if not vulnerabilities:
            print("   ✅ No Open Redirect found")

        return vulnerabilities

    def analyze_risk(self):
        total = len(self.results.get('vulnerabilities', []))

        self.results['is_vulnerable'] = total > 0
        self.results['total_vulnerabilities'] = total

        if total == 0:
            self.results['risk_level'] = 'Low'
            self.results['cvss_score'] = 0.0
            self.results['protection_score'] = 100
            self.results['assessment'] = '✅ NO OPEN REDIRECT'
            self.results['issues'] = []
            self.results['protections'] = ["No open redirect vulnerabilities"]
        else:
            self.results['risk_level'] = 'Medium'
            self.results['cvss_score'] = 6.1
            self.results['protection_score'] = 30
            self.results['assessment'] = '🔴 OPEN REDIRECT FOUND'
            self.results['issues'] = [f"{total} Open Redirect vulnerabilities"]
            self.results['protections'] = []

def main():
    url = sys.argv[1] if len(sys.argv) > 1 else input("🔍 Enter URL: ").strip()
    if url:
        scanner = OpenRedirectScanner(url)
        if scanner.scan():
            ScannerUtils.print_result_summary(scanner.results)

if __name__ == "__main__":
    main()
