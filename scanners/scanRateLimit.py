#!/usr/bin/env python3
"""
scanRateLimit.py
Rate Limiting & Brute-Force Protection Scanner
"""

import sys
import os
from datetime import datetime
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.utils import ScannerUtils

class RateLimitScanner:
    def __init__(self, url):
        self.url = ScannerUtils.normalize_url(url)
        self.domain = ScannerUtils.get_domain(url)
        self.scan_time = datetime.now()
        self.results = {
            'scanner_name': 'Rate Limit Scanner',
            'url': self.url,
            'scan_time': self.scan_time.isoformat()
        }

    def scan(self):
        ScannerUtils.print_banner("Rate Limiting Scanner")
        print(f"🔍 Target: {self.url}\n")

        try:
            print("📤 Testing Rate Limiting (sending multiple requests)...")
            test_result = self.test_rate_limit()

            self.results['rate_limit_test'] = test_result
            self.analyze_risk()

            print(f"\n{'='*70}\n✅ QUÉT HOÀN TẤT\n{'='*70}\n")
            return True

        except Exception as e:
            print(f"❌ Lỗi: {e}")
            return False

    def test_rate_limit(self, num_requests=20):
        """Send multiple requests to test rate limiting"""
        print(f"   Sending {num_requests} requests...")

        status_codes = []
        response_times = []
        blocked = False
        blocked_at = None

        for i in range(num_requests):
            start_time = time.time()
            response = ScannerUtils.make_request(self.url)
            end_time = time.time()

            if response:
                status_codes.append(response.status_code)
                response_times.append(end_time - start_time)

                # Check for rate limit indicators
                if response.status_code == 429:
                    blocked = True
                    blocked_at = i + 1
                    print(f"      ⚠️ Request {i+1}: 429 Too Many Requests (Rate Limited!)")
                    break
                elif response.status_code in [403, 503]:
                    if 'rate' in response.text.lower() or 'limit' in response.text.lower():
                        blocked = True
                        blocked_at = i + 1
                        print(f"      ⚠️ Request {i+1}: {response.status_code} (Possible Rate Limit)")
                        break

            time.sleep(0.1)  # Small delay

        if blocked:
            print(f"   ✅ Rate limiting DETECTED at request #{blocked_at}")
        else:
            print(f"   ❌ No rate limiting detected after {num_requests} requests")

        return {
            'blocked': blocked,
            'blocked_at_request': blocked_at,
            'total_requests_sent': len(status_codes),
            'status_codes': status_codes,
            'avg_response_time': sum(response_times) / len(response_times) if response_times else 0
        }

    def analyze_risk(self):
        test = self.results.get('rate_limit_test', {})
        has_rate_limit = test.get('blocked', False)

        self.results['is_vulnerable'] = not has_rate_limit

        if has_rate_limit:
            self.results['risk_level'] = 'Low'
            self.results['cvss_score'] = 0.0
            self.results['protection_score'] = 100
            self.results['assessment'] = '✅ RATE LIMITING ENABLED'
            self.results['issues'] = []
            self.results['protections'] = [f"Rate limit triggered at request #{test.get('blocked_at_request')}"]
        else:
            self.results['risk_level'] = 'Medium'
            self.results['cvss_score'] = 5.3
            self.results['protection_score'] = 0
            self.results['assessment'] = '⚠️ NO RATE LIMITING'
            self.results['issues'] = ["No rate limiting detected - vulnerable to brute-force"]
            self.results['protections'] = []

def main():
    url = sys.argv[1] if len(sys.argv) > 1 else input("🔍 Enter URL: ").strip()
    if url:
        scanner = RateLimitScanner(url)
        if scanner.scan():
            ScannerUtils.print_result_summary(scanner.results)

if __name__ == "__main__":
    main()
