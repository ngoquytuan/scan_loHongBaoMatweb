#!/usr/bin/env python3
"""
scanSQLi.py
SQL Injection Vulnerability Scanner
Quét lỗ hổng SQL Injection
"""

import sys
import os
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.utils import ScannerUtils, RateLimiter

class SQLiScanner:
    def __init__(self, url):
        self.url = ScannerUtils.normalize_url(url)
        self.domain = ScannerUtils.get_domain(url)
        self.scan_time = datetime.now()
        self.results = {
            'scanner_name': 'SQL Injection Scanner',
            'url': self.url,
            'scan_time': self.scan_time.isoformat()
        }
        self.rate_limiter = RateLimiter(max_requests_per_second=3)

        # SQL error patterns
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your MySQL",
            r"ORA-\d{5}",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_",
            r"valid PostgreSQL result",
            r"Microsoft SQL Server",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"Incorrect syntax near",
            r"Unclosed quotation mark",
            r"quoted string not properly terminated"
        ]

    def scan(self):
        ScannerUtils.print_banner("SQL Injection Scanner")
        print(f"🔍 Target: {self.url}\n")

        try:
            print("📤 Test 1: Error-based SQL Injection...")
            error_based = self.test_error_based()

            print("\n📤 Test 2: Boolean-based SQL Injection...")
            boolean_based = self.test_boolean_based()

            self.results['error_based'] = error_based
            self.results['boolean_based'] = boolean_based

            self.analyze_risk()

            print(f"\n{'='*70}")
            print("✅ QUÉT HOÀN TẤT")
            print(f"{'='*70}\n")

            return True

        except Exception as e:
            print(f"❌ Lỗi: {e}")
            return False

    def test_error_based(self):
        """Test error-based SQL injection"""
        vulnerabilities = []

        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        if not params:
            print("   ℹ️ No URL parameters to test")
            return vulnerabilities

        payloads = ["'", '"', "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "' AND 1=2--"]

        for param_name in params.keys():
            print(f"   Testing parameter: {param_name}")

            for payload in payloads:
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
                    for pattern in self.error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            print(f"      ❌ VULNERABLE: SQL error detected")
                            vulnerabilities.append({
                                'type': 'Error-based SQLi',
                                'parameter': param_name,
                                'payload': payload,
                                'error_pattern': pattern
                            })
                            break

                if vulnerabilities:
                    break

        if not vulnerabilities:
            print("   ✅ No error-based SQL injection found")

        return vulnerabilities

    def test_boolean_based(self):
        """Test boolean-based blind SQL injection"""
        vulnerabilities = []

        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)

        if not params:
            return vulnerabilities

        for param_name in params.keys():
            original_value = params[param_name][0]

            # Get baseline response
            baseline_resp = ScannerUtils.make_request(self.url)
            if not baseline_resp:
                continue

            baseline_len = len(baseline_resp.text)

            # Test with true condition
            true_payload = f"{original_value}' AND '1'='1"
            test_params = params.copy()
            test_params[param_name] = [true_payload]

            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))

            true_resp = ScannerUtils.make_request(test_url)

            # Test with false condition
            false_payload = f"{original_value}' AND '1'='2"
            test_params[param_name] = [false_payload]

            new_query = urlencode(test_params, doseq=True)
            test_url_false = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))

            false_resp = ScannerUtils.make_request(test_url_false)

            if true_resp and false_resp:
                true_len = len(true_resp.text)
                false_len = len(false_resp.text)

                # If true response similar to baseline but false is different
                if abs(true_len - baseline_len) < 100 and abs(false_len - baseline_len) > 100:
                    print(f"      ⚠️ Possible boolean-based SQLi in {param_name}")
                    vulnerabilities.append({
                        'type': 'Boolean-based Blind SQLi',
                        'parameter': param_name,
                        'confidence': 'Medium'
                    })

        return vulnerabilities

    def analyze_risk(self):
        error_vulns = len(self.results.get('error_based', []))
        boolean_vulns = len(self.results.get('boolean_based', []))

        total = error_vulns + boolean_vulns

        self.results['is_vulnerable'] = total > 0
        self.results['total_vulnerabilities'] = total

        issues = []
        protections = []

        if error_vulns > 0:
            issues.append(f"{error_vulns} Error-based SQL Injection found")

        if boolean_vulns > 0:
            issues.append(f"{boolean_vulns} Possible Boolean-based SQLi found")

        if total == 0:
            protections.append("No SQL Injection vulnerabilities detected")
            self.results['risk_level'] = 'Low'
            self.results['cvss_score'] = 0.0
            self.results['protection_score'] = 100
            self.results['assessment'] = '✅ NO SQL INJECTION'
        else:
            self.results['risk_level'] = 'Critical'
            self.results['cvss_score'] = 9.8
            self.results['protection_score'] = 0
            self.results['assessment'] = '🔴 SQL INJECTION VULNERABILITY'

        self.results['issues'] = issues
        self.results['protections'] = protections

def main():
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("🔍 Enter URL: ").strip()

    if not url:
        print("❌ Please provide a URL!")
        return

    scanner = SQLiScanner(url)
    if scanner.scan():
        ScannerUtils.print_result_summary(scanner.results)

if __name__ == "__main__":
    main()
