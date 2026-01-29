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

    def save_report(self, filename=None):
        """Save detailed report"""
        if filename is None:
            timestamp = ScannerUtils.generate_timestamp()
            filename = f"ratelimit_report_{self.domain}_{timestamp}.md"

        test = self.results.get('rate_limit_test', {})

        report = f"""# 🚦 Rate Limiting Scan Report

**Scan Time:** {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}
**Target:** {self.url}
**Assessment:** {self.results.get('assessment', 'Unknown')}

---

## Test Results

- **Rate Limiting Detected:** {"✅ Yes" if test.get('blocked', False) else "❌ No"}
- **Blocked at Request:** #{test.get('blocked_at_request', 'N/A')}
- **Total Requests Sent:** {test.get('total_requests_sent', 0)}
- **Average Response Time:** {test.get('avg_response_time', 0):.3f}s

### HTTP Status Codes Received

"""

        status_codes = test.get('status_codes', [])
        if status_codes:
            # Count status codes
            from collections import Counter
            code_counts = Counter(status_codes)
            for code, count in code_counts.items():
                report += f"- **{code}:** {count} requests\n"
        else:
            report += "_No data_\n"

        report += """
---

## Risk Assessment

"""

        report += f"""- **Risk Level:** {self.results.get('risk_level', 'Unknown')}
- **CVSS Score:** {self.results.get('cvss_score', 0.0)}
- **Protection Score:** {self.results.get('protection_score', 0)}/100

"""

        issues = self.results.get('issues', [])
        if issues:
            report += "### ❌ Issues Found\n\n"
            for issue in issues:
                report += f"- {issue}\n"
        else:
            report += "### ✅ Protections Detected\n\n"
            for protection in self.results.get('protections', []):
                report += f"- {protection}\n"

        report += """
---

## Remediation

### Implement Rate Limiting

**Nginx (nginx.conf):**
```nginx
limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;

server {
    location /api/ {
        limit_req zone=mylimit burst=20 nodelay;
        limit_req_status 429;
    }
}
```

**Express.js (Node.js):**
```javascript
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);
```

**Django (Python):**
```python
# settings.py
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle'
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '100/hour',
        'user': '1000/hour'
    }
}
```

**Apache (.htaccess with mod_ratelimit):**
```apache
<Location "/api">
    SetOutputFilter RATE_LIMIT
    SetEnv rate-limit 400
</Location>
```

### Best Practices

1. **Progressive delays** - Increase delay time after each failed attempt
2. **CAPTCHA** - Require CAPTCHA after N failed attempts
3. **Account lockout** - Temporarily lock accounts after failed logins
4. **IP-based limiting** - Limit requests per IP address
5. **Monitor & Alert** - Log and alert on suspicious activity

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
        scanner = RateLimitScanner(url)
        if scanner.scan():
            ScannerUtils.print_result_summary(scanner.results)

            # Ask to save report
            save = input("\n💾 Lưu báo cáo? (y/n): ").strip().lower()
            if save in ['y', 'yes', 'có']:
                scanner.save_report()

if __name__ == "__main__":
    main()
