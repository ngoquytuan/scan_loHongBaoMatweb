#!/usr/bin/env python3
"""
Core utilities for Web Security Scanner
Các hàm tiện ích dùng chung cho tất cả scanners
"""

import requests
from urllib.parse import urlparse, urljoin
from datetime import datetime
import logging
import time

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class ScannerUtils:
    """Utilities class for all scanners"""

    @staticmethod
    def normalize_url(url):
        """Chuẩn hóa URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')

    @staticmethod
    def get_domain(url):
        """Lấy domain từ URL"""
        return urlparse(url).netloc

    @staticmethod
    def make_request(url, method='GET', headers=None, data=None, params=None,
                     timeout=10, allow_redirects=True, verify=True):
        """
        Gửi HTTP request với error handling

        Returns:
            response object hoặc None nếu lỗi
        """
        try:
            if headers is None:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }

            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                params=params,
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=verify
            )
            return response
        except requests.exceptions.Timeout:
            logging.error(f"Timeout khi kết nối đến {url}")
            return None
        except requests.exceptions.ConnectionError:
            logging.error(f"Connection error đến {url}")
            return None
        except requests.exceptions.SSLError as e:
            logging.error(f"SSL Error: {e}")
            return None
        except Exception as e:
            logging.error(f"Lỗi không xác định: {e}")
            return None

    @staticmethod
    def safe_request(url, method='GET', **kwargs):
        """
        Wrapper an toàn hơn cho make_request với retry logic
        """
        max_retries = 3
        retry_delay = 2

        for attempt in range(max_retries):
            response = ScannerUtils.make_request(url, method, **kwargs)
            if response is not None:
                return response

            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                logging.info(f"Retry {attempt + 1}/{max_retries}...")

        return None

    @staticmethod
    def is_url_accessible(url):
        """Kiểm tra URL có accessible không"""
        response = ScannerUtils.make_request(url, timeout=5)
        return response is not None and response.status_code < 500

    @staticmethod
    def extract_forms(html_content, base_url):
        """
        Trích xuất tất cả forms từ HTML

        Returns:
            List of form dictionaries
        """
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html_content, 'html.parser')
        forms = []

        for form in soup.find_all('form'):
            form_details = {
                'action': form.get('action', ''),
                'method': (form.get('method', 'GET')).upper(),
                'inputs': []
            }

            # Normalize action URL
            if form_details['action']:
                form_details['action'] = urljoin(base_url, form_details['action'])
            else:
                form_details['action'] = base_url

            # Extract inputs
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name', '')
                input_value = input_tag.get('value', '')

                if input_name:
                    form_details['inputs'].append({
                        'type': input_type,
                        'name': input_name,
                        'value': input_value
                    })

            forms.append(form_details)

        return forms

    @staticmethod
    def calculate_cvss_score(severity, exploitability=1.0, impact=1.0):
        """
        Tính CVSS score đơn giản

        Args:
            severity: 'Critical', 'High', 'Medium', 'Low', 'Info'
            exploitability: 0.0 - 1.0
            impact: 0.0 - 1.0
        """
        base_scores = {
            'Critical': 9.0,
            'High': 7.0,
            'Medium': 5.0,
            'Low': 3.0,
            'Info': 0.0
        }

        base = base_scores.get(severity, 0.0)
        return round(base * exploitability * impact, 1)

    @staticmethod
    def generate_timestamp():
        """Tạo timestamp cho filename"""
        return datetime.now().strftime('%Y%m%d_%H%M%S')

    @staticmethod
    def sanitize_filename(filename):
        """Sanitize filename để an toàn"""
        import re
        # Remove invalid characters
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        return filename

    @staticmethod
    def load_payloads(payload_file):
        """
        Load payloads từ file

        Returns:
            List of payloads
        """
        import os

        try:
            file_path = os.path.join(
                os.path.dirname(__file__),
                'payloads',
                payload_file
            )

            if not os.path.exists(file_path):
                logging.warning(f"Payload file không tồn tại: {file_path}")
                return []

            with open(file_path, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]

            return payloads
        except Exception as e:
            logging.error(f"Lỗi khi load payloads: {e}")
            return []

    @staticmethod
    def print_banner(scanner_name):
        """In banner cho scanner"""
        print("=" * 70)
        print(f"🛡️  {scanner_name.upper()}")
        print("=" * 70)
        print()

    @staticmethod
    def print_result_summary(results):
        """In tóm tắt kết quả"""
        print("\n" + "=" * 70)
        print("📊 TÓM TẮT KẾT QUẢ")
        print("=" * 70)
        print(f"Scanner: {results.get('scanner_name', 'Unknown')}")
        print(f"URL: {results.get('url', 'N/A')}")
        print(f"Đánh giá: {results.get('assessment', 'N/A')}")
        print(f"Mức độ rủi ro: {results.get('risk_level', 'N/A')}")
        print(f"Điểm bảo mật: {results.get('protection_score', 0)}/100")
        print(f"CVSS Score: {results.get('cvss_score', 0.0)}")

        if results.get('is_vulnerable'):
            print("\n🔴 PHÁT HIỆN LỖ HỔNG!")
            if results.get('issues'):
                print("\nVấn đề:")
                for issue in results['issues']:
                    print(f"  ❌ {issue}")
        else:
            print("\n✅ AN TOÀN!")
            if results.get('protections'):
                print("\nĐiểm mạnh:")
                for prot in results['protections'][:3]:
                    print(f"  ✅ {prot}")

        print("=" * 70 + "\n")

class RateLimiter:
    """Rate limiter để tránh spam requests"""

    def __init__(self, max_requests_per_second=10):
        self.max_requests = max_requests_per_second
        self.requests = []

    def wait_if_needed(self):
        """Chờ nếu đã vượt quá rate limit"""
        now = time.time()

        # Remove requests older than 1 second
        self.requests = [req_time for req_time in self.requests if now - req_time < 1.0]

        if len(self.requests) >= self.max_requests:
            sleep_time = 1.0 - (now - self.requests[0])
            if sleep_time > 0:
                time.sleep(sleep_time)

        self.requests.append(time.time())

class PayloadEncoder:
    """Encoder cho payloads"""

    @staticmethod
    def url_encode(payload):
        """URL encode payload"""
        from urllib.parse import quote
        return quote(payload)

    @staticmethod
    def double_url_encode(payload):
        """Double URL encode"""
        from urllib.parse import quote
        return quote(quote(payload))

    @staticmethod
    def html_encode(payload):
        """HTML entity encode"""
        import html
        return html.escape(payload)

    @staticmethod
    def base64_encode(payload):
        """Base64 encode"""
        import base64
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def unicode_encode(payload):
        """Unicode escape encode"""
        return payload.encode('unicode_escape').decode()

# Export các classes và functions chính
__all__ = [
    'ScannerUtils',
    'RateLimiter',
    'PayloadEncoder'
]
