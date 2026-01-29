#!/usr/bin/env python3
"""
main.py
Web Security Scanner - Main CLI
Quản lý và chạy tất cả security scanners
"""

import sys
import os
import argparse
import importlib.util
from datetime import datetime

# Add to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.report import ReportGenerator
from core.utils import ScannerUtils

# Available scanners mapping
SCANNERS = {
    # Existing scanners
    'sri': ('scanSRI', 'SRISecurityScanner'),
    'clickjacking': ('scanClickjacking2', 'ClickjackingScanner'),
    'options': ('scanOptions', 'OptionsSecurityScanner'),
    'csrf': ('scanCSRF', 'CSRFSecurityScanner'),
    'headers': ('scanSecurityHeaders', 'SecurityHeadersScanner'),
    'cors': ('scanCORS', 'CORSSecurityScanner'),
    'ssl': ('scanSSL', 'SSLSecurityScanner'),
    'mixed-content': ('scanMixedContent', 'MixedContentScanner'),
    'cookies': ('scanCookies', 'CookieSecurityScanner'),

    # New scanners
    'xss': ('scanners.scanXSS', 'XSSScanner'),
    'sqli': ('scanners.scanSQLi', 'SQLiScanner'),
    'path-traversal': ('scanners.scanPathTraversal', 'PathTraversalScanner'),
    'open-redirect': ('scanners.scanOpenRedirect', 'OpenRedirectScanner'),
    'rate-limit': ('scanners.scanRateLimit', 'RateLimitScanner'),
    'dir-enum': ('scanners.scanDirEnum', 'DirEnumScanner'),
}

# Scanner groups for convenience
SCANNER_GROUPS = {
    'all': list(SCANNERS.keys()),
    'critical': ['xss', 'sqli', 'csrf', 'path-traversal'],
    'headers': ['headers', 'cors', 'clickjacking', 'sri'],
    'config': ['ssl', 'cookies', 'options', 'mixed-content'],
    'injection': ['xss', 'sqli', 'path-traversal'],
    'info': ['dir-enum', 'rate-limit', 'open-redirect'],
}

def print_banner():
    """Print ASCII banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   🛡️  WEB SECURITY SCANNER v2.0                                     ║
║   Comprehensive Web Vulnerability Scanner                           ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""
    print(banner)

def load_scanner(module_name, class_name):
    """Dynamically load scanner module and class"""
    try:
        # Try to import from scanners/ directory first
        if not module_name.startswith('scanners.'):
            module_path = os.path.join(os.path.dirname(__file__), 'scanners', f"{module_name}.py")
            if not os.path.exists(module_path):
                # Try root directory
                module_path = os.path.join(os.path.dirname(__file__), f"{module_name}.py")

            spec = importlib.util.spec_from_file_location(module_name, module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        else:
            # Import from package
            module = importlib.import_module(module_name)

        scanner_class = getattr(module, class_name)
        return scanner_class
    except Exception as e:
        print(f"❌ Error loading {module_name}.{class_name}: {e}")
        return None

def run_scanner(scanner_key, url):
    """Run a single scanner"""
    if scanner_key not in SCANNERS:
        print(f"❌ Unknown scanner: {scanner_key}")
        return None

    module_name, class_name = SCANNERS[scanner_key]
    scanner_class = load_scanner(module_name, class_name)

    if not scanner_class:
        return None

    try:
        scanner = scanner_class(url)

        # Run scan
        if hasattr(scanner, 'scan'):
            scanner.scan()
        elif hasattr(scanner, 'scan_sri'):
            scanner.scan_sri()
        elif hasattr(scanner, 'scan_clickjacking'):
            scanner.scan_clickjacking()
        elif hasattr(scanner, 'scan_options'):
            scanner.scan_options()
        elif hasattr(scanner, 'scan_csrf'):
            scanner.scan_csrf()
        elif hasattr(scanner, 'scan_headers'):
            scanner.scan_headers()
        elif hasattr(scanner, 'scan_cors'):
            scanner.scan_cors()
        elif hasattr(scanner, 'scan_ssl'):
            scanner.scan_ssl()
        elif hasattr(scanner, 'scan_mixed_content'):
            scanner.scan_mixed_content()
        elif hasattr(scanner, 'scan_cookies'):
            scanner.scan_cookies()

        # Return results
        return scanner.results

    except Exception as e:
        print(f"❌ Error running {scanner_key}: {e}")
        import traceback
        traceback.print_exc()
        return None

def main():
    parser = argparse.ArgumentParser(
        description='Web Security Scanner - Comprehensive vulnerability scanning tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan with all scanners
  python main.py --url https://example.com --modules all

  # Scan with specific scanners
  python main.py --url https://example.com --modules xss,sqli,csrf

  # Scan critical vulnerabilities only
  python main.py --url https://example.com --group critical

  # Generate JSON report
  python main.py --url https://example.com --group all --output report.json

  # Generate HTML report
  python main.py --url https://example.com --group all --format html --output report.html

Available Scanners:
  """ + ", ".join(SCANNERS.keys()) + """

Available Groups:
  all:       All scanners
  critical:  XSS, SQLi, CSRF, Path Traversal
  headers:   Security headers related
  config:    Configuration issues
  injection: Injection vulnerabilities
  info:      Information disclosure
        """
    )

    parser.add_argument('--url', '-u', required=True, help='Target URL to scan')
    parser.add_argument('--modules', '-m', help='Comma-separated list of scanners to run')
    parser.add_argument('--group', '-g', choices=list(SCANNER_GROUPS.keys()),
                        help='Run a predefined group of scanners')
    parser.add_argument('--output', '-o', help='Output file path')
    parser.add_argument('--format', '-f', choices=['json', 'markdown', 'html', 'csv'],
                        default='markdown', help='Output format (default: markdown)')
    parser.add_argument('--quiet', '-q', action='store_true', help='Quiet mode (less output)')
    parser.add_argument('--list', '-l', action='store_true', help='List all available scanners')

    args = parser.parse_args()

    # List scanners and exit
    if args.list:
        print("\n📋 Available Scanners:\n")
        for key, (module, _) in SCANNERS.items():
            print(f"  • {key:20s} - {module}")
        print("\n📦 Available Groups:\n")
        for group, scanners in SCANNER_GROUPS.items():
            print(f"  • {group:20s} - {', '.join(scanners[:5])}{'...' if len(scanners) > 5 else ''}")
        return

    if not args.quiet:
        print_banner()

    url = ScannerUtils.normalize_url(args.url)

    # Determine which scanners to run
    scanners_to_run = []

    if args.group:
        scanners_to_run = SCANNER_GROUPS[args.group]
        print(f"📦 Running group: {args.group} ({len(scanners_to_run)} scanners)\n")
    elif args.modules:
        scanners_to_run = [m.strip() for m in args.modules.split(',')]
        print(f"🔧 Running modules: {', '.join(scanners_to_run)}\n")
    else:
        print("❌ Please specify --modules or --group")
        print("   Use --list to see available options")
        return

    # Validate scanners
    invalid = [s for s in scanners_to_run if s not in SCANNERS]
    if invalid:
        print(f"❌ Invalid scanners: {', '.join(invalid)}")
        print("   Use --list to see available scanners")
        return

    # Initialize report generator
    report_gen = ReportGenerator()

    # Run scanners
    print(f"🚀 Starting scan of: {url}")
    print(f"⏰ Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    print("=" * 70 + "\n")

    for idx, scanner_key in enumerate(scanners_to_run, 1):
        print(f"\n[{idx}/{len(scanners_to_run)}] Running: {scanner_key}")
        print("-" * 70)

        result = run_scanner(scanner_key, url)

        if result:
            report_gen.add_scan_result(result)

            # Print quick summary
            if not args.quiet:
                status = "🔴 VULNERABLE" if result.get('is_vulnerable') else "✅ SAFE"
                score = result.get('protection_score', 0)
                print(f"    Status: {status} | Score: {score}/100")
        else:
            print(f"    ⚠️ Scanner failed or returned no results")

    # Finalize and generate report
    report_gen.finalize()

    print("\n" + "=" * 70)
    print("📊 SCAN COMPLETED")
    print("=" * 70 + "\n")

    # Print summary
    summary = report_gen.get_summary()
    print(f"Total Scanners Run:  {summary['total_scanners']}")
    print(f"Vulnerabilities Found: 🔴 {summary['vulnerable_count']}")
    print(f"Safe Scanners:       ✅ {summary['safe_count']}")
    print(f"Overall Score:       {summary['overall_score']}/100")
    print(f"Max CVSS Score:      {summary['max_cvss']}")
    print(f"\nSeverity Breakdown:")
    print(f"  Critical: {summary['critical_count']}")
    print(f"  High:     {summary['high_count']}")
    print(f"  Medium:   {summary['medium_count']}")
    print(f"  Low:      {summary['low_count']}")
    print(f"\nScan Duration:       {summary['scan_duration']}")

    # Generate report
    if args.output:
        print(f"\n📄 Generating {args.format.upper()} report...")

        if args.format == 'json':
            report_gen.to_json(args.output)
        elif args.format == 'markdown':
            report_gen.to_markdown(args.output, target_url=url)
        elif args.format == 'html':
            report_gen.to_html(args.output)
        elif args.format == 'csv':
            report_gen.to_csv(args.output)

        print(f"✅ Report saved to: {args.output}")
    else:
        # Auto-generate report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        domain = ScannerUtils.get_domain(url)
        filename = f"scan_report_{domain}_{timestamp}.md"

        report_gen.to_markdown(filename, target_url=url)
        print(f"\n✅ Auto-generated report: {filename}")

    print("\n" + "=" * 70 + "\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
