#!/usr/bin/env python3
"""
Report Generator for Web Security Scanner
Tạo và xuất báo cáo dưới nhiều format (JSON, Markdown, HTML, CSV)
"""

import json
from datetime import datetime
import os

class ReportGenerator:
    """Tạo báo cáo tổng hợp từ nhiều scanner"""

    def __init__(self):
        self.scan_results = []
        self.start_time = datetime.now()
        self.end_time = None

    def add_scan_result(self, result):
        """Thêm kết quả từ một scanner"""
        self.scan_results.append(result)

    def finalize(self):
        """Hoàn tất scan"""
        self.end_time = datetime.now()

    def get_summary(self):
        """Lấy tóm tắt kết quả"""
        total_scanners = len(self.scan_results)
        vulnerable_count = sum(1 for r in self.scan_results if r.get('is_vulnerable', False))

        # Calculate overall score
        scores = [r.get('protection_score', 0) for r in self.scan_results]
        avg_score = sum(scores) / len(scores) if scores else 0

        # Get highest CVSS
        cvss_scores = [r.get('cvss_score', 0.0) for r in self.scan_results]
        max_cvss = max(cvss_scores) if cvss_scores else 0.0

        # Count by severity
        critical_count = sum(1 for r in self.scan_results if r.get('risk_level') == 'Critical')
        high_count = sum(1 for r in self.scan_results if r.get('risk_level') == 'High')
        medium_count = sum(1 for r in self.scan_results if r.get('risk_level') == 'Medium')
        low_count = sum(1 for r in self.scan_results if r.get('risk_level') == 'Low')

        return {
            'total_scanners': total_scanners,
            'vulnerable_count': vulnerable_count,
            'safe_count': total_scanners - vulnerable_count,
            'overall_score': round(avg_score, 1),
            'max_cvss': max_cvss,
            'critical_count': critical_count,
            'high_count': high_count,
            'medium_count': medium_count,
            'low_count': low_count,
            'scan_duration': str(self.end_time - self.start_time) if self.end_time else 'N/A'
        }

    def to_json(self, filename=None):
        """Xuất báo cáo JSON"""
        self.finalize()

        report_data = {
            'scan_time': self.start_time.isoformat(),
            'scan_duration': str(self.end_time - self.start_time) if self.end_time else 'N/A',
            'summary': self.get_summary(),
            'results': self.scan_results
        }

        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            return filename
        else:
            return json.dumps(report_data, indent=2, ensure_ascii=False)

    def to_markdown(self, filename=None, target_url=None):
        """Xuất báo cáo Markdown tổng hợp"""
        self.finalize()
        summary = self.get_summary()

        report = f"""# 🛡️ Web Security Scan Report

**Scan Time:** {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}
**Scan Duration:** {summary['scan_duration']}
**Target:** {target_url or 'N/A'}

---

## 📊 Executive Summary

| Metric | Value |
|--------|-------|
| Total Scanners | {summary['total_scanners']} |
| Vulnerable | 🔴 {summary['vulnerable_count']} |
| Safe | ✅ {summary['safe_count']} |
| Overall Security Score | {summary['overall_score']}/100 |
| Highest CVSS Score | {summary['max_cvss']} |

### Issues by Severity:

| Severity | Count |
|----------|-------|
| 🔴 Critical | {summary['critical_count']} |
| 🟠 High | {summary['high_count']} |
| 🟡 Medium | {summary['medium_count']} |
| 🔵 Low | {summary['low_count']} |

---

## 📋 Detailed Results

"""

        # Sắp xếp theo CVSS score (cao nhất trước)
        sorted_results = sorted(
            self.scan_results,
            key=lambda x: x.get('cvss_score', 0.0),
            reverse=True
        )

        for idx, result in enumerate(sorted_results, 1):
            scanner_name = result.get('scanner_name', 'Unknown')
            is_vuln = result.get('is_vulnerable', False)
            status_icon = "🔴" if is_vuln else "✅"
            risk = result.get('risk_level', 'N/A')
            cvss = result.get('cvss_score', 0.0)
            score = result.get('protection_score', 0)

            report += f"""### {idx}. {status_icon} {scanner_name}

**Status:** {"VULNERABLE" if is_vuln else "SAFE"}
**Risk Level:** {risk}
**CVSS Score:** {cvss}
**Protection Score:** {score}/100

"""

            # Issues
            if result.get('issues'):
                report += "**Issues Found:**\n"
                for issue in result['issues']:
                    report += f"- ❌ {issue}\n"
                report += "\n"

            # Protections
            if result.get('protections'):
                report += "**Protections:**\n"
                for prot in result['protections'][:3]:
                    report += f"- ✅ {prot}\n"
                report += "\n"

            report += "---\n\n"

        # Recommendations
        report += """## 🎯 Recommendations

"""

        if summary['critical_count'] > 0:
            report += f"""### 🔴 CRITICAL - Fix Immediately

{summary['critical_count']} critical issues found. These pose immediate risk and should be fixed ASAP.

"""

        if summary['high_count'] > 0:
            report += f"""### 🟠 HIGH - Fix Soon

{summary['high_count']} high severity issues found. Schedule fixes within this week.

"""

        if summary['medium_count'] > 0:
            report += f"""### 🟡 MEDIUM - Fix When Possible

{summary['medium_count']} medium severity issues. Include in next sprint.

"""

        # Overall recommendation
        if summary['overall_score'] >= 80:
            report += "\n✅ **Overall Assessment:** Good security posture. Maintain current protections.\n"
        elif summary['overall_score'] >= 60:
            report += "\n⚠️ **Overall Assessment:** Fair security. Address high/medium issues.\n"
        else:
            report += "\n🔴 **Overall Assessment:** Poor security posture. Immediate action required.\n"

        report += f"""

---

**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Tool:** Web Security Scanner v1.0
"""

        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(report)
            return filename
        else:
            return report

    def to_csv(self, filename):
        """Xuất báo cáo CSV"""
        import csv

        self.finalize()

        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Header
            writer.writerow([
                'Scanner Name',
                'Status',
                'Risk Level',
                'CVSS Score',
                'Protection Score',
                'Issues Count',
                'Issues Details'
            ])

            # Data rows
            for result in self.scan_results:
                writer.writerow([
                    result.get('scanner_name', 'Unknown'),
                    'Vulnerable' if result.get('is_vulnerable') else 'Safe',
                    result.get('risk_level', 'N/A'),
                    result.get('cvss_score', 0.0),
                    result.get('protection_score', 0),
                    len(result.get('issues', [])),
                    '; '.join(result.get('issues', []))
                ])

        return filename

    def to_html(self, filename):
        """Xuất báo cáo HTML"""
        self.finalize()
        summary = self.get_summary()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Security Scan Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            color: #666;
            font-size: 14px;
        }}
        .summary-card .value {{
            font-size: 32px;
            font-weight: bold;
            color: #333;
        }}
        .result-card {{
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .vulnerable {{ border-left: 4px solid #e74c3c; }}
        .safe {{ border-left: 4px solid #2ecc71; }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
        }}
        .badge-critical {{ background: #e74c3c; color: white; }}
        .badge-high {{ background: #e67e22; color: white; }}
        .badge-medium {{ background: #f39c12; color: white; }}
        .badge-low {{ background: #3498db; color: white; }}
        .badge-info {{ background: #95a5a6; color: white; }}
        ul {{ list-style: none; padding: 0; }}
        ul li {{ padding: 5px 0; }}
        .issue {{ color: #e74c3c; }}
        .protection {{ color: #2ecc71; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Web Security Scan Report</h1>
        <p>Scan Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Duration: {summary['scan_duration']}</p>
    </div>

    <div class="summary">
        <div class="summary-card">
            <h3>Overall Score</h3>
            <div class="value">{summary['overall_score']}/100</div>
        </div>
        <div class="summary-card">
            <h3>Total Scanners</h3>
            <div class="value">{summary['total_scanners']}</div>
        </div>
        <div class="summary-card">
            <h3>Vulnerable</h3>
            <div class="value" style="color: #e74c3c;">{summary['vulnerable_count']}</div>
        </div>
        <div class="summary-card">
            <h3>Safe</h3>
            <div class="value" style="color: #2ecc71;">{summary['safe_count']}</div>
        </div>
    </div>

    <h2>Detailed Results</h2>
"""

        # Sorted results
        sorted_results = sorted(
            self.scan_results,
            key=lambda x: x.get('cvss_score', 0.0),
            reverse=True
        )

        for result in sorted_results:
            scanner_name = result.get('scanner_name', 'Unknown')
            is_vuln = result.get('is_vulnerable', False)
            risk = result.get('risk_level', 'Low')
            cvss = result.get('cvss_score', 0.0)
            score = result.get('protection_score', 0)

            card_class = 'vulnerable' if is_vuln else 'safe'
            badge_class = f'badge-{risk.lower()}'

            html += f"""
    <div class="result-card {card_class}">
        <h3>{scanner_name}</h3>
        <p>
            <span class="badge {badge_class}">{risk}</span>
            CVSS: {cvss} | Protection Score: {score}/100
        </p>
"""

            if result.get('issues'):
                html += "<h4>Issues:</h4><ul>"
                for issue in result['issues']:
                    html += f'<li class="issue">❌ {issue}</li>'
                html += "</ul>"

            if result.get('protections'):
                html += "<h4>Protections:</h4><ul>"
                for prot in result['protections'][:3]:
                    html += f'<li class="protection">✅ {prot}</li>'
                html += "</ul>"

            html += "</div>"

        html += """
</body>
</html>
"""

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)

        return filename

# Export
__all__ = ['ReportGenerator']
