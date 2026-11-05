from src.mizan.code_quality import CodeQualityScanner
from src.mizan.semgrep_scanner import SemgrepScanner
import sys
import os

def main():
    print("========================================")
    print("       ⚖️  نظام MIZAN للتحليل الشامل       ")
    print("========================================\n")

    report_lines = ["## ⚖️ تقرير MIZAN الآلي\n"]

    # 1. فحص الجودة
    print("--- [1/2] فحص جودة الكود (JavaScript/TypeScript) ---")
    quality_scanner = CodeQualityScanner(target_dir=".")
    quality_success, quality_results = quality_scanner.run_eslint()
    
    if quality_success:
        report_lines.append("✅ **جودة الكود:** لا توجد مشاكل.\n")
    else:
        report_lines.append(f"🚨 **جودة الكود:** تم اكتشاف مشاكل. يرجى مراجعة السجلات (Logs).\n")

    print("\n" + "-"*40 + "\n")

    # 2. الفحص الأمني
    print("--- [2/2] فحص الأمان (Python via Bandit) ---")
    security_scanner = SemgrepScanner(target_dir=".")
    security_success, security_results = security_scanner.run_semgrep()

    if security_success:
        report_lines.append("✅ **الفحص الأمني:** لا توجد ثغرات.\n")
    else:
        report_lines.append(f"🚨 **الفحص الأمني:** تم اكتشاف {len(security_results)} مشاكل/ثغرات محتملة.\n")

    print("\n========================================")
    
    # حفظ التقرير
    with open("mizan_report.md", "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))

    if not quality_success or not security_success:
        print("🚨 النتيجة: فشل الفحص. يرجى مراجعة المشاكل أعلاه.")
        sys.exit(1)
    else:
        print("✅ النتيجة: الكود نظيف وآمن. أحسنت!")
        sys.exit(0)

if __name__ == "__main__":
    main()
