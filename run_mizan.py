from src.mizan.code_quality import CodeQualityScanner
from src.mizan.semgrep_scanner import SemgrepScanner
import sys

def main():
    print("========================================")
    print("       ⚖️  نظام MIZAN للتحليل الشامل       ")
    print("========================================\n")

    print("--- [1/2] فحص جودة الكود (JavaScript/TypeScript) ---")
    quality_scanner = CodeQualityScanner(target_dir=".")
    quality_success, _ = quality_scanner.run_eslint()
    
    print("\n" + "-"*40 + "\n")

    print("--- [2/2] فحص الأمان متعدد اللغات (Semgrep) ---")
    security_scanner = SemgrepScanner(target_dir=".")
    security_success, _ = security_scanner.run_semgrep()

    print("\n========================================")
    if not quality_success or not security_success:
        print("🚨 النتيجة: فشل الفحص. يرجى مراجعة المشاكل أعلاه.")
        sys.exit(1)
    else:
        print("✅ النتيجة: الكود نظيف وآمن. أحسنت!")
        sys.exit(0)

if __name__ == "__main__":
    main()
