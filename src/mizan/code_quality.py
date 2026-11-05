import subprocess
import json
import os
import sys

class CodeQualityScanner:
    def __init__(self, target_dir="."):
        self.target_dir = target_dir

    def run_eslint(self):
        print("⚖️ [MIZAN] بدء فحص جودة الكود باستخدام ESLint...")
        
        # إعداد ESLint v9+ (Flat Config)
        eslint_config = os.path.join(self.target_dir, "eslint.config.js")
        if not os.path.exists(eslint_config):
            default_config = """
export default [
    {
        rules: {
            "no-unused-vars": "warn",
            "no-undef": "error",
            "no-console": "off"
        }
    }
];
"""
            with open(eslint_config, 'w') as f:
                f.write(default_config)
            print("✅ تم إنشاء ملف إعدادات ESLint الافتراضي (eslint.config.js).")

        try:
            result = subprocess.run(
                ["npx", "eslint", ".", "--ext", ".js,.jsx,.ts,.tsx", "--format", "json"],
                cwd=self.target_dir,
                capture_output=True,
                text=True
            )
            
            # التحقق من وجود أخطاء تقنية في تشغيل ESLint نفسه
            if result.stderr and not result.stdout:
                print(f"❌ [MIZAN] خطأ في تشغيل ESLint:\n{result.stderr}")
                return False, []

            # تحليل النتائج
            issues = json.loads(result.stdout) if result.stdout else []
            total_errors = sum(item.get("errorCount", 0) for item in issues)
            total_warnings = sum(item.get("warningCount", 0) for item in issues)

            if total_errors > 0 or total_warnings > 0:
                print(f"🚨 [MIZAN] تم اكتشاف مشاكل في جودة الكود: {total_errors} أخطاء، {total_warnings} تحذيرات.")
                return False, issues
            else:
                print("✅ [MIZAN] الكود نظيف، لا توجد مشاكل في الجودة.")
                return True, issues

        except FileNotFoundError:
            print("❌ [MIZAN] خطأ: Node.js أو npx غير مثبت على هذا النظام.")
            return False, []
        except Exception as e:
            print(f"❌ [MIZAN] حدث خطأ غير متوقع: {e}")
            return False, []

if __name__ == "__main__":
    scanner = CodeQualityScanner(target_dir=".")
    success, results = scanner.run_eslint()
    if not success:
        sys.exit(1)
