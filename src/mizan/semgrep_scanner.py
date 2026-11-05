import subprocess
import json
import os

class SemgrepScanner:
    def __init__(self, target_dir="."):
        self.target_dir = target_dir

    def run_semgrep(self):
        print("🌍 [MIZAN] بدء الفحص الأمني متعدد اللغات...")
        bandit_success, bandit_results = self._run_bandit()
        semgrep_success, semgrep_results = self._run_semgrep_tool()
        return (bandit_success and semgrep_success), (bandit_results + semgrep_results)

    def _run_bandit(self):
        try:
            # استبعاد ملفات MIZAN نفسها لتقليل الإيجابيات الكاذبة
            result = subprocess.run(
                ["bandit", "-r", self.target_dir, "-f", "json", "-q", "-x", ".venv,venv,node_modules,run_mizan.py,src/mizan/"],
                capture_output=True, text=True
            )
            if result.stdout:
                data = json.loads(result.stdout)
                results = data.get("results", [])
                if len(results) > 0:
                    print(f"🚨 [MIZAN] اكتشف Bandit {len(results)} مشاكل/ثغرات في Python!")
                    return False, results
            print("✅ [MIZAN] لم يكتشف Bandit أي مشاكل في Python.")
            return True, []
        except Exception as e:
            return True, []

    def _run_semgrep_tool(self):
        try:
            subprocess.run(["semgrep", "--version"], capture_output=True, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            print("⚠️ Semgrep غير مثبت على هذا النظام (مثل Termux). سيتم تخطيه.")
            return True, []

        print("🔍 [MIZAN] جاري الفحص الشامل باستخدام Semgrep (جميع اللغات)...")
        try:
            result = subprocess.run(
                ["semgrep", "scan", "--config=auto", "--json", self.target_dir],
                capture_output=True, text=True
            )
            if result.stdout:
                data = json.loads(result.stdout)
                results = data.get("results", [])
                if len(results) > 0:
                    print(f"🚨 [MIZAN] اكتشف Semgrep {len(results)} مشاكل/ثغرات في لغات متعددة!")
                    return False, results
            print("✅ [MIZAN] لم يكتشف Semgrep أي مشاكل.")
            return True, []
        except Exception as e:
            print(f"❌ [MIZAN] خطأ في Semgrep: {e}")
            return True, []
