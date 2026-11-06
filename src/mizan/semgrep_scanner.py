import subprocess
import json
import os

class SemgrepScanner:
    """Optional multi-language bridge to Bandit/Semgrep when installed."""

    def __init__(self, target_dir="."):
        self.target_dir = target_dir

    def run_semgrep(self):
        print("🌍 [MIZAN] بدء الفحص الأمني متعدد اللغات...")
        bandit_success, bandit_results = self._run_bandit()
        semgrep_success, semgrep_results = self._run_semgrep_tool()
        return (bandit_success and semgrep_success), (bandit_results + semgrep_results)

    def _run_bandit(self):
        try:
            result = subprocess.run(
                ["bandit", "-r", self.target_dir, "-f", "sarif", "-o", "bandit.sarif", "-q", "-x", ".venv,venv,node_modules,run_mizan.py,src/mizan/"],
                capture_output=True, text=True
            )
            if os.path.exists("bandit.sarif"):
                with open("bandit.sarif", "r") as f:
                    data = json.load(f)
                    runs = data.get("runs", [])
                    if runs and len(runs[0].get("results", [])) > 0:
                        print(f"🚨 [MIZAN] اكتشف Bandit {len(runs[0]['results'])} مشاكل/ثغرات في Python!")
                        return False, runs[0]["results"]
            print("✅ [MIZAN] لم يكتشف Bandit أي مشاكل في Python.")
            return True, []
        except Exception as e:
            print(f"❌ [MIZAN] خطأ في Bandit: {e}")
            return True, []

    def _run_semgrep_tool(self):
        try:
            subprocess.run(["semgrep", "--version"], capture_output=True, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            print("⚠️ Semgrep غير مثبت على هذا النظام. سيتم تخطيه.")
            return True, []

        print("🔍 [MIZAN] جاري الفحص الشامل باستخدام Semgrep (جميع اللغات)...")
        try:
            result = subprocess.run(
                ["semgrep", "scan", "--config=auto", "--sarif", "--output", "semgrep.sarif", self.target_dir],
                capture_output=True, text=True
            )
            if os.path.exists("semgrep.sarif"):
                with open("semgrep.sarif", "r") as f:
                    data = json.load(f)
                    runs = data.get("runs", [])
                    if runs and len(runs[0].get("results", [])) > 0:
                        print(f"🚨 [MIZAN] اكتشف Semgrep {len(runs[0]['results'])} مشاكل/ثغرات في لغات متعددة!")
                        return False, runs[0]["results"]
            print("✅ [MIZAN] لم يكتشف Semgrep أي مشاكل.")
            return True, []
        except Exception as e:
            print(f"❌ [MIZAN] خطأ في Semgrep: {e}")
            return True, []
