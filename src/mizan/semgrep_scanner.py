import subprocess
import json

class SemgrepScanner:
    def __init__(self, target_dir="."):
        self.target_dir = target_dir

    def run_semgrep(self):
        print("🌍 [MIZAN] بدء الفحص الأمني متعدد اللغات (Python via Bandit)...")
        return self._run_with_bandit()

    def _run_with_bandit(self):
        try:
            # -q لإخفاء شريط التقدم، -x لاستبعاد المجلدات غير المرغوبة
            result = subprocess.run(
                ["bandit", "-r", self.target_dir, "-f", "json", "-q", "-x", ".venv,venv,node_modules"],
                capture_output=True, text=True
            )
            
            if result.stderr and not result.stdout:
                print(f"❌ [MIZAN] خطأ في Bandit:\n{result.stderr}")
                return False, []

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    results = data.get("results", [])
                    
                    if len(results) > 0:
                        print(f"🚨 [MIZAN] اكتشف Bandit {len(results)} مشاكل/ثغرات في كود Python!")
                        return False, results
                except json.JSONDecodeError:
                    print(f"❌ [MIZAN] فشل في قراءة نتائج Bandit. المخرجات الخام:\n{result.stdout[:200]}")
                    return False, []
                    
            print("✅ [MIZAN] لم يكتشف Bandit أي مشاكل في Python.")
            return True, []

        except FileNotFoundError:
            print("❌ [MIZAN] خطأ: أداة Bandit غير مثبتة.")
            return False, []
        except Exception as e:
            print(f"❌ [MIZAN] حدث خطأ غير متوقع في Bandit: {e}")
            return False, []
