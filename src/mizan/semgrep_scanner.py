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
            # أضفنا استبعاداً لملفات MIZAN نفسها حتى لا تفحص نفسها
            result = subprocess.run(
                ["bandit", "-r", self.target_dir, "-f", "sarif", "-o", "bandit_results.sarif", "-q", 
                 "-x", ".venv,venv,node_modules,run_mizan.py,src/mizan/"],
                capture_output=True, text=True
            )
            
            print("✅ [MIZAN] تم الانتهاء من فحص Bandit وتوليد تقرير SARIF.")
            
            with open("bandit_results.sarif", "r") as f:
                sarif_data = json.load(f)
                runs = sarif_data.get("runs", [])
                if runs and len(runs[0].get("results", [])) > 0:
                    print(f"🚨 [MIZAN] اكتشف Bandit ثغرات! (يرجى مراجعة تبويب الأمان في GitHub)")
                    return False, runs[0]["results"]
            
            return True, []

        except FileNotFoundError:
            print("❌ [MIZAN] خطأ: أداة Bandit غير مثبتة.")
            return False, []
        except Exception as e:
            print(f"❌ [MIZAN] حدث خطأ غير متوقع في Bandit: {e}")
            return False, []
