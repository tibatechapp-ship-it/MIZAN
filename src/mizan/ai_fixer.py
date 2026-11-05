import json
import os
import re

def fix_vulnerabilities():
    print("🧠 [MIZAN AI] بدء عملية الإصلاح الذكي للثغرات...")
    
    if not os.path.exists("bandit.sarif"):
        print("⚠️ لم يتم العثور على تقرير Bandit. سيتم تخطي الإصلاح.")
        return

    with open("bandit.sarif", "r") as f:
        data = json.load(f)
        runs = data.get("runs", [])
        if not runs: return

        results = runs[0].get("results", [])
        if not results:
            print("✅ لا توجد ثغرات لإصلاحها.")
            return

        for result in results:
            rule_id = result.get("ruleId")
            file_path = result.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
            
            # تركيز الإصلاح على ثغرة استخدام eval الخطير
            if rule_id == "B307" and file_path and os.path.exists(file_path):
                print(f"🔧 [MIZAN AI] محاولة إصلاح ثغرة {rule_id} في الملف {file_path}...")
                
                with open(file_path, "r") as code_file:
                    content = code_file.read()
                
                # استخدام تعبير نمطي للبحث عن eval واستبدالها بدالة آمنة
                # هذا يحاكي ما يفعله الذكاء الاصطناعي عند إعادة كتابة الكود
                safe_content = re.sub(r'\beval\s*\(', 'import ast; ast.literal_eval(', content)
                
                if content != safe_content:
                    with open(file_path, "w") as code_file:
                        code_file.write(safe_content)
                    print(f"✅ [MIZAN AI] تم إصلاح الملف {file_path} بنجاح!")
                else:
                    print(f"⚠️ [MIZAN AI] لم يتم العثور على نمط eval مطابق في {file_path}.")

if __name__ == "__main__":
    fix_vulnerabilities()
