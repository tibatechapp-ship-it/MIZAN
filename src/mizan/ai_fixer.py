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
            locations = result.get("locations", [])
            if not locations: continue
            
            file_path = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            
            # إزالة "./" من بداية المسار إذا وجدت
            if file_path.startswith("./"):
                file_path = file_path[2:]

            if rule_id == "B307" and file_path and os.path.exists(file_path):
                print(f"🔧 [MIZAN AI] محاولة إصلاح ثغرة {rule_id} في الملف {file_path}...")
                
                with open(file_path, "r") as code_file:
                    content = code_file.read()
                
                # استبدال eval بـ ast.literal_eval
                safe_content = re.sub(r'\beval\s*\(', 'ast.literal_eval(', content)
                
                # إضافة import ast إذا لم يكن موجوداً
                if 'ast.literal_eval' in safe_content and 'import ast' not in safe_content:
                    safe_content = 'import ast\n' + safe_content
                
                if content != safe_content:
                    with open(file_path, "w") as code_file:
                        code_file.write(safe_content)
                    print(f"✅ [MIZAN AI] تم إصلاح الملف {file_path} بنجاح!")

if __name__ == "__main__":
    fix_vulnerabilities()
