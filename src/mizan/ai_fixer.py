import json
import os
import re
from urllib.parse import unquote

def normalize_path(path):
    """تحويل أي مسار (URI أو مطلق) إلى مسار نسبي من جذر المشروع."""
    if path.startswith("file://"):
        path = path[7:]
    if os.path.isabs(path):
        parts = path.split(os.sep)
        try:
            idx = parts.index("MIZAN")
            path = os.sep.join(parts[idx+1:])
        except ValueError:
            path = os.sep.join(parts[-2:])
    if path.startswith("./"):
        path = path[2:]
    return unquote(path)

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
            
            raw_path = locations[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            file_path = normalize_path(raw_path)

            if rule_id == "B307" and file_path and os.path.exists(file_path):
                print(f"🔧 [MIZAN AI] محاولة إصلاح ثغرة {rule_id} في الملف {file_path}...")
                
                with open(file_path, "r") as code_file:
                    content = code_file.read()
                
                safe_content = re.sub(r'\beval\s*\(', 'ast.literal_eval(', content)
                
                if 'ast.literal_eval' in safe_content and 'import ast' not in safe_content:
                    safe_content = 'import ast\n' + safe_content
                
                if content != safe_content:
                    with open(file_path, "w") as code_file:
                        code_file.write(safe_content)
                    print(f"✅ [MIZAN AI] تم إصلاح الملف {file_path} بنجاح!")
                else:
                    print(f"ℹ️ [MIZAN AI] لا تغييرات مطلوبة في {file_path}.")

if __name__ == "__main__":
    fix_vulnerabilities()
