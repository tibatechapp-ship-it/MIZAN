import json
import os
import re

def remove_secrets():
    print("🛡️ [MIZAN] بدء عملية الحذف التلقائي للأسرار...")
    
    if not os.path.exists("ggshield-results.json"):
        print("⚠️ لم يتم العثور على تقرير GitGuardian.")
        return

    with open("ggshield-results.json", "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print("❌ فشل في قراءة ملف JSON الخاص بـ GitGuardian.")
            return

    # GitGuardian قد يُخرج النتائج كقائمة أو قاموس
    findings = data if isinstance(data, list) else data.get("findings", [])

    if not findings:
        print("✅ لا توجد أسرار مسربة لحذفها.")
        return

    for finding in findings:
        # استخراج مسار الملف والسر (حسب هيكل JSON الخاص بـ GitGuardian)
        # قد تختلف التسميات قليلاً، لكننا نغطي الاحتمالات الشائعة
        secret_value = finding.get("match") or finding.get("secret")
        file_path = finding.get("filename") or finding.get("file_path")

        if not secret_value or not file_path:
            continue

        # إزالة "./" إذا وجدت
        if file_path.startswith("./"):
            file_path = file_path[2:]

        if os.path.exists(file_path):
            print(f"🔧 [MIZAN] تم العثور على سر مسرب في {file_path}. جاري الحذف...")
            
            with open(file_path, "r") as code_file:
                content = code_file.read()
            
            # استبدال المفتاح بنص آمن
            safe_content = content.replace(secret_value, "[REDACTED_BY_MIZAN]")
            
            if content != safe_content:
                with open(file_path, "w") as code_file:
                    code_file.write(safe_content)
                print(f"✅ [MIZAN] تم حذف المفتاح من {file_path} بنجاح!")
            else:
                print(f"ℹ️ [MIZAN] لم يتم العثور على المفتاح حرفياً في الملف (قد يكون مشفراً أو بصيغة مختلفة).")

if __name__ == "__main__":
    remove_secrets()
