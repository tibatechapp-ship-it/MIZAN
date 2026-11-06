import os
import smtplib
import ssl
from email.message import EmailMessage

def send_email_report():
    """Send the scan report by email (requires SMTP configuration)."""
    sender_email = os.environ.get("GMAIL_USERNAME")
    app_password = os.environ.get("GMAIL_APP_PASSWORD")
    receiver_email = sender_email # سنرسل لنفس البريد

    if not sender_email or not app_password:
        print("⚠️ لم يتم تعيين بيانات Gmail. سيتم تخطي إرسال البريد.")
        return

    report_content = "لم يتم العثور على تقرير."
    if os.path.exists("mizan_report.md"):
        with open("mizan_report.md", "r", encoding="utf-8") as f:
            report_content = f.read()

    msg = EmailMessage()
    msg.set_content(report_content)
    msg["Subject"] = "⚖️ تقرير MIZAN الآلي"
    msg["From"] = sender_email
    msg["To"] = receiver_email

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, app_password)
            server.send_message(msg)
        print("✅ تم إرسال تقرير MIZAN إلى بريدك الإلكتروني بنجاح.")
    except Exception as e:
        print(f"❌ فشل إرسال البريد: {e}")

if __name__ == "__main__":
    send_email_report()
