# سياسة الأمان — Security Policy

> العربية أولاً، والإنجليزية أدناه · Arabic first, English below.

---

## الإصدارات المدعومة | Supported Versions

| الإصدار | مدعوم |
|---|---|
| 0.7.x+ | ✅ نعم |
| < 0.7.0 | ❌ لا — يُنصح بالترقية فوراً (إصلاح أمني حرج في 0.3.0، وتقوية إضافية في 0.7.0) |

## كيف تُبلّغ عن ثغرة؟ | Reporting a Vulnerability

**لا تفتح Issue عامة أبداً لثغرة أمنية.**

1. استخدم قناة **Private Vulnerability Reporting** في GitHub:
   `Security → Report a vulnerability` على هذا المستودع، أو
2. راسلنا عبر مستخدم GitHub للمشروع لترتيب قناة مشفّرة بديلة.

### ماذا تُضمّن في البلاغ؟
- وصف الثغرة ونوعها (مثال: صلاحيات CI، تنفيذ كود، تسريب سر)
- خطوات إعادة الإنتاج أو رابط PR/Commit يثبتها
- الأثر المتوقع وشدة الخطورة المقترحة (CVSS إن أمكن)
- اقتراح إصلاح إن وُجد

## التزامنا | Our Commitment

- **الإقرار خلال 72 ساعة** من استلام البلاغ.
- **تقييم أولي خلال 7 أيام** مع تحديد شدة الخطورة.
- **إصلاح الثغرات الحرجة خلال 14 يوماً** (كما فعلنا مع CI-01: نمط Pwn Request في مسار `pull_request_target` — أُغلق في الإصدار 0.3.0 بفصل مسار الفحص غير الموثوق عن مسار النشر الموثوق).
- **الإفصاح المنسّق**: ننشر Security Advisory + نسخة مُصلحة معاً، ونُشكر المُبلِّغ (بإذنه) في الإعلان.
- **سجل مساءلة علني**: كل قرار أمني يُوثَّق في سجل التغييرات (CHANGELOG.md) وسجل MIZAN Ledger.

## نطاق السياسة | Scope

يشمل: أكواد مسارات العمل في `.github/workflows/`، الأكشن المركّب `action/`، حزمة `mizan` نفسها، وموقع `website/`.
لا يشمل: مكتبات الطرف الثالث (بلّغها لصاحبها، ويمكننا المساعدة عبر تكامل OSV لدينا).

## قواعد المساهمة الآمنة | Safe Contribution Rules

- أي تعديل على مسارات العمل يخضع لاختبار BM-71: **ممنوع `pull_request_target`**.
- ممنوع تمرير أسرار إلى مهام تنفّذ كود طلبات الدمج (اختبار BM-72).
- الأكشنز الخارجية تُثبَّت بـ SHA كامل دائماً.
- التعديلات الآلية تمر حصراً عبر بوابة `mizan.repair` (فرع معزول + مراجعة بشرية).

---

# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.7.x+ | ✅ Yes |
| < 0.7.0 | ❌ No — upgrade immediately (0.3.0 ships a critical CI fix, 0.7.0 completes the hardening wave) |

## Reporting

**Never open a public issue for a security vulnerability.**

Use GitHub **Private Vulnerability Reporting** (Security → Report a vulnerability).

We acknowledge within **72 hours**, triage within **7 days**, and fix critical issues within **14 days**. Coordinated disclosure: advisory + patched release together, credited reporter (with consent).

## Scope

In scope: `.github/workflows/`, the composite `action/`, the `mizan` package, and `website/`. Out of scope: third-party dependencies (report upstream; our OSV integration can help).

## Safe Contribution Rules

- `pull_request_target` is forbidden (enforced by benchmark BM-71).
- Secrets must never reach jobs executing untrusted PR code (BM-72).
- External actions are always pinned to full commit SHAs.
- Automated edits must go through the `mizan.repair` gate (isolated branch + human review).
