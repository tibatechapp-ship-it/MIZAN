# إعداد بيئة MIZAN — دليل التشغيل

## GitHub Pages — خطوة واحدة لكل مستودع (يدوية بالضرورة)

المسار الآلي `pages.yml` يفترض وجود موقع Pages مُنشأً مسبقاً. توكن
GitHub Actions داخل الـ workflow — ولو منح `pages: write` — لا يستطيع
إنشاء الموقع لأول مرة: GitHub يرد بـ
`Create Pages site failed: Resource not accessible by integration`
(مُقاس 2026-11-08 على تشغيل 42479141776 لالتزام `817b22e`). لذلك:

1. مرة واحدة لكل مستودع، أنشئ الموقع بأحد الطريقتين:
   - واجهة الويب: Settings → Pages → Source: **GitHub Actions**.
   - أو عبر API بتوكن مستخدم يملك صلاحية إدارية على المستودع:
     `POST /repos/{owner}/{repo}/pages` بجسم `{"build_type":"workflow"}`.
2. أعد تشغيل الوظيفة الفاشلة: Actions → Deploy Website → Re-run failed
   jobs. بعدها تعمل الأتمتة كاملة على كل دفع لاحق (القياس: إنشاء HTTP 201
   ثم 4/4 workflows success على `817b22e` و`8ecb19f`، والموقع يجيب 200).

**حد الأتمتة الصادق**: كل شيء آلي بعد هذه الخطوة الواحدة؛ الادعاء
بـ«أتمتة كاملة من الصفر» غير دقيق — إنشاء الموقع الأول بيد الإنسان
بتصميم GitHub نفسه، لا بقصور في `pages.yml`.

## المصادقة — لا توكنات في المحادثة إطلاقاً

استخدم GitHub CLI مرة واحدة: `gh auth login` (تدفق الجهاز: يظهر كود
لمرة واحدة تُدخله في github.com/login/device) — يُخزَّن التوكن في
`~/.config/gh/hosts.yml` محلياً ويمرره `gh` تلقائياً لكل استدعاء
(`gh api`، وgit push عبر `gh auth setup-git`). لا تلصق توكن في
المحادثة ولا تكتبه في أي ملف؛ إن لُصق بالخطأ فأبطِله فوراً من
github.com/settings/tokens. القاعدة الحاكمة للمشروع: التوكن من البيئة
أو من `gh` حصراً، ولا يُطبع في أي مخرج.
