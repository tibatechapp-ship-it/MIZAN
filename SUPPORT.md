# الدعم — Support

> العربية أولاً، والإنجليزية أدناه · Arabic first, English below.

---

## القنوات الرسمية | Official Channels

| نوع الطلب | القناة الصحيحة |
|---|---|
| ثغرة أمنية | **Never في Issue عامة** — اتبع [SECURITY.md](SECURITY.md): قناة GitHub «Private Vulnerability Reporting» فقط |
| خطأ (bug) في MIZAN | [GitHub Issues](https://github.com/tibatechapp-ship-it/MIZAN/issues) بقالب «Bug Report» |
| اقتراح ميزة | [GitHub Issues](https://github.com/tibatechapp-ship-it/MIZAN/issues) بقالب «Feature Request» |
| سؤال عن الاستخدام | [GitHub Discussions](https://github.com/tibatechapp-ship-it/MIZAN/discussions) إن كانت مفعّلة، وإلا Issue بقالب الميزة مع التصنيف «question» |
| التوثيق | [README.md](README.md)، [docs/](docs/)، [docs/CLI.md](docs/CLI.md)، [action/README.md](action/README.md) |

## قبل أن تفتح تقريرًا | Before You Open a Report

1. **جرّب أحدث إصدار مستقر** (`v0.16.0`) أو آخر وسم تطوير (`v0.17.0-dev`) — المشكلة قد تكون أُصلحت بالفعل.
2. **أرفق المخرج الكامل**: MIZAN يفشل صراحةً بقصد — رسالة الفشل تحمل المسار والسبب وهي جوهر التشخيص، فلا تختصرها.
3. **لا تُرفق أسرارًا حقيقية أبدًا**: مجسمات الأسرار صناعية دائمًا (`EXAMPLE_SECRET` بلا بصمة مزوّد حقيقي). التقرير الذي يحمل سرًّا حقيقيًا سيُغلق فورًا ويُبلَّغ عنه.
4. **اذكر بيئتك**: إصدار Python، نظام التشغيل، وكيف شُغّلت MIZAN (CLI، Python API، أو GitHub Action).
5. **ادّعِ ما قِس فقط**: إن أردت مناقشة دقة القواعد، استخدم أرقامًا من تشغيلك الفعلي (`mizan analyze --json`) لا انطباعات عامة.

## ما لا يقدمه MIZAN | What MIZAN Does Not Provide

- **لا SLA لأوقات الاستجابة**: هذا مشروع مصدر مفتوح يعمل بجهود أفضل — كل تقرير يُقرأ، لكن لا وعد بموعد إصلاح.
- **لا استشارات أمنية عامة**: نحن محرك تحليل لا فريق استجابة حوادث؛ ثغرات المشاريع الأخرى تُبلَّغ لأصحابها عبر قنواتهم.
- **لا دعم للإصدارات غير المدعومة**: راجع جدول الإصدارات المدعومة في [SECURITY.md](SECURITY.md).
- **لا طلبات تنفيذ عن بُعد**: MIZAN للقراءة حصرًا ولا ينفّذ كود المستخدم أبدًا — أي طلب لتغيير هذا القاعدة مرفوض مسبقًا.

---

## Support — English

### Channels

| Request type | Correct channel |
|---|---|
| Security vulnerability | **Never a public issue** — follow [SECURITY.md](SECURITY.md): GitHub «Private Vulnerability Reporting» only |
| Bug in MIZAN | [GitHub Issues](https://github.com/tibatechapp-ship-it/MIZAN/issues) with the «Bug Report» template |
| Feature request | [GitHub Issues](https://github.com/tibatechapp-ship-it/MIZAN/issues) with the «Feature Request» template |
| Usage question | [GitHub Discussions](https://github.com/tibatechapp-ship-it/MIZAN/discussions) if enabled, otherwise an Issue labeled «question» |
| Documentation | [README.md](README.md), [docs/](docs/), [docs/CLI.md](docs/CLI.md), [action/README.md](action/README.md) |

### Before you open a report

1. **Try the latest stable release** (`v0.16.0`) or the latest dev tag (`v0.17.0-dev`) first.
2. **Attach the full output**: MIZAN fails loudly on purpose — the failure message carries the path and the reason, which is the core of diagnosis. Do not trim it.
3. **Never attach real secrets**: secret fixtures are always synthetic (`EXAMPLE_SECRET`, no real provider shapes). A report carrying a real secret will be closed immediately and reported.
4. **State your environment**: Python version, OS, and how you ran MIZAN (CLI, Python API, or GitHub Action).
5. **Claim only what you measured**: when discussing rule accuracy, use numbers from your own run (`mizan analyze --json`), not general impressions.

### What MIZAN does not provide

- **No response-time SLA**: this is a best-effort open-source project — every report is read, but no fix deadline is promised.
- **No general security consulting**: MIZAN is an analysis engine, not an incident-response team; vulnerabilities in other projects go to their owners through their channels.
- **No support for unsupported versions**: see the supported-versions table in [SECURITY.md](SECURITY.md).
- **No remote-execution requests**: MIZAN is strictly read-only and never executes user code — any request to change this rule is rejected in advance.
