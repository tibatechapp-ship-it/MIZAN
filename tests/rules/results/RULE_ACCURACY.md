# تقرير دقة القواعد — MIZAN v0.14.0-dev (قياس فعلي)

**التاريخ**: 2026-11-08 · **المنهج**: مجموعات ذهبية (5 إيجابيات + 5 سلبيات لكل
قاعدة) + 16 حالة حدية + قياس ميداني على 10 مستودعات حقيقية بتصنيف يدوي
لكل إيجابية. **لا رقم في هذا التقرير افتراض** — كل صف مأخوذ من تشغيل فعلي.

---

## 1) جرد القواعد (من `mizan plugins list` — لا من المفترض)

الجرد الفعلي: **20 قاعدة أمنية** في إضافة `security` (+ 3 قواعد جودة:
todo، python-syntax-error، file-read-error). مطابقة مخطط الرسالة الأصلي
(8 عائلات) مع الهويات الفعلية: «sql-injection» للرسالة تغطي `sql-injection`
+ `request-to-sql` (تدفق)، «shell-true» تغطي `shell-true` +
`process-execution`، «hardcoded-secret» = `hardcoded-secret-candidate`.

| # | القاعدة | الشدة | CWE (مدقّق في report/cwe.py) | CWE (غير مدقّق — بصدق) |
|---|---|---|---|---|
| 1 | dynamic-execution | high | CWE-94 | |
| 2 | process-execution | medium | | غير مدقّق (عائلة CWE-78) |
| 3 | shell-true | high | | غير مدقّق (عائلة CWE-78) |
| 4 | hardcoded-secret-candidate | high | CWE-798 | |
| 5 | unsafe-deserialization | high | CWE-502 | |
| 6 | yaml-unsafe-load | medium | | غير مدقّق (CWE-502) |
| 7 | sql-injection | high | CWE-89 (لـrequest-to-sql) | |
| 8 | path-traversal | medium | CWE-22 | |
| 9 | weak-crypto | medium | | غير مدقّق (CWE-327) |
| 10 | tls-verification-disabled | high | | غير مدقّق (CWE-295) |
| 11 | ssl-unverified-context | high | | غير مدقّق (CWE-295) |
| 12 | request-without-timeout | low | | غير مدقّق |
| 13 | torch-unsafe-load | high | | غير مدقّق (CWE-502) |
| 14 | hf-trust-remote-code | high | | غير مدقّق (CWE-94) |
| 15 | jinja2-autoescape-false | high | | غير مدقّق (CWE-79) |
| 16 | django-mark-safe | medium | | غير مدقّق (CWE-79) |
| 17 | tarfile-extractall | high | | غير مدقّق (CWE-22) |
| 18 | hardcoded-tmp-path | low | | غير مدقّق (CWE-377) |
| 19 | request-to-sql (تدفق) | high | CWE-89 | |
| 20 | input-to-subprocess (تدفق) | high | CWE-78 | |

عمود CWE يتبع سياسة `report/cwe.py`: يُكتب فقط ما دُقق — «غير مدقّق»
قيمة صادقة لا ادعاء.

## 2) المجموعات الذهبية — قبل الإصلاح ← بعد الإصلاح

200 عينة (`tests/rules/fixtures/{positive,negative}/<rule>/NN_*.py`)
+ 16 حالة حدية. كل عينة مكتوبة وفق الدلالات **المقاسة** من `analyzer.py`
و`taint.py` قبل تأليفها.

| القاعدة | إيجابي قبل | إيجابي بعد | سلبي قبل | سلبي بعد |
|---|---|---|---|---|
| dynamic-execution | 3/5 | **5/5** | 5/5 | 5/5 |
| process-execution | 5/5 | 5/5 | 5/5 | 5/5 |
| shell-true | 2/5 | **5/5** | 5/5 | 5/5 |
| hardcoded-secret-candidate | 4/5 | **5/5** | 5/5 | 5/5 |
| unsafe-deserialization | 4/5 | **5/5** | 5/5 | 5/5 |
| yaml-unsafe-load | 4/5 | **5/5** | 5/5 | 5/5 |
| sql-injection | 4/5 | **5/5** | 5/5 | 5/5 |
| path-traversal | 5/5 | 5/5 | 5/5 | 5/5 |
| weak-crypto | 5/5 | 5/5 | 5/5 | 5/5 |
| tls-verification-disabled | 5/5 | 5/5 | 5/5 | 5/5 |
| ssl-unverified-context | 5/5 | 5/5 | 5/5 | 5/5 |
| request-without-timeout | 5/5 | 5/5 | 5/5 | 5/5 |
| torch-unsafe-load | 5/5 | 5/5 | 5/5 | 5/5 |
| hf-trust-remote-code | 5/5 | 5/5 | 5/5 | 5/5 |
| jinja2-autoescape-false | 5/5 | 5/5 | 5/5 | 5/5 |
| django-mark-safe | 5/5 | 5/5 | 5/5 | 5/5 |
| tarfile-extractall | 5/5 | 5/5 | 5/5 | 5/5 |
| hardcoded-tmp-path | 5/5 | 5/5 | 5/5 | 5/5 |
| request-to-sql (تدفق) | 5/5 | 5/5 | 5/5 | 5/5 |
| input-to-subprocess (تدفق) | 5/5 | 5/5 | 5/5 | 5/5 |
| **المجموع** | **93/100** | **100/100** | **100/100** | **100/100** |

**سُقطات الاستدعاء قبل الإصلاح (السبع، كلها مشخّصة)**:
1. `dynamic-execution`: bare `compile()` — لم تكن مغطاة.
2. `dynamic-execution`: bare `__import__()` — لم تكن مغطاة.
3. `shell-true`: `subprocess.call(shell=True)` — كانت القاعدة على `.run` فقط.
4. `hardcoded-secret-candidate`: `DATABASE_PASSWORD = "…"` — الـ`\b` يفشل
   قبل بادئة `WORD_`.
5. `unsafe-deserialization`: `shelve.open()` — تُزيل قيمها عبر pickle.
6. `yaml-unsafe-load`: `yaml.unsafe_load()` — اسمها لا يطابق `load`.
7. `sql-injection`: `"…{}".format(x)` — لا BinOp ولا JoinedStr.

**الإيجابيات الكاذبة المقاسة قبل الإصلاح**: 1 — `zipfile.ZipFile(f).
extractall()` كانت تُطلق `tarfile-extractall` رغم أن صيغة zip بلا
تجاوز-رموز (استثناء zipfile كان يشمل المتغيرات المربوطة فقط).

## 3) الإصلاحات المطبقة (كلها توسيع/ضبط لقواعد قائمة — لا عائلة جديدة)

| # | الإصلاح | الأثر |
|---|---|---|
| 1 | shell-true على عائلة subprocess كاملة (run/Popen/call/check_call/check_output/getoutput/getstatusoutput) والمرسل محصور بجذر subprocess | استدعاء +3 |
| 2 | **خُلل تكرار مكتشف ميدانيًا**: بلوك shell-true القديم على `.run` نجا من إعادة الكتابة فأطلق الإيجابية **مرتين** لكل موقع (ظهر في zyko tools_builtin:142). حُذف + حالة حدية `16_shell_true_single_report.py` تمنع رجوعه | دقة الإبلاغ |
| 3 | dynamic-execution: + bare `compile()` و`__import__()` (حد الاستدعاء المجرد يُبقي `re.compile`/`obj.eval` صامتة) | استدعاء +2 |
| 4 | `__import__("const")` بثابت وحدة = أسلوب lazy-import لا تنفيذ من بيانات — صامتة؛ الاسم المتغيّر/الـf-string يبقى مُطلَقًا. تصحيح ميداني: 8/8 مواقع ثابتة في القياس كانت أسلوب استيراد خاملي | دقة ميدانية |
| 5 | unsafe-deserialization: + `shelve.open` | استدعاء +1 |
| 6 | yaml-unsafe-load: + `yaml.unsafe_load` | استدعاء +1 |
| 7 | sql-injection: + `"...{}".format(x)` على سلسلة حرفية | استدعاء +1 |
| 8 | hardcoded-secret-candidate: مفاتيح ببادئة `WORD_`/`WORD-` (`DATABASE_PASSWORD`) عبر نمط إضافي؛ حدود صارمة: لا مفاتيح بلا فاصل (`tokenizer`، `TOKEN_BUCKET` تبقى صامتة) | استدعاء +1 |
| 9 | tarfile-extractall: استثناء zip يشمل المستقبِل المباشر `zipfile.ZipFile(...)` | FP −1 |
| 10 | placeholders: + `top_secret`/`topsecret` (موقع ميداني nexus agency.py:37) + قوالب الاستيفاء `{{…}}`/`{…}` (موقع ميداني seekfeek TOOLS_TOKEN) | FP −2 ميدانيًا |

## 4) قرارات موثقة بعدم التغيير (قياس لا ادعاء)

| الحالة | القرار | السبب |
|---|---|---|
| `eval("1+1")` ثابت | **تبقى مُطلَقة** | انحراف مقصود عن مخطط الرسالة: توافق Bandit B307 + ثبات سهل الكسر (`eval("1"+"+1")`)؛ الحالة الحدية `11` تثبت السلوك |
| `yaml.full_load()` | **لا تُطلق** | FullLoader عامل تخفيف في PyYAML (يمنع بناء كائنات اعتباطية)؛ بينما `load(Loader=FullLoader)` تبقى مُطلَقة لتوافق B506 — موثق كتناقض مقصود |
| `# nosec` | **لا يُحترم** | سياسة معلنة (README): التعليق لا يدفن إيجابية؛ الكبح أداة الـbaseline |
| `ast.literal_eval` | لا تُطلق | آمنة — مثبتة |
| SQL بمُعرّف-موضع `f"…FROM {table}"` | لا تُطلق | نطاق موثق: ربط مُعرّفات الإعدادات |
| سِرّ مقسوم `"abc"+"def"` | لا يُكتشف | حد regex على سطر — الضابط البنيوي (لا مقتطفات) هو الإجابة المصممة |
| دالة مساعدة `def run(q): cursor.execute(q)` | لا تُكتشف | لا تحليل عبر-إجرائي (حد PoC موثق) |
| `import pickle as pk` | لا تُكتشف | لا حل أسماء مستعارة — قيد شامل موثق (يشمل `import torch as th`) |

## 5) القياس الميداني — 10 مستودعات حقيقية (المؤسسة tibatechapp-ship-it)

استنساخ ضحل عبر التوكن (بيئة فقط، حُرِّرت بعد الاستخدام)، فحص `mizan scan`
كامل، وتصنيف يدوي لكل إيجابية بقراءة سطرها المصدرية.

| المستودع | قبل الإصلاح | بعد الإصلاح | حقيقية | سياقية | كاذبة |
|---|---|---|---|---|---|
| MIZAN | 4 | 3 | 0 | 0 | **3** |
| BASIRAH-AI | 2 | 2 | 1 | 1 | 0 |
| zyko | 3 | 1 | 1 | 0 | 0 |
| tayf | 2 | 2 | 2 | 0 | 0 |
| raqib | 0 | 0 | — | — | — |
| pharma-sdl | 1 | 1 | 1 | 0 | 0 |
| chess-cli | 0 | 0 | — | — | — |
| lifelink-app | 0 | 0 | — | — | — |
| seekfeek | 18 | 17 | 15 | 0 | **2** |
| nexus-core | 48 | 41 | 35 | 1 | **5** |
| **المجموع** | **78** | **67** | **55** | **2** | **10** |

**أثر إصلاحات الحقل (78←67)**: اختفت 8 مواقع `__import__("const")`
(أسلوب lazy-import)، وFP قالب `{{tools}}`، وتكرار shell-true واحد.

### تصنيف الإيجابيات الكاذبة العشر — بالسبب (معيار القبول: 0 أو موثق)

| # | الموقع | السبب الجذري | عائلة الإصلاح المستقبلي |
|---|---|---|---|
| 1-2 | MIZAN `analyzer.py:548-549` (tmp×2) | ذاتية-الإشارة: حروف المقارنة في كود القاعدة نفسها (`value == "/tmp"`) | لا إصلاح — كود كاشف عن القاعدة ذاتها؛ توثيق فقط |
| 3 | MIZAN `report/timeline.py:121` (sql) | f-string يُقحم `placeholders` — ثابت داخلي (`"?"*n`) لكن إسناده BinOp يمنع إثبات الثبات بـAST سطحي | نقل ثوابت الشظايا (موجة لاحقة، لا تعجيل) |
| 4 | seekfeek `clipboard.ts:40` (dynamic-execution) | `exec('copy')` = أسلوب execCommand للحافظة؛ حدود regex لـJS لا تميز execCommand | تغطية ذهبية لـJS أولًا ثم ثابت-الوسيطة صامت |
| 5 | seekfeek `publish-npm-baseline.ts:918` (secret) | قيمة وصفية `keyless-installed-web-no-call` — القاعدة **candidate** بحكم تصميمها (تحقق يدوي) | سلوك مقصود — تُرسل للفرز لا تُكت |
| 6-9 | nexus `session_store.py:301/486/741`، `memory/engine.py:147` (sql) | SQL ديناميكي فوق شظايا أعمدة داخلية مع قيم مُعامَلة (`WHERE id = ?`) — لا بيانات للثبات بلا تدفق أعمق | نفس عائلة #3 |
| 10 | nexus `tech_targets.py:49` (secret) | سلسلة اختبار ذاتية-الإشارة داخل مهمة كشف وهمية (`"api_key = 'sk-abc123…'"` كنص) | ذاتية-الإشارة كـ#1-2 |

**نسبة الإيجابيات الكاذبة: 10/67 = 14.9%** — منها 3 ذاتية-الإشارة
(كود-عن-كود)، 5 عائلة SQL-الشظايا (حد AST سطحي موثق)، 1 غموض JS،
1 قيمة حارسة لقاعدة candidate. **صفر إيجابية كاذبة تدّعي اختراقًا غير
موجود**: كل الكاذبات إما شدة منخفضة/متوسطة أو شكل مراجعة لا ادعاء.

### الإيجابيات الحقيقية البارزة (أمثلة قابلة للتحقق)

- `BASIRAH-AI ml_classifier.py:146` — `pickle.load` لملف نموذج: ناقص
  RCE قياسي (يوافق B301).
- `zyko tools_builtin.py:142` — `shell=True` حقيقي؛ المستودع نفسه يوثق
  أنه أداة `danger` مقيّدة بسياسة + `# nosec B602` — وسياسة MIZAN
  (لا nosec مضمّن) تُبقيه ظاهرًا **بقرار لا بنسيان**.
- `tayf e2e_smoke.py:49` — `sys.argv → Popen`: قاعدة التدفق تُثبت
  المسار مصدر→مصب فعليًا (ليس مجرد شكل).
- `nexus-core` — 13 موقع dynamic-execution كلها `__import__(<اسم
  متغير>)` أو `compile(<كود>)` في أنابيب تحميل إضافات/تصحيح ذاتي:
  أنماط تستحق مراجعة فعلًا.

## 6) التغطية الآلية

```
tests/rules/test_rule_positive.py   20 قاعدة × 5 عينات      ✅ 100/100
tests/rules/test_rule_negative.py   20 قاعدة × 5 عينات      ✅ 100/100
tests/rules/test_rule_edge.py       16 حالة حدية + استثناءات الشجرة  ✅
الحزمة الكاملة                                              555/555 ✅
```

تنبيه منهجي: المجموعات الذهبية تمسح العينات عبر `analyze_file` مباشرة
(قياس الكشف، لا المشي الشجري) — لأن عيناتنا تحت `tests/` وهي مستثناة
**بعمد** من المشي الشجري؛ سلوك الاستثناءات له اختباره المستقل
(`TreeExclusions`).

## 7) ما لم يُقَس بعد (بصدق)

- الذهبي بايثوني فقط؛ قواعد JS/TS (dynamic-execution على regex) بلا
  مجموعات ذهبية JS — قبل إصلاح أي FP لـJS تُبنى تغطيتها أولًا.
- القياس الميداني 10 مستودعات — ليس بديلًا عن حَكْم مواقع الـ456
  (bench100) أو تقرير Taint على 20 مستودعًا؛ تلك بوابات P2 قائمة.
