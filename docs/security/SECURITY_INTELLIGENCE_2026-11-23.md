# Security Intelligence & Remediation Brief — 2026-11-23

Coverage: 2026-11-09 through 2026-11-23. This is threat intelligence and repo-level remediation guidance, not proof of compromise or a production patch.

## Immediate priority

1. Patch exposed internet-facing products listed in CISA KEV; confirm product/version and vendor fixed release.
2. Update developer browsers, Android devices, Office/Outlook, and operating systems to current supported security builds.
3. Remove trust in loopback or forwarded headers as an authentication shortcut. Trust proxy headers only from explicitly configured proxy addresses.
4. Enforce object-level authorization, safe XML parsing, and shell-free subprocess calls in our own APIs and agents.
5. A green CI or static scan does not prove a production host is patched or uncompromised.

## Exploited-in-the-wild: CISA KEV additions

- Nov 9: GPUStack improper authentication CVE-2026-102895; FreeSWITCH code injection CVE-2026-116779; OpenSSH issue CVE-2026-123158; IBM Aspera Faspex authorization flaw CVE-2026-123218.
- Nov 10: Cisco BroadWorks XXE CVE-2026-20320; Barracuda command injection CVE-2026-111560 and ESG authentication bypass CVE-2026-116606; Openwave Webtop CVE-2026-111793; Outlook unsafe-action CVE-2026-124194; Chromium use-after-free CVE-2026-125350.
- Nov 13: UnrealIRCd delimiter handling CVE-2026-114713; Check Point permission assignment CVE-2026-123039.
- Nov 17: Puppet Enterprise deserialization CVE-2026-115731.
- Nov 18: Apache Axis CVE-2026-90436 and REDCap CVE-2026-90817.
- Nov 20: Cisco Expressway CVE-2026-76466; Apache Roller CVE-2026-129448; VMware vCenter CVE-2026-123890; SAP NetWeaver CVE-2025-42884.

For each matching asset, use the official vendor advisory to identify fixed versions and mitigations. For a KEV asset exposed before patching, preserve logs and assess compromise; do not patch and automatically declare clean.

## Relevant releases/advisories

- FastAPI GHSA-f56c-v883-vx8r, published Nov 17: high-severity denial of service from quadratic request-parameter processing. Affected versions are >=0.123.2 and <0.163.2; fixed in 0.163.2. Upgrade to >=0.163.2 and add a request-parameter stress regression test. Reverse-proxy limits reduce exposure but are not a complete fix.
- FastAPI 0.163.2 (Nov 17) contains the security fix. Releases 0.164.0 and 0.165.0 (Nov 18) add configurable request-body and form-parsing limits; adopt the fixed version and latest compatible patch, then test. Do not treat 0.162.3 as the security fix.
- GPUStack CVE-2026-102895: prioritize if deployed. Reported fixed from 2.2.0; verify current vendor advisory/latest supported patch. Never grant admin solely because a request appears to originate from loopback or contains client-controlled forwarded headers.
- Apache Roller CVE-2026-129448: actively exploited; security sources report fixed release 6.1.6+. Verify official vendor release notes and update if deployed.
- Oracle Java CVE-2026-114938 (Java4Shell), highlighted by CISA Nov 17: identify JDK/JRE versions including runtimes bundled inside containers/appliances, patch per Oracle/vendor advisory, and restrict unauthenticated Base64 input/size if patching is delayed. Monitor unexpected JVM crashes and rogue Java processes.\n- Android/Chrome/Outlook: install the latest vendor-supported security update. Android patch level 2026-11-05 is a minimum bulletin checkpoint, not a substitute for newer patches.

## Apply to our products

### NEXUS Core / NovaMind — P0/P1
- Preserve fail-closed provider behavior: mock/simulated output must never count as verified execution.
- Enforce per-tool capability allowlists and server-side authorization. Require explicit approval for destructive actions, deployment, credential rotation, or merge.
- Treat repo files, issue/PR text, webpages, model output, and tool results as untrusted data, never as instructions that can alter permissions.
- Execute target code only in disposable isolated workspaces; disable network by default, set resource/time limits, and never inherit credentials.
- Redact secrets before logs, memory, checkpoints, and PR artifacts. Regex redaction is defense-in-depth, not complete DLP.
- Add adversarial tests for forwarded-header spoofing, loopback identity, prompt injection, malicious XML, shell injection, and cross-user resource access.

### MIZAN — P1
- Keep scanning read-only; never execute target code to validate a finding.
- Add lockfile SBOM/dependency advisory matching (CVE/GHSA/OSV) and distinguish exact locked versions from best-effort manifest inference.
- Report advisory ID, package/ecosystem, detected/fixed version, lockfile path, source, KEV status, reachability (known/unknown), and confidence.
- An unresolved KEV on an exposed production component is critical. Unknown version, truncated inventory, or incomplete analysis must be “incomplete,” never “clean.”
- Add non-executed fixtures for XXE parser settings, unsafe deserialization, shell command construction, proxy-header trust, and request-parameter DoS.
- Prefer AST/dataflow/framework-aware checks for authorization and trust boundaries; measure false positives before broad regex rules.

### Rento — P0/P1
- Enforce object-level authorization for booking, listing, payment, message, and owner endpoints (BOLA/IDOR).
- Calculate price, fees, ownership, availability, and refunds server-side.
- Make payment/webhook operations idempotent; rate-limit login, booking, upload, and search.
- Trust forwarded headers only from configured proxy IPs.

### Rasan / Android — P1
- Apply current Android patches; review exported components, deep links, intent permissions, WebView bridges, and secure storage.
- Keep API secrets out of APK assets/build config; use short-lived server tokens and Keystore-backed storage.
- Record OS patch level, dependency scan, signing verification, and backend authorization tests in release evidence.

### Raqib / NexHub — P1
- Verify trusted proxy chain; never use raw X-Forwarded-* values for access control.
- Authenticate and authorize telemetry, device, admin, and websocket endpoints.
- Pin/audit dependencies and use supported Flutter/Dart toolchains with lockfiles.

### Pharma-SDL — P1
- Keep patient/sample data and LIMS credentials out of logs, fixtures, reports, and model prompts.
- Use scoped LIMS credentials, TLS verification, immutable audit events, and explicit authorization for sample/protocol mutations.
- Use synthetic CI data and test export/authorization boundaries.

## Deployment checklist

- [ ] Inventory product, version, internet exposure, and owner.
- [ ] Match against CISA KEV and vendor advisory; record fixed version/date.
- [ ] Patch/mitigate in a controlled window and validate authentication/service health.
- [ ] If exposed while vulnerable, preserve logs and inspect for new accounts/API keys, suspicious admin changes, processes/network activity, workflow changes, and deploy-key changes.
- [ ] Rotate affected credentials after containment/assessment if compromise is plausible.
- [ ] Re-run tests/security scans and record commit, build, and deployment version.
- [ ] Close only with patch evidence and post-patch validation.

## Sources

- CISA KEV Nov 9: https://content.govdelivery.com/accounts/USDHSCISA/bulletins/4323900
- CISA KEV Nov 10: https://content.govdelivery.com/accounts/USDHSCISA/bulletins/4325e4d
- CISA KEV Nov 13: https://content.govdelivery.com/accounts/USDHSCISA/bulletins/432b09e
- CISA KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FastAPI advisory (fixed in 0.163.2): https://github.com/fastapi/fastapi/security/advisories/GHSA-f56c-v883-vx8r\n- CISA Java4Shell alert, Nov 17: https://content.govdelivery.com/accounts/USDHSCISA/bulletins/4332a87\n- FastAPI advisories: https://github.com/fastapi/fastapi/security/advisories
- FastAPI releases: https://fastapi.tiangolo.com/release-notes/
- Android security bulletins: https://source.android.com/docs/security/bulletin
- OWASP Agent Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html

Status: intelligence triage only. No claim of production patching or compromise assessment without asset inventory and deployment telemetry.
