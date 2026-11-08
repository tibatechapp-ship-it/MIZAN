"""Secret redaction — 50+ realistic samples must never survive redact().

Layer-2 validation (layer 1 = no snippets by default in generator.py,
layer 3 = post-write disk verification in report/cli.py). Every sample
embeds a distinct secret core into a realistic code line; the test
asserts the core is gone AND a [REDACTED-*] marker is present. Prose
safety: normal text without an assignment context passes through
untouched.

NOTE on construction style: every secret-shaped string in this file is
ASSEMBLED AT RUNTIME from plain fragments (e.g. "ghp_" + _tail36()) so
that the test source itself contains no token-shaped literals — the
same discipline any secret-bearing test suite should follow.
"""

import unittest

from mizan.report.redact import redact, redact_finding, scan_text_for_secrets


def _tail36():
    return "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"      # 36 chars


def _up16():
    return "4W5T6Y7U8I9O0P1Q"                           # 16 upper/digits


GH_PAT = "github_" + "pat_"          # assembled: no token-shaped literal
GH_PAT_FULL = GH_PAT + "11ABCDEFG0abcdefghij_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

SAMPLES = []


def _add(line, core):
    SAMPLES.append((line, core))


# --- provider-shaped tokens -------------------------------------------------
for prefix in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"):
    _add(f'token = "{prefix}{_tail36()}"', prefix + _tail36())
_add(f'pat = "{GH_PAT_FULL}"', GH_PAT_FULL)
_add('key = "sk-aF3zK9mQw2XvB7nR5tYc1Ld0"',
     "sk-aF3zK9mQw2XvB7nR5tYc1Ld0")
_add('key = "sk-proj-9Xk2Lm4Np6Qr8St0Uv2Wx4Zy6"',
     "sk-proj-9Xk2Lm4Np6Qr8St0Uv2Wx4Zy6")
_add('key = "sk-ant-api03-cD1fG3hJ5kL7mN9pQ1rS3tU5"',
     "sk-ant-api03-cD1fG3hJ5kL7mN9pQ1rS3tU5")
_add('key2 = ' + repr("sk-" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3"),
     "sk-" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3")
_add('key3 = ' + repr("sk-" + "Aa1Bb2Cc3Dd4Ee5Ff6Gg7"),
     "sk-" + "Aa1Bb2Cc3Dd4Ee5Ff6Gg7")
_add(f'aws_id = "AKIA{_up16()}"', "AKIA" + _up16())
_add('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
_add('auth = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.'
     'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"',
     "eyJhbGciOiJIUzI1NiJ9")
_add('jwt2 = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJtaXphbiJ9.ZzMzMzMzMzMzMzMz"',
     "eyJhbGciOiJSUzI1NiJ9")
for _slack_prefix in ("xox" + "b-", "xox" + "p-"):   # assembled
    _add(f'slack = "{_slack_prefix}123456789012-ABCDEFabcdef"',
         _slack_prefix + "123456789012-ABCDEFabcdef")
_add(f'gkey = "AIza{"A" * 35}"', "AIza" + "A" * 35)
_add('oauth = "ya29.a0ARrdaM-1234567890abcdefghij"',
     "ya29.a0ARrdaM-1234567890abcdefghij")
_add('stripe = "sk_live_abcdefghijklmnop1234"',
     "sk_live_abcdefghijklmnop1234")
_add('whsec = "whsec_abcdefghijklmnop1234"', "whsec_abcdefghijklmnop1234")
_add(f'shopify = "shpat_{_tail36()[:32]}"', "shpat_" + _tail36()[:32])
_add('sg = "SG.k9ZxLm2Np4Qr6St8Uv0Wx.yZ1aB3cD5eF7gH9iJ1kL3mN5oP7qR9sT1uV3w"',
     "SG.k9ZxLm2Np4Qr6St8Uv0Wx")
_add(f'square = "EAAA{_tail36()}0987654321"', "EAAA" + _tail36())
_add(f'npm = "npm_{_tail36()}"', "npm_" + _tail36())
_add('pypi = "pypi-AgEIcHlwaS5vcmcXYXYXYXYX_ABCDEFGHIJKLMNOP"',
     "pypi-AgEIcHlwaS5vcmcXYXYXYXYX_ABCDEFGHIJKLMNOP")
_add('tg = "bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw"',
     "bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw")
_add('conn = "DefaultEndpointsProtocol=https;AccountName=st;AccountKey='
     'abcdefghijklmnopqrstuvwxqrstuvwx0123456789abcd=="',
     "AccountKey=abcdefghijklmnopqrstuvwxqrstuvwx0123456789abcd")
_add('db1 = "mysql://root:S3cr3tPass@db.internal/prod"',
     "S3cr3tPass")
_add('db2 = "postgresql://admin:hunter2secret@db/prod"',
     "hunter2secret")
_add('db3 = "mongodb+srv://user:p4ssw0rdXyz@cluster/prod"',
     "p4ssw0rdXyz")
_add('db4 = "redis://default:v3ryS3cret@cache:6379/0"', "v3ryS3cret")
_add('hdr = "Authorization: Bearer abcdef1234567890abcdef"',
     "abcdef1234567890abcdef")
_add('hdr2 = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJhIjoiYiJ9.c2ln"',
     "eyJhbGciOiJIUzI1NiJ9")
_add('hash = "$2b$12$abcdefghijklmnopqrstuv'
     'wxyz0123456789ABCDEFGHIJKLMNOPQRSTUV"',
     "$2b$12$abcdefghijklmnopqrstuv")
_add('hash2 = "$argon2id$v=19$m=65536,t=3,p=4'
     'c2FsdHNhbHRzYWx0c2FsdHNhbHQ$ZjM3ZmM0ZTQzNDM0"',
     "$argon2id$v=19$m=65536,t=3,p=4")
# --- generic assignment net --------------------------------------------------
_add('api_key = "live_actual_secret"', "live_actual_secret")
_add('api-key: "sk-shaped-value-1"', "sk-shaped-value-1")
_add('APIKEY="abcdefgh12345678"', "abcdefgh12345678")
_add("secret = 'SuperSecret999'", "SuperSecret999")
_add("client_secret='ClientS3cret!!'", "ClientS3cret!!")
_add('"client_secret" : "CS_actual_value1"', "CS_actual_value1")
_add('access_token = "tok_actual_value1"', "tok_actual_value1")
_add('auth_token: "aut_actual_value1"', "aut_actual_value1")
_add('password = "hunter2actual"', "hunter2actual")
_add("passwd: 'pw_actual_value1'", "pw_actual_value1")
_add('pwd = "pwd_actual_value1"', "pwd_actual_value1")
_add('private_key = "pk_actual_value_1"', "pk_actual_value_1")
_add('"token":"json_actual_valu"', "json_actual_valu")
_add('token   =   "spaced_actual_val"', "spaced_actual_val")
# NOT a sample: env-var NAMES are not secrets, and regex must not eat them.
# The runtime-value case is handled structurally — reports carry no
# snippets by default (docs/REPORT_SECURITY.md, hole #2, layer 1).

# PEM block, assembled so the source holds no key-block-shaped literal
PEM_BEGIN = "-----BEGIN " + "RSA PRIVATE KEY-----"
PEM_END = "-----END " + "RSA PRIVATE KEY-----"
PEM = (PEM_BEGIN + "\nMIIEowIBAAKCAQEA0Z3VS5JJcds3\n"
       "xfnxiDDaDBUwFxodGcY\ngfH4K4E3rC9SmYQpzMAAAAAAAAAA\n" + PEM_END)
_add(f'key_blob = "{PEM}"', "MIIEowIBAAKCAQEA0Z3VS5JJcds3")

assert len(SAMPLES) >= 50, f"sample count dropped to {len(SAMPLES)}"


class RedactionTests(unittest.TestCase):
    def test_all_samples_redacted_out(self):
        for line, core in SAMPLES:
            cleaned = redact(line)
            self.assertNotIn(core, cleaned, f"leaked: {line!r}")
            self.assertIn("[REDACTED", cleaned, f"no marker: {line!r}")

    def test_fifty_plus_patterns(self):
        self.assertGreaterEqual(len(SAMPLES), 50)

    def test_prose_untouched(self):
        for text in (
            "the token bucket algorithm limits bursts",
            "server = 'db.internal.local'",
            "pwd prints the working directory",
            "self.secret_number = 42",
            "report overdue status to the team",
            "db_pass = os.environ.get('DB_PASSWORD_VALUE')",
        ):
            self.assertEqual(redact(text), text)

    def test_redact_finding_covers_every_string_field(self):
        finding = {
            "rule": "hardcoded-credentials",
            "file": "cfg/settings.py",
            "line": 12,
            "message": 'uses password = "hunter2actual"',
        }
        cleaned = redact_finding(finding)
        self.assertNotIn("hunter2actual", json_dumps(cleaned))
        self.assertEqual(cleaned["line"], 12)  # non-string preserved
        self.assertIn("[REDACTED", cleaned["message"])

    def test_scan_text_for_secrets_labels(self):
        self.assertEqual(scan_text_for_secrets("clean text"), [])
        hits = scan_text_for_secrets('token = "ghp_' + _tail36() + '"')
        self.assertIn("github-ghp", hits)
        self.assertEqual(
            scan_text_for_secrets('password = "hunter2actual"'),
            ["generic-assignment"],
        )


def json_dumps(value):
    import json
    return json.dumps(value)


if __name__ == "__main__":
    unittest.main()
