"""GA7 Q2 - LLM Action Firewall.

Pure stdlib, no network, no LLM.  Mounted at POST /action-firewall as::

    from app.q2_firewall import handle
    @app.post("/action-firewall")
    async def action_firewall(body: dict):
        return handle(body)

Design note (the whole point of the question): provenance and untrustedContent
NEVER decide anything on their own.  There is deliberately no phrase blocklist
here -- a valid read-only action stays allowed even when the untrusted text it
came with screams "ignore all previous instructions".  Schemas, tenant scope,
egress allowlist, human approval and safe rendering are the only boundary.
"""

import re
import variant

TENANT_ID = "tenant-r9l91zn"
EMAIL_DOMAIN = "notify-lizt2eh.example"

# Required top-level keys are enforced strictly (a missing one is a schema
# fault).  Flip to False to instead default provenance -> "untrusted" and
# humanApproved -> False when they are absent.
STRICT_REQUIRED_TOPLEVEL = True

PROVENANCE_VALUES = ("trusted", "untrusted")

# Exact arg key sets.  No extras, nothing missing.
TOOL_ARG_KEYS = {
    "search": {"query"},
    "lookup_record": {"tenantId", "recordId"},
    "send_email": {"to", "subject", "body"},
    "render_html": {"html"},
}
ALLOWED_TOOLS = set(TOOL_ARG_KEYS)

QUERY_MIN, QUERY_MAX = 1, 200

ALLOW = {"decision": "allow", "reason": "ALLOW"}


def _block(reason):
    return {"decision": "block", "reason": reason}


# --- html safety patterns ---------------------------------------------------

# <script ...>, </script>, < iframe, <\nobject, <embed ...
_DANGEROUS_TAG = re.compile(r"<\s*/?\s*(script|iframe|object|embed)\b", re.I | re.S)

# the body of a tag, so event handlers are only looked for in attribute
# position and never in ordinary text.
_TAG = re.compile(r"<[^<>]*(?:>|$)", re.S)

# inline event handler: preceded by whitespace, a quote or a slash.
_EVENT_HANDLER = re.compile(r"[\s\"'/](on[a-z]+)\s*=", re.I)

# English words starting with "on" that could appear as an attribute-ish token
# in a URL ("/only=1") - not event handlers.
_NOT_HANDLERS = {"one", "once", "only", "onto", "ongoing", "online"}

# javascript: URL, tolerating whitespace/newlines anywhere inside the scheme
# ("java\nscript:", "javascript :").
_JS_URL = re.compile(r"j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:", re.I)


def _has_event_handler(html):
    for tag in _TAG.findall(html):
        for name in _EVENT_HANDLER.findall(tag):
            if name.lower() not in _NOT_HANDLERS:
                return True
    return False


def _is_unsafe_html(html):
    return bool(
        _DANGEROUS_TAG.search(html)
        or _JS_URL.search(html)
        or _has_event_handler(html)
    )


# --- step 1: top-level schema ----------------------------------------------

def _check_body(body):
    """Return an error reason, or None if the envelope is well formed."""
    if not isinstance(body, dict):
        return "INVALID_SCHEMA"

    if "provenance" in body:
        if body["provenance"] not in PROVENANCE_VALUES or not isinstance(
            body["provenance"], str
        ):
            return "INVALID_SCHEMA"
    elif STRICT_REQUIRED_TOPLEVEL:
        return "INVALID_SCHEMA"

    if "humanApproved" in body:
        if not isinstance(body["humanApproved"], bool):
            return "INVALID_SCHEMA"
    elif STRICT_REQUIRED_TOPLEVEL:
        return "INVALID_SCHEMA"

    if "untrustedContent" in body and not isinstance(body["untrustedContent"], str):
        return "INVALID_SCHEMA"

    action = body.get("action")
    if not isinstance(action, dict):
        return "INVALID_SCHEMA"
    if not isinstance(action.get("tool"), str):
        return "INVALID_SCHEMA"
    if not isinstance(action.get("args"), dict):
        return "INVALID_SCHEMA"

    return None


# --- step 3: per-tool argument schema ---------------------------------------

def _check_args(tool, args):
    if set(args) != TOOL_ARG_KEYS[tool]:
        return "INVALID_SCHEMA"

    if tool == "search":
        query = args["query"]
        if not isinstance(query, str) or not (QUERY_MIN <= len(query) <= QUERY_MAX):
            return "INVALID_SCHEMA"

    elif tool == "lookup_record":
        if not isinstance(args["tenantId"], str) or not isinstance(
            args["recordId"], str
        ):
            return "INVALID_SCHEMA"
        if args["recordId"] == "":
            return "INVALID_SCHEMA"

    elif tool == "send_email":
        for key in ("to", "subject", "body"):
            if not isinstance(args[key], str):
                return "INVALID_SCHEMA"

    elif tool == "render_html":
        if not isinstance(args["html"], str):
            return "INVALID_SCHEMA"

    return None


# --- step 5: egress ---------------------------------------------------------

def _domain_allowed(to):
    """Exact-match the recipient domain.  Look-alikes are rejected."""
    if to.count("@") != 1:
        return False
    local, _, domain = to.partition("@")
    if not local:
        return False
    if re.search(r"\s", to):
        return False
    return domain.lower() == variant.get("emailDomain", EMAIL_DOMAIN)


# --- entry point ------------------------------------------------------------

def handle(body):
    try:
        reason = _check_body(body)
        if reason:
            return _block(reason)

        action = body["action"]
        tool = action["tool"]
        args = action["args"]

        if tool not in ALLOWED_TOOLS:
            return _block("TOOL_NOT_ALLOWED")

        reason = _check_args(tool, args)
        if reason:
            return _block(reason)

        if tool == "lookup_record" and args["tenantId"] != variant.get("tenantId", TENANT_ID):
            return _block("TENANT_SCOPE")

        if tool == "send_email":
            if not _domain_allowed(args["to"]):
                return _block("EGRESS_DENIED")
            if body.get("humanApproved") is not True:
                return _block("APPROVAL_REQUIRED")

        if tool == "render_html" and _is_unsafe_html(args["html"]):
            return _block("UNSAFE_OUTPUT")

        return dict(ALLOW)
    except Exception:
        # never 500 - an unexpected shape is just a schema fault
        return _block("INVALID_SCHEMA")
