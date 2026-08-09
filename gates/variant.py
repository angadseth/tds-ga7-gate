"""Per-student variant derivation.

The exam builds each student's assigned tenant, workspace, labels and host
allowlist from a seeded PRNG keyed on their email. Reproducing that here lets a
single deployment answer correctly for any student: the identity travels in the
URL path, and the gates read the values for whoever is being graded.

The generator functions mirror the exam's own, so the sequence of draws must
match exactly — including how many characters each draw consumes.
"""

import base64
import binascii
import math
from contextlib import contextmanager
from contextvars import ContextVar

from seedrandom import seedrandom

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
VERSION = "v1"

#: Set per request; None means "use the module defaults compiled into the gates".
CURRENT = ContextVar("variant", default=None)


def _rng(question_id, email, version=VERSION):
    return seedrandom(f"{question_id}#{str(email or '').strip().lower()}#{version}")


def _chars(rng, n):
    return "".join(ALPHABET[math.floor(rng() * 36)] for _ in range(n))


def derive(email):
    """Return every per-student value this service needs, for one email."""
    rng = _rng("q-llm-action-firewall-server", email)
    tenant_id = "tenant-" + _chars(rng, 7)
    email_domain = "notify-" + _chars(rng, 7) + ".example"

    rng = _rng("q-terraform-plan-guard-server", email)
    environment = "prod-" + _chars(rng, 6)
    labels = {
        "owner": "student-" + _chars(rng, 5),
        "environment": "production",
        "cost_center": "cc-" + _chars(rng, 4),
    }

    rng = _rng("q-llm-output-sanitizer-server", email)
    allowed_hosts = frozenset(
        {"cdn-" + _chars(rng, 7) + ".example", "app-" + _chars(rng, 7) + ".example"}
    )

    rng = _rng("q-osint-corroboration-server", email)
    subject = _chars(rng, 6) + ".example"
    staleness_days = [90, 120, 180, 365][math.floor(rng() * 4)]

    return {
        "email": email,
        "tenantId": tenant_id,
        "emailDomain": email_domain,
        "environment": environment,
        "labels": labels,
        "allowedHosts": allowed_hosts,
        "subject": subject,
        "stalenessDays": staleness_days,
    }


def get(key, default):
    """Read one value for the request in flight, falling back to the default."""
    current = CURRENT.get()
    if not current:
        return default
    value = current.get(key)
    return default if value is None else value


@contextmanager
def use(config):
    token = CURRENT.set(config)
    try:
        yield
    finally:
        CURRENT.reset(token)


# --- identity in the URL ----------------------------------------------------

def encode_email(email):
    """base64url of the email, so a student's base URL carries their identity."""
    raw = str(email).strip().lower().encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_email(token):
    """Inverse of :func:`encode_email`; returns None if the token is not ours."""
    try:
        padded = token + "=" * (-len(token) % 4)
        email = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    email = email.strip().lower()
    # Cheap sanity check: this must look like an address, not arbitrary bytes.
    if email.count("@") != 1 or "." not in email.split("@")[1] or len(email) > 254:
        return None
    if any(ch.isspace() or ord(ch) < 32 for ch in email):
        return None
    return email


_CACHE = {}


def for_email(email):
    """Derive once per email; the values never change for a given address."""
    key = str(email).strip().lower()
    if key not in _CACHE:
        if len(_CACHE) > 5000:
            _CACHE.clear()
        _CACHE[key] = derive(key)
    return _CACHE[key]
