"""A faithful port of seedrandom 3.0.5 (the ARC4 generator).

The exam seeds every student's variant with this exact PRNG, so the service has
to reproduce it bit for bit — a generator that is merely "random the same way"
would hand a student someone else's tenant id. Ported from the published
source rather than reimplemented, and checked against the JavaScript original
across a sweep of emails in tests/test_seedrandom.py.
"""

WIDTH = 256
MASK = WIDTH - 1
CHUNKS = 6
DIGITS = 52
STARTDENOM = float(WIDTH**CHUNKS)
SIGNIFICANCE = float(2**DIGITS)
OVERFLOW = SIGNIFICANCE * 2


class _ARC4:
    def __init__(self, key):
        if not key:
            key = [0]
        self.i = 0
        self.j = 0
        self.S = list(range(WIDTH))
        keylen = len(key)

        j = 0
        for i in range(WIDTH):
            t = self.S[i]
            j = MASK & (j + key[i % keylen] + t)
            self.S[i] = self.S[j]
            self.S[j] = t

        # RC4-drop[256]: the original discards a first batch inside the
        # constructor. Leaving it out yields a plausible but entirely wrong
        # stream, which is exactly the kind of bug that silently hands a
        # student someone else's variant.
        self.g(WIDTH)

    def g(self, count):
        """The original returns a `count`-digit base-256 number."""
        r = 0
        i, j, S = self.i, self.j, self.S
        for _ in range(count):
            i = MASK & (i + 1)
            t = S[i]
            j = MASK & (j + t)
            S[i] = S[j]
            S[j] = t
            r = r * WIDTH + S[MASK & (S[i] + t)]
        self.i, self.j = i, j
        return r


def _mixkey(seed):
    """Fold the seed string into a 256-entry key array.

    `smear` in the original starts undefined, and every slot is read before it
    is written, so for seeds shorter than 256 characters it stays 0 throughout —
    which is why this reduces to the low byte of each character.
    """
    key = {}
    smear = 0
    for j, ch in enumerate(str(seed)):
        idx = MASK & j
        prev = key.get(idx)
        # undefined * 19 is NaN, and NaN coerces to 0 under ^.
        smear ^= (prev * 19) if prev is not None else 0
        key[idx] = MASK & (smear + ord(ch))
    if not key:
        return []
    return [key.get(i, 0) for i in range(max(key) + 1)]


def seedrandom(seed):
    """Return a callable producing the same float sequence as seedrandom(seed)."""
    arc4 = _ARC4(_mixkey(seed))

    def prng():
        n = float(arc4.g(CHUNKS))
        d = STARTDENOM
        x = 0
        while n < SIGNIFICANCE:
            n = (n + x) * WIDTH
            d *= WIDTH
            x = arc4.g(1)
        while n >= OVERFLOW:
            n /= 2
            d /= 2
            x >>= 1
        return (n + x) / d

    return prng
