"""
entropy_calculator.py
=====================
SauSec Password Strength Tool — Entropy Calculator
Calculates Shannon entropy and keyspace bits for a given password.

Author  : SauSec
Version : 1.0.0
"""

import math
from collections import Counter


# ── THRESHOLDS (matches scoring engine in script.js) ──────────────
THRESHOLD_VERY_WEAK = 28    # bits
THRESHOLD_WEAK      = 36
THRESHOLD_MODERATE  = 60
THRESHOLD_STRONG    = 128


def calculate_charset_size(password: str) -> int:
    """
    Determine the effective character set size based on
    which character classes are present in the password.

    Lowercase a-z     → +26
    Uppercase A-Z     → +26
    Digits 0-9        → +10
    Symbols / special → +32
    """
    size = 0
    if any(c.islower() for c in password):
        size += 26
    if any(c.isupper() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(not c.isalnum() for c in password):
        size += 32
    return size


def shannon_entropy(password: str) -> float:
    """
    Calculate Shannon entropy in bits per character.

    Formula: H = -Σ p(x) * log2(p(x))
    where p(x) is the probability of each character.

    Higher value = more random character distribution.
    """
    if not password:
        return 0.0

    length = len(password)
    freq = Counter(password)
    entropy = 0.0

    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 2)


def keyspace_bits(password: str) -> float:
    """
    Calculate keyspace bits — the total search space for brute force.

    Formula: bits = len * log2(charset_size)

    Uses the logarithm identity log2(cs^len) = len * log2(cs)
    to avoid float overflow on long passwords (Math.pow overflows
    above ~50 chars with a full charset in JavaScript).

    Higher value = larger brute-force search space = harder to crack.
    """
    if not password:
        return 0.0

    cs = calculate_charset_size(password)
    if cs == 0:
        return 0.0

    length = len(password)
    bits = length * math.log2(cs)
    return round(bits, 1)


def get_verdict(kb: float) -> str:
    """
    Map keyspace bits to a human-readable strength verdict.
    Thresholds match the scoring engine in script.js.
    """
    if kb < THRESHOLD_VERY_WEAK:
        return "very weak"
    elif kb < THRESHOLD_WEAK:
        return "weak"
    elif kb < THRESHOLD_MODERATE:
        return "moderate"
    elif kb < THRESHOLD_STRONG:
        return "strong"
    else:
        return "very strong"


def analyze(password: str) -> dict:
    """
    Run the full entropy analysis on a password.

    Returns a dict with:
        shannon      — bits per character (float)
        keyspace_bits — total search space in bits (float)
        charset_size  — effective character set size (int)
        length        — password length (int)
        verdict       — strength label (str)
    """
    if not password:
        return {
            "shannon": 0.0,
            "keyspace_bits": 0.0,
            "charset_size": 0,
            "length": 0,
            "verdict": "empty"
        }

    kb = keyspace_bits(password)

    return {
        "shannon":       shannon_entropy(password),
        "keyspace_bits": kb,
        "charset_size":  calculate_charset_size(password),
        "length":        len(password),
        "verdict":       get_verdict(kb)
    }


# ── CLI runner ─────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python entropy_calculator.py <password>")
        print("Example: python entropy_calculator.py MyP@ssw0rd!")
        sys.exit(1)

    pw = sys.argv[1]
    result = analyze(pw)

    print("\n[ SauSec Entropy Calculator ]")
    print("-" * 36)
    print(f"  Password length : {result['length']} chars")
    print(f"  Charset size    : {result['charset_size']} chars")
    print(f"  Shannon entropy : {result['shannon']} bits/char")
    print(f"  Keyspace bits   : {result['keyspace_bits']} bits")
    print(f"  Verdict         : {result['verdict'].upper()}")
    print("-" * 36)