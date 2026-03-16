"""
pattern_scanner.py
==================
SauSec Password Strength Tool - Pattern Scanner
Detects weak and predictable patterns in passwords that make them
vulnerable to dictionary attacks, rule-based cracking, and social
engineering guesses — even if the entropy score looks acceptable.

Author  : SauSec
Version : 1.0.0

Patterns detected:
    1. Keyboard walks       — qwerty, asdf, zxcv, 12345
    2. Repeated characters  — aaaa, 1111, ....
    3. Sequential numbers   — 123, 456, 789, 890
    4. Year patterns        — 1990, 2024, 20xx, 19xx
    5. Date patterns        — MMDD format e.g. 0312, 1225
    6. Leet substitutions   — P@ssw0rd, Adm1n, L3tm3in
    7. Word + number        — Summer123, Admin2024!
    8. Length violations    — below 8 (fail), below 12 (warn)
"""

import re
import sys
from typing import List, Dict


# ── KEYBOARD WALK SEQUENCES ───────────────────────────────────────
# Stored as plain strings — detects common keyboard path patterns.
# Attacker dictionaries always include these sequences first.
KEYBOARD_WALKS = [
    "qwerty", "qwert", "werty",
    "asdfg", "asdf", "sdfgh",
    "zxcvb", "zxcv", "xcvbn",
    "12345", "123456", "1234567",
    "234567", "345678", "456789",
    "567890", "098765", "987654",
]

# ── LEET SUBSTITUTION MAP ─────────────────────────────────────────
# Maps common leet characters back to their alphabetic equivalents.
# Used to detect words disguised with symbol replacements.
LEET_MAP = str.maketrans({
    "@": "a",
    "$": "s",
    "!": "i",
    "0": "o",
    "1": "i",
    "3": "e",
    "8": "b",
    "5": "s",
    "+": "t",
    "4": "a",
    "7": "t",
    "|": "i",
})

# ── COMMON WORD LIST (leet check targets) ─────────────────────────
# Words that attackers always try first, with and without leet.
COMMON_WORDS = frozenset([
    "password", "letmein", "welcome", "monkey", "dragon",
    "admin", "iloveyou", "shadow", "qwerty", "superman",
    "batman", "master", "sunshine", "princess", "football",
    "soccer", "baseball", "hockey", "killer", "login",
    "access", "trustno", "abc", "test", "pass",
])

# ── LENGTH THRESHOLDS ─────────────────────────────────────────────
LENGTH_MINIMUM     = 8    # NIST 800-63B hard minimum
LENGTH_RECOMMENDED = 12   # Recommended for strong passwords


def detect_keyboard_walks(password: str) -> List[str]:
    """
    Detect keyboard walk sequences in the password.
    Checks both forward and reverse directions.
    Case-insensitive matching.
    """
    issues = []
    lower = password.lower()
    for walk in KEYBOARD_WALKS:
        if walk in lower:
            issues.append(f'keyboard walk "{walk}"')
        # Also check reverse direction
        rev = walk[::-1]
        if rev != walk and rev in lower:
            issues.append(f'reverse keyboard walk "{rev}"')
    return issues


def detect_repeated_chars(password: str) -> List[str]:
    """
    Detect runs of 3 or more identical characters.
    e.g. aaa, 1111, ....
    """
    issues = []
    if re.search(r"(.)\1{2,}", password):
        match = re.search(r"(.)\1{2,}", password)
        repeated_char = match.group(1)
        run_length = len(re.search(r"(.)\1+", match.group()).group())
        issues.append(
            f'repeated character "{repeated_char}" ({run_length}+ times)'
        )
    return issues


def detect_sequential_numbers(password: str) -> List[str]:
    """
    Detect ascending or descending number sequences of 3+ digits.
    e.g. 123, 456, 789, 987, 654
    """
    issues = []
    sequences = [
        "012", "123", "234", "345", "456",
        "567", "678", "789", "890",
        "987", "876", "765", "654",
        "543", "432", "321", "210",
    ]
    for seq in sequences:
        if seq in password:
            issues.append(f'sequential number run "{seq}"')
            break  # report once per password
    return issues


def detect_year_pattern(password: str) -> List[str]:
    """
    Detect year patterns (19xx or 20xx).
    Attackers always try birth years and recent years.
    """
    issues = []
    if re.search(r"(19|20)\d{2}", password):
        match = re.search(r"(19|20)\d{2}", password)
        issues.append(f'year pattern detected "{match.group()}"')
    return issues


def detect_date_pattern(password: str) -> List[str]:
    """
    Detect MMDD date patterns.
    e.g. 0101, 1225, 0704
    """
    issues = []
    if re.search(r"(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])", password):
        match = re.search(
            r"(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])", password
        )
        issues.append(f'date pattern MMDD "{match.group()}"')
    return issues


def detect_leet_substitution(password: str) -> List[str]:
    """
    Detect leet substitutions of common dictionary words.
    e.g. P@ssw0rd -> password, Adm1n -> admin
    Normalises the password using the leet map then checks
    against the common word list.
    """
    issues = []
    normalised = password.lower().translate(LEET_MAP)
    if normalised in COMMON_WORDS:
        issues.append(
            f'leet substitution of common word '
            f'("{password}" normalises to "{normalised}")'
        )
    return issues


def detect_word_number_pattern(password: str) -> List[str]:
    """
    Detect the classic word + number (+ optional symbol) pattern.
    e.g. Summer123, Admin2024, Football1!
    These are among the first patterns tried by rule-based crackers.
    """
    issues = []
    if re.match(r"^[a-zA-Z]{3,}[0-9]{1,6}[!@#$%^&*]?$", password):
        issues.append("word + number pattern (e.g. Name123 or Word2024!)")
    if re.match(r"^[A-Z][a-z]+[0-9]+$", password):
        issues.append("capitalised word + digits only")
    return issues


def detect_length_issues(password: str) -> List[str]:
    """
    Check password length against NIST 800-63B thresholds.
    Below 8  → hard violation
    Below 12 → recommendation warning
    """
    issues = []
    length = len(password)
    if length < LENGTH_MINIMUM:
        issues.append(
            f"too short: {length} chars (minimum {LENGTH_MINIMUM})"
        )
    elif length < LENGTH_RECOMMENDED:
        issues.append(
            f"short: {length} chars ({LENGTH_RECOMMENDED}+ recommended)"
        )
    return issues


def get_verdict(issue_count: int) -> str:
    """
    Convert issue count into a human-readable verdict.
    Matches the verdict labels used in script.js.
    """
    if issue_count == 0:
        return "clean"
    elif issue_count <= 2:
        return "minor patterns"
    else:
        return "significant patterns"


def analyze(password: str) -> dict:
    """
    Run all pattern detectors on the password and return a full report.

    Returns a dict with:
        issues   — list of detected pattern descriptions
        count    — total number of issues found
        verdict  — 'clean' | 'minor patterns' | 'significant patterns'
        length   — password length
        details  — breakdown of which detectors fired
    """
    if not password:
        return {
            "issues":  [],
            "count":   0,
            "verdict": "empty",
            "length":  0,
            "details": {},
        }

    detectors = {
        "keyboard_walks":     detect_keyboard_walks(password),
        "repeated_chars":     detect_repeated_chars(password),
        "sequential_numbers": detect_sequential_numbers(password),
        "year_patterns":      detect_year_pattern(password),
        "date_patterns":      detect_date_pattern(password),
        "leet_substitution":  detect_leet_substitution(password),
        "word_number":        detect_word_number_pattern(password),
        "length_issues":      detect_length_issues(password),
    }

    all_issues = []
    for found in detectors.values():
        all_issues.extend(found)

    # Deduplicate while preserving order
    seen = set()
    unique_issues = []
    for issue in all_issues:
        if issue not in seen:
            seen.add(issue)
            unique_issues.append(issue)

    return {
        "issues":  unique_issues,
        "count":   len(unique_issues),
        "verdict": get_verdict(len(unique_issues)),
        "length":  len(password),
        "details": {k: v for k, v in detectors.items() if v},
    }


# ── CLI runner ─────────────────────────────────────────────────────
if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage  : python pattern_scanner.py <password>")
        print("Example: python pattern_scanner.py Summer2024!")
        sys.exit(1)

    pw = sys.argv[1]
    result = analyze(pw)

    verdict_icon = {
        "clean":                "✓",
        "minor patterns":       "⚠",
        "significant patterns": "✗",
    }.get(result["verdict"], "?")

    print("\n[ SauSec Pattern Scanner ]")
    print("-" * 44)
    print(f"  Password length : {result['length']} chars")
    print(f"  Issues found    : {result['count']}")
    print(f"  Verdict         : {verdict_icon}  {result['verdict'].upper()}")
    print("-" * 44)

    if result["issues"]:
        print("  Patterns detected:")
        for issue in result["issues"]:
            print(f"    !  {issue}")
    else:
        print("  ✓  No weak patterns detected.")

    if result["details"]:
        print("\n  Detector breakdown:")
        for detector, findings in result["details"].items():
            label = detector.replace("_", " ").title()
            for f in findings:
                print(f"    [{label}]  {f}")

    print()