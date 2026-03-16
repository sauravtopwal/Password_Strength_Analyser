"""
scoring_engine.py
=================
SauSec Password Strength Tool - Scoring Engine
Combines results from all 4 analysis tools into a final
weighted score (0-100) with verdict and recommendations.

Author  : SauSec
Version : 1.0.0

Scoring breakdown:
    Entropy score   : 0 - 40 pts  (keyspace bits / 3.5, capped at 40)
    Breach penalty  : -50 pts     (if found in breach DB)
    Breach bonus    :  +20 pts    (if clean)
    Pattern score   : 0 - 25 pts  (25 - (issue_count * 8))
    Policy score    : 0 - 15 pts  (15 - violations*8 - warnings*3)
    ─────────────────────────────
    Total           : 0 - 100 pts (clamped)

Verdict thresholds:
    CRITICAL    — found in breach database (regardless of score)
    Weak        — score < 30
    Moderate    — score 30–54
    Strong      — score 55–77
    Very Strong — score 78–100
"""

import sys
from typing import Optional


# ── SCORING CONSTANTS ─────────────────────────────────────────────
ENTROPY_MAX_PTS      = 40     # max points from entropy
ENTROPY_DIVISOR      = 3.5    # keyspace_bits / this = entropy pts
BREACH_CLEAN_BONUS   = 20     # pts awarded if not in any breach
BREACH_PENALTY       = -50    # pts deducted if found in breach
PATTERN_MAX_PTS      = 25     # max points from pattern scan
PATTERN_DEDUCT       = 8      # pts deducted per pattern issue
POLICY_MAX_PTS       = 15     # max points from NIST policy
POLICY_VIOL_DEDUCT   = 8      # pts deducted per violation
POLICY_WARN_DEDUCT   = 3      # pts deducted per warning

# ── VERDICT THRESHOLDS ────────────────────────────────────────────
THRESHOLD_WEAK       = 30
THRESHOLD_MODERATE   = 55
THRESHOLD_STRONG     = 78

# ── RECOMMENDATION TEMPLATES ──────────────────────────────────────
REC_BREACHED      = "PASSWORD COMPROMISED — found in breach database. Stop using it immediately."
REC_SHORT         = "Increase length to minimum 12 chars. Target 16+ for sensitive accounts."
REC_CHARSET       = "Expand character set: mix uppercase, lowercase, digits and symbols."
REC_KEYBOARD      = "Remove keyboard walk pattern (e.g. qwerty, asdf)."
REC_LEET          = "Leet substitutions (@ for a, 0 for o) are well-known to crackers. Avoid them."
REC_YEAR          = "Remove date/year patterns — they are the first guessed by automated tools."
REC_REPEATED      = "Eliminate repeated character sequences (e.g. aaa, 111)."
REC_WORD_NUMBER   = "Word + digits combos (e.g. Name123) are trivially guessed. Redesign."
REC_DATE          = "Date patterns (MMDD format) are predictable — remove them."
REC_STRONG        = "Excellent. Consider a password manager to generate 20+ char random strings."
REC_MFA           = "Enable multi-factor authentication (MFA/2FA) wherever this password is used."


def compute_entropy_score(entropy_result: dict) -> int:
    """
    Convert keyspace bits into an entropy score (0–40 pts).
    Uses integer division capped at ENTROPY_MAX_PTS.
    """
    kb = entropy_result.get("keyspace_bits", 0)
    score = min(ENTROPY_MAX_PTS, round(kb / ENTROPY_DIVISOR))
    return max(0, score)


def compute_breach_score(breach_result: dict) -> int:
    """
    Return breach bonus or penalty.
    -50 if found in any breach database.
    +20 if completely clean.
    """
    if breach_result.get("found", False):
        return BREACH_PENALTY
    return BREACH_CLEAN_BONUS


def compute_pattern_score(pattern_result: dict) -> int:
    """
    Deduct points for each detected pattern issue.
    Clamped to 0 minimum.
    """
    count = pattern_result.get("count", 0)
    score = PATTERN_MAX_PTS - (count * PATTERN_DEDUCT)
    return max(0, score)


def compute_policy_score(policy_result: dict) -> int:
    """
    Deduct points for NIST 800-63B violations and warnings.
    Clamped to 0 minimum.
    """
    violations = len(policy_result.get("violations", []))
    warnings   = len(policy_result.get("warnings", []))
    score = POLICY_MAX_PTS - (violations * POLICY_VIOL_DEDUCT) - (warnings * POLICY_WARN_DEDUCT)
    return max(0, score)


def compute_total(entropy_score: int, breach_score: int,
                  pattern_score: int, policy_score: int) -> int:
    """
    Sum all component scores and clamp to 0–100 range.
    """
    total = entropy_score + breach_score + pattern_score + policy_score
    return max(0, min(100, total))


def get_verdict(total: int, breach_result: dict) -> str:
    """
    Determine the final verdict label.
    Breach always results in CRITICAL regardless of other scores.
    """
    if breach_result.get("found") and breach_result.get("verdict") == "compromised":
        return "CRITICAL"
    if total < THRESHOLD_WEAK:
        return "Weak"
    if total < THRESHOLD_MODERATE:
        return "Moderate"
    if total < THRESHOLD_STRONG:
        return "Strong"
    return "Very Strong"


def build_summary(breach_result: dict, pattern_result: dict,
                  entropy_result: dict, policy_result: dict) -> str:
    """
    Build a one-line human-readable summary of issues found.
    """
    parts = []
    if breach_result.get("found"):
        parts.append("found in breach database")
    if pattern_result.get("count", 0) > 0:
        n = pattern_result["count"]
        parts.append(f"{n} weak pattern{'s' if n > 1 else ''} detected")
    if entropy_result.get("keyspace_bits", 0) < 36:
        parts.append("low entropy")
    if policy_result.get("violations"):
        parts.append("NIST violations present")

    if not parts:
        return "All checks passed. Password meets security criteria."
    return "Issues: " + " | ".join(parts)


def build_recommendations(entropy_result: dict, breach_result: dict,
                           pattern_result: dict, policy_result: dict) -> list:
    """
    Build a prioritised list of actionable recommendations.
    Most critical issues (breach) appear first.
    Returns up to 6 recommendations.
    """
    recs = []

    # Breach — highest priority
    if breach_result.get("found"):
        recs.append(REC_BREACHED)

    # Length
    if entropy_result.get("length", 0) < 12:
        recs.append(REC_SHORT)

    # Charset diversity
    if entropy_result.get("charset_size", 0) < 60:
        recs.append(REC_CHARSET)

    # Pattern-specific recommendations
    for issue in pattern_result.get("issues", []):
        if "keyboard walk" in issue and REC_KEYBOARD not in recs:
            recs.append(REC_KEYBOARD)
        elif "leet substitution" in issue and REC_LEET not in recs:
            recs.append(REC_LEET)
        elif "year pattern" in issue and REC_YEAR not in recs:
            recs.append(REC_YEAR)
        elif "repeated" in issue and REC_REPEATED not in recs:
            recs.append(REC_REPEATED)
        elif "word + number" in issue and REC_WORD_NUMBER not in recs:
            recs.append(REC_WORD_NUMBER)
        elif "date pattern" in issue and REC_DATE not in recs:
            recs.append(REC_DATE)

    # Policy violations
    for v in policy_result.get("violations", []):
        recs.append(f"Policy violation: {v}")

    # Policy warnings
    for w in policy_result.get("warnings", []):
        recs.append(f"Tip: {w}")

    # Fallback for perfect passwords
    if not recs:
        recs.append(REC_STRONG)

    # Always suggest MFA
    recs.append(REC_MFA)

    return recs[:6]


def analyze(entropy_result: dict, breach_result: dict,
            pattern_result: dict, policy_result: dict) -> dict:
    """
    Combine all 4 tool results into a final scored report.

    Parameters:
        entropy_result  — output from entropy_calculator.analyze()
        breach_result   — output from breach_db_checker.analyze()
        pattern_result  — output from pattern_scanner.analyze()
        policy_result   — output from nist_validator.analyze()

    Returns a dict with:
        score        — integer 0–100
        verdict      — CRITICAL | Weak | Moderate | Strong | Very Strong
        summary      — one-line issue summary
        recommendations — list of up to 6 actionable tips
        components   — breakdown of each score component
    """
    entropy_score = compute_entropy_score(entropy_result)
    breach_score  = compute_breach_score(breach_result)
    pattern_score = compute_pattern_score(pattern_result)
    policy_score  = compute_policy_score(policy_result)
    total         = compute_total(entropy_score, breach_score,
                                  pattern_score, policy_score)
    verdict       = get_verdict(total, breach_result)
    summary       = build_summary(breach_result, pattern_result,
                                  entropy_result, policy_result)
    recommendations = build_recommendations(entropy_result, breach_result,
                                            pattern_result, policy_result)

    return {
        "score":           total,
        "verdict":         verdict,
        "summary":         summary,
        "recommendations": recommendations,
        "components": {
            "entropy":  max(0, entropy_score),
            "breach":   max(0, breach_score),
            "pattern":  pattern_score,
            "policy":   policy_score,
        },
    }


# ── CLI DEMO — runs all 4 tools and scores the result ─────────────
if __name__ == "__main__":

    # Import the other tool modules if available
    try:
        from entropy_calculator import analyze as entropy_analyze
        from breach_db_checker  import analyze as breach_analyze
        from pattern_scanner    import analyze as pattern_analyze
    except ImportError:
        print("Note: place entropy_calculator.py, breach_db_checker.py,")
        print("      pattern_scanner.py in the same directory for full analysis.")
        print()

    if len(sys.argv) < 2:
        print("Usage  : python scoring_engine.py <password>")
        print("Example: python scoring_engine.py Summer2024!")
        sys.exit(1)

    pw = sys.argv[1]

    # ── Run all 4 tools ──
    try:
        e_result = entropy_analyze(pw)
    except Exception:
        e_result = {"keyspace_bits": 0, "charset_size": 0, "length": len(pw)}

    try:
        b_result = breach_analyze(pw)
    except Exception:
        b_result = {"found": False, "count": 0, "verdict": "unknown"}

    try:
        p_result = pattern_analyze(pw)
    except Exception:
        p_result = {"issues": [], "count": 0, "verdict": "clean"}

    # Minimal inline NIST check (nist_validator.py not imported separately)
    v, w = [], []
    if len(pw) < 8:
        v.append("below minimum length (8)")
    elif len(pw) < 12:
        w.append("recommend 12+ chars")
    if len(pw) > 128:
        v.append("exceeds max (128)")
    div = sum([
        bool(any(c.islower() for c in pw)),
        bool(any(c.isupper() for c in pw)),
        bool(any(c.isdigit() for c in pw)),
        bool(any(not c.isalnum() for c in pw)),
    ])
    if div < 2:
        v.append("only 1 character type")
    elif div < 3:
        w.append("add a 3rd character type")
    pol_result = {
        "compliant":   len(v) == 0,
        "violations":  v,
        "warnings":    w,
        "diversity":   f"{div}/4 types",
        "length":      len(pw),
    }

    # ── Score ──
    result = analyze(e_result, b_result, p_result, pol_result)

    # ── Verdict icon ──
    icon = {
        "CRITICAL":   "☠",
        "Weak":       "✗",
        "Moderate":   "⚠",
        "Strong":     "✓",
        "Very Strong":"★",
    }.get(result["verdict"], "?")

    # ── Output ──
    print("\n[ SauSec Scoring Engine — Full Report ]")
    print("=" * 48)
    print(f"  Final Score  :  {result['score']} / 100")
    print(f"  Verdict      :  {icon}  {result['verdict']}")
    print(f"  Summary      :  {result['summary']}")
    print()
    print("  Score Breakdown:")
    print(f"    Entropy  : +{result['components']['entropy']} pts")
    print(f"    Breach   : {'+' if result['components']['breach'] >= 0 else ''}{result['components']['breach']} pts")
    print(f"    Patterns : +{result['components']['pattern']} pts")
    print(f"    Policy   : +{result['components']['policy']} pts")
    print()
    print("  Tool Results:")
    print(f"    [Entropy]  {e_result.get('keyspace_bits', 0)} bits  —  {e_result.get('verdict', 'n/a')}")
    print(f"    [Breach ]  {'FOUND ⚠' if b_result.get('found') else 'clean'}  —  {b_result.get('source', 'n/a')}")
    print(f"    [Pattern]  {p_result.get('count', 0)} issues  —  {p_result.get('verdict', 'n/a')}")
    print(f"    [Policy ]  {'compliant' if pol_result['compliant'] else 'violations'}  —  {pol_result['diversity']}")
    print()
    print("  Recommendations:")
    for i, rec in enumerate(result["recommendations"], 1):
        print(f"    {i}. {rec}")
    print("=" * 48)
    print()