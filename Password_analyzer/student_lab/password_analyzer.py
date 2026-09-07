# LAB 2: Password Security Analyzer — STUDENT VERSION
# password_analyzer.py — Implement the 4 TODO functions below
# DO NOT modify anything outside the TODO sections

import math
import re
import string
from dataclasses import dataclass, field
from typing import List, Tuple, Dict


# ── Data structure ────────────────────────────────────────────────

@dataclass
class PasswordAnalysis:
    password:        str
    length:          int   = 0
    entropy_bits:    float = 0.0
    charset_size:    int   = 0
    strength_score:  int   = 0
    strength_label:  str   = "Unknown"
    char_classes:    List[str] = field(default_factory=list)
    breach_count:    int   = 0
    breach_risk:     str   = "Unknown"
    crack_time_sec:  float = 0.0
    crack_time_label: str  = "Unknown"
    final_grade:     str   = "?"
    final_score:     float = 0.0
    suggestions:     List[str] = field(default_factory=list)


# ── Character class definitions: name → (characters, pool size N) ─

CHAR_CLASSES: Dict[str, Tuple[str, int]] = {
    "lowercase": (string.ascii_lowercase, 26),
    "uppercase": (string.ascii_uppercase, 26),
    "digits":    (string.digits,           10),
    "special":   (string.punctuation,      32),
    "space":     (" ",                      1),
}

#  TASK 1 — detect_char_classes(password)
# Loop CHAR_CLASSES. For each class, check if any character in the
# password belongs to it using:  any(c in chars for c in password)
# Accumulate the pool size and class name list.
# Return (classes, pool) — pool is N in H = L × log₂(N)
#
# Examples:
#   detect_char_classes("hello")   → (["lowercase"], 26)
#   detect_char_classes("Hello1!") → (["lowercase","uppercase","digits","special"], 94)
#   detect_char_classes("1234")    → (["digits"], 10)

def detect_char_classes(password: str) -> Tuple[List[str], int]:
    classes = []
    pool = 0
    # ── YOUR CODE HERE ────────────────────────────────────────


    pass  # remove this line when done
    return classes, pool



# ── Entropy: H = L × log₂(N) — do not modify ────────────────────

def calculate_entropy(password: str) -> float:
    if not password:
        return 0.0
    _, pool_size = detect_char_classes(password)
    if pool_size == 0:
        return 0.0
    combinatorial = len(password) * math.log2(pool_size)
    freq: dict = {}
    for ch in password:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(password)
    shannon = -sum((c / n) * math.log2(c / n) for c in freq.values())
    return round(max(combinatorial, shannon * n), 2)


# ── NIST strength scoring — do not modify ────────────────────────

_PENALTY_PATTERNS = [
    (re.compile(r"(.)\1{2,}"),                                                                      "Repeated characters",           15),
    (re.compile(r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)", re.IGNORECASE), "Keyboard/alpha sequence", 15),
    (re.compile(r"^[A-Z][a-z]+\d{1,4}$"),                                                          "Predictable Word+digits pattern", 10),
    (re.compile(r"(password|passwd|pass|qwerty|letmein|welcome|admin|login|root|user|test)", re.IGNORECASE), "Common password fragment",   25),
]

def score_password(password: str) -> Tuple[int, str, List[str]]:
    entropy = calculate_entropy(password)
    classes, _ = detect_char_classes(password)
    length = len(password)
    suggestions: List[str] = []

    if   entropy < 28: score = 10
    elif entropy < 36: score = 30
    elif entropy < 60: score = 50
    elif entropy < 80: score = 70
    else:              score = 90

    if   length >= 16:      score += 10
    elif length >= 12:      score += 5
    if   len(classes) >= 4: score += 10
    elif len(classes) == 3: score += 5

    for pattern, desc, penalty in _PENALTY_PATTERNS:
        if pattern.search(password):
            score -= penalty
            suggestions.append(f"Avoid: {desc.lower()}.")

    if "uppercase" not in classes: suggestions.append("Add uppercase letters.")
    if "lowercase" not in classes: suggestions.append("Add lowercase letters.")
    if "digits"    not in classes: suggestions.append("Add digits.")
    if "special"   not in classes: suggestions.append("Add special characters (!@#$...).")
    if length < 12: suggestions.append(f"Increase length to at least 12 (currently {length}).")

    score = max(0, min(100, score))
    if   score < 20: label = "Very Weak"
    elif score < 40: label = "Weak"
    elif score < 60: label = "Fair"
    elif score < 80: label = "Strong"
    else:            label = "Very Strong"

    return score, label, suggestions


# ── Breach data: populated at startup by report_generator.py ─────

BREACH_DATA: Dict[str, int] = {}  # { "password": rank } — rank 1 = most common

def load_breach_data(passwords: List[str]) -> None:
    BREACH_DATA.clear()
    for rank, pw in enumerate(passwords, start=1):
        if pw not in BREACH_DATA:
            BREACH_DATA[pw] = rank


#  TASK 2 — calculate_breach_risk(password)
#
# Build 12 mutations of the password (case variants, digit suffixes,
# leet substitutions). Count how many appear in BREACH_DATA.
# Return (count, risk_label).
#
# Mutations to build:
#   password, password.lower(), password.upper(), password.capitalize(),
#   password+"1", password+"123", password+"!",
#   lower.replace("a","@"), lower.replace("o","0"),
#   lower.replace("e","3"), lower.replace("s","$"), lower.replace("i","1")
#
# Risk thresholds:
#   rank <= 1000 (exact match in top 1000) → "Critical"
#   count >= 7  → "Critical"
#   count >= 4  → "High"
#   count >= 2  → "Medium"
#   count == 1  → "Low"
#   count == 0  → "None"
#
# Examples:
#   calculate_breach_risk("password") → (8, "Critical")
#   calculate_breach_risk("x9#Km2$v") → (0, "None")

def calculate_breach_risk(password: str) -> Tuple[int, str]:
    if not BREACH_DATA:
        return 0, "Unknown"

    mutations = [
        password,
        password.lower(),
        password.upper(),
        password.capitalize(),
        password + "1",
        password + "123",
        password + "!",
        password.lower().replace("a", "@"),
        password.lower().replace("o", "0"),
        password.lower().replace("e", "3"),
        password.lower().replace("s", "$"),
        password.lower().replace("i", "1"),
    ]

    # ── YOUR CODE HERE 
    count = 0
    risk  = "None"


    pass  # remove this line when done
    return count, risk


# ── GPU attack speed constants — do not modify ───────────────────
#
# Real-world Hashcat benchmarks on a consumer GPU (RTX 4090):
#   SHA-256:  10,000,000,000 hashes/sec  (10 billion)
#
# Your lab CPU does ~1.5M/sec. A $300 GPU does 10 billion/sec.
# That is 6,600x faster. This is why password length matters.

GPU_HASHES_PER_SEC = 10_000_000_000  # RTX 4090 on SHA-256


def _time_label(seconds: float) -> str:
    # Convert seconds into a human-readable time label
    if seconds < 60:
        return "under 1 minute"
    if seconds < 3_600:
        m = int(seconds / 60)
        return f"{m} minute{'s' if m != 1 else ''}"
    if seconds < 86_400:
        h = int(seconds / 3_600)
        return f"{h} hour{'s' if h != 1 else ''}"
    if seconds < 604_800:
        d = int(seconds / 86_400)
        return f"{d} day{'s' if d != 1 else ''}"
    if seconds < 2_592_000:
        w = int(seconds / 604_800)
        return f"{w} week{'s' if w != 1 else ''}"
    if seconds < 31_536_000:
        mo = int(seconds / 2_592_000)
        return f"{mo} month{'s' if mo != 1 else ''}"
    if seconds < 3_153_600_000:
        y = int(seconds / 31_536_000)
        return f"{y} year{'s' if y != 1 else ''}"
    if seconds < 3.154e13:
        c = int(seconds / 3_153_600_000)
        return f"{c} centuries"
    return "longer than human civilisation"


# ════════════════════════════════════════════════════════════════
#  TASK 3 — estimate_crack_time(password)
# ════════════════════════════════════════════════════════════════
#
# Estimate how long a GPU would take to crack this password.
#
# Formula:
#   Step 1: total_combinations = 2 ** entropy_bits
#   Step 2: crack_time_seconds = total_combinations / GPU_HASHES_PER_SEC
#   Step 3: divide by 2 (attacker finds it halfway on average)
#   Step 4: pass result to _time_label() for human-readable string
#
# Return (crack_time_seconds, label)
#
# Examples (approximate):
#   estimate_crack_time("mrbean")        → (small,     "under 1 minute")
#   estimate_crack_time("jamiroquai")    → (medium,    "1 hour")
#   estimate_crack_time("liverpool11")   → (large,     "2 months")
#   estimate_crack_time("L9vEVzZ9+4%4") → (very large, "7571 centuries")

def estimate_crack_time(password: str) -> Tuple[float, str]:
    entropy = calculate_entropy(password)
    # ── YOUR CODE HERE ────────────────────────────────────────


    pass  # remove this line when done


# ── Grade weights — do not modify ────────────────────────────────

GRADE_WEIGHTS = {
    "entropy":    0.40,
    "breach":     0.35,
    "crack_time": 0.25,
}

GRADE_THRESHOLDS = [
    (95, "A+"), (88, "A"), (80, "A-"),
    (72, "B+"), (65, "B"), (58, "B-"),
    (50, "C+"), (42, "C"), (35, "C-"),
    (25, "D"),  (0,  "F"),
]


#  TASK 4 — calculate_final_grade(password)
# Combine entropy, breach risk, and crack time into one weighted
# final score (0–100), then convert to a letter grade A+ to F.
# Step 1 — entropy score (0–100):
#   entropy_score = min(100, (entropy_bits / 128) * 100)
#
# Step 2 — breach score (0–100):
#   "None"→100  "Low"→75  "Medium"→50  "High"→25  "Critical"→0  "Unknown"→50
#
# Step 3 — crack time score (0–100):
#   >= 3,153,600,000 sec (100 years) → 100
#   >=    31,536,000 sec (1 year)    → 80
#   >=     2,592,000 sec (1 month)   → 60
#   >=        86,400 sec (1 day)     → 40
#   >=         3,600 sec (1 hour)    → 20
#   anything less                   → 0
#
# Step 4 — weighted final score:
#   final_score = (entropy_score * GRADE_WEIGHTS["entropy"]
#               + breach_score   * GRADE_WEIGHTS["breach"]
#               + crack_score    * GRADE_WEIGHTS["crack_time"])
#
# Step 5 — letter grade from GRADE_THRESHOLDS:
#   Loop the list, return the grade for the first threshold the score meets.
#
# Return (final_score, grade)

def calculate_final_grade(password: str) -> Tuple[float, str]:
    entropy         = calculate_entropy(password)
    _, breach_risk  = calculate_breach_risk(password)
    crack_time_sec, _ = estimate_crack_time(password)

    # ── YOUR CODE HERE 


    pass  # remove this line when done


# ── Pipeline — do not modify 

def analyze_password(password: str) -> PasswordAnalysis:
    classes_result = detect_char_classes(password)
    if classes_result is None:
        raise NotImplementedError(
            "\n\n  ╔══════════════════════════════════════════════╗"
            "\n  ║  TASK 1 not yet implemented!                 ║"
            "\n  ║  Complete detect_char_classes() first.       ║"
            "\n  ╚══════════════════════════════════════════════╝\n"
        )
    breach_result = calculate_breach_risk(password)
    if breach_result is None:
        raise NotImplementedError(
            "\n\n  ╔══════════════════════════════════════════════╗"
            "\n  ║  TASK 2 not yet implemented!                 ║"
            "\n  ║  Complete calculate_breach_risk() first.     ║"
            "\n  ╚══════════════════════════════════════════════╝\n"
        )
    crack_result = estimate_crack_time(password)
    if crack_result is None:
        raise NotImplementedError(
            "\n\n  ╔══════════════════════════════════════════════╗"
            "\n  ║  TASK 3 not yet implemented!                 ║"
            "\n  ║  Complete estimate_crack_time() first.       ║"
            "\n  ╚══════════════════════════════════════════════╝\n"
        )
    grade_result = calculate_final_grade(password)
    if grade_result is None:
        raise NotImplementedError(
            "\n\n  ╔══════════════════════════════════════════════╗"
            "\n  ║  TASK 4 not yet implemented!                 ║"
            "\n  ║  Complete calculate_final_grade() first.     ║"
            "\n  ╚══════════════════════════════════════════════╝\n"
        )

    result = PasswordAnalysis(password=password)
    result.length = len(password)
    result.entropy_bits = calculate_entropy(password)
    result.char_classes, result.charset_size = classes_result
    result.strength_score, result.strength_label, result.suggestions = score_password(password)
    result.breach_count, result.breach_risk = breach_result
    result.crack_time_sec, result.crack_time_label = crack_result
    result.final_score, result.final_grade = grade_result
    return result


def analyze_batch(passwords: List[str]) -> List[PasswordAnalysis]:
    return [analyze_password(p) for p in passwords]
