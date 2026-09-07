# LAB 2: Password Security Analyzer — REFERENCE SOLUTION
# password_analyzer.py

import math
import re
import string
from dataclasses import dataclass, field
from typing import List, Tuple, Dict


@dataclass
class PasswordAnalysis:
    password:         str
    length:           int   = 0
    entropy_bits:     float = 0.0
    charset_size:     int   = 0
    strength_score:   int   = 0
    strength_label:   str   = "Unknown"
    char_classes:     List[str] = field(default_factory=list)
    breach_count:     int   = 0
    breach_risk:      str   = "Unknown"
    crack_time_sec:   float = 0.0
    crack_time_label: str   = "Unknown"
    final_grade:      str   = "?"
    final_score:      float = 0.0
    suggestions:      List[str] = field(default_factory=list)


CHAR_CLASSES: Dict[str, Tuple[str, int]] = {
    "lowercase": (string.ascii_lowercase, 26),
    "uppercase": (string.ascii_uppercase, 26),
    "digits":    (string.digits,           10),
    "special":   (string.punctuation,      32),
    "space":     (" ",                      1),
}


# ── TASK 1 ────────────────────────────────────────────────────────
def detect_char_classes(password: str) -> Tuple[List[str], int]:
    classes = []
    pool = 0
    for name, (chars, size) in CHAR_CLASSES.items():
        if any(c in chars for c in password):
            classes.append(name)
            pool += size
    return classes, pool


# ── Entropy 
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


# ── Strength scoring 
_PENALTY_PATTERNS = [
    (re.compile(r"(.)\1{2,}"), "Repeated characters", 15),
    (re.compile(r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)", re.IGNORECASE), "Keyboard/alpha sequence", 15),
    (re.compile(r"^[A-Z][a-z]+\d{1,4}$"), "Predictable Word+digits pattern", 10),
    (re.compile(r"(password|passwd|pass|qwerty|letmein|welcome|admin|login|root|user|test)", re.IGNORECASE), "Common password fragment", 25),
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


# ── Breach data 
BREACH_DATA: Dict[str, int] = {}

def load_breach_data(passwords: List[str]) -> None:
    BREACH_DATA.clear()
    for rank, pw in enumerate(passwords, start=1):
        if pw not in BREACH_DATA:
            BREACH_DATA[pw] = rank


# ── TASK 2 
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

    count = sum(1 for m in mutations if m in BREACH_DATA)

    if password in BREACH_DATA and BREACH_DATA[password] <= 1000:
        risk = "Critical"
    elif count >= 7: risk = "Critical"
    elif count >= 4: risk = "High"
    elif count >= 2: risk = "Medium"
    elif count == 1: risk = "Low"
    else:            risk = "None"

    return count, risk


# ── GPU constants ─────────────────────────────────────────────────
GPU_HASHES_PER_SEC = 10_000_000_000


def _time_label(seconds: float) -> str:
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


# ── TASK 3 ────────────────────────────────────────────────────────
def estimate_crack_time(password: str) -> Tuple[float, str]:
    entropy = calculate_entropy(password)
    total_combinations = 2 ** entropy
    crack_time_seconds = (total_combinations / GPU_HASHES_PER_SEC) / 2
    label = _time_label(crack_time_seconds)
    return round(crack_time_seconds, 2), label


# ── Grade constants ───────────────────────────────────────────────
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


# ── TASK 4 ────────────────────────────────────────────────────────
def calculate_final_grade(password: str) -> Tuple[float, str]:
    entropy          = calculate_entropy(password)
    _, breach_risk   = calculate_breach_risk(password)
    crack_time_sec, _ = estimate_crack_time(password)

    entropy_score = min(100.0, (entropy / 128.0) * 100)

    breach_map = {"None": 100, "Low": 75, "Medium": 50, "High": 25, "Critical": 0, "Unknown": 50}
    breach_score = breach_map.get(breach_risk, 50)

    if   crack_time_sec >= 3_153_600_000: crack_score = 100
    elif crack_time_sec >= 31_536_000:    crack_score = 80
    elif crack_time_sec >= 2_592_000:     crack_score = 60
    elif crack_time_sec >= 86_400:        crack_score = 40
    elif crack_time_sec >= 3_600:         crack_score = 20
    else:                                 crack_score = 0

    final_score = round(
        entropy_score  * GRADE_WEIGHTS["entropy"]
        + breach_score * GRADE_WEIGHTS["breach"]
        + crack_score  * GRADE_WEIGHTS["crack_time"],
        1
    )

    grade = "F"
    for threshold, letter in GRADE_THRESHOLDS:
        if final_score >= threshold:
            grade = letter
            break

    return final_score, grade


# ── Pipeline ──────────────────────────────────────────────────────
def analyze_password(password: str) -> PasswordAnalysis:
    result = PasswordAnalysis(password=password)
    result.length = len(password)
    result.entropy_bits = calculate_entropy(password)
    result.char_classes, result.charset_size = detect_char_classes(password)
    result.strength_score, result.strength_label, result.suggestions = score_password(password)
    result.breach_count, result.breach_risk = calculate_breach_risk(password)
    result.crack_time_sec, result.crack_time_label = estimate_crack_time(password)
    result.final_score, result.final_grade = calculate_final_grade(password)
    return result


def analyze_batch(passwords: List[str]) -> List[PasswordAnalysis]:
    return [analyze_password(p) for p in passwords]
