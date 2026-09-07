# LAB 2: Password Security Analyzer
# report_generator.py — Entry point. Run: python report_generator.py

import string
from datetime import datetime
from typing import List

from generator import generate_password_set, fetch_rockyou
from password_analyzer import (
    analyze_password, analyze_batch, load_breach_data,
    PasswordAnalysis, GRADE_WEIGHTS
)
from hash_cracker import hash_password, dictionary_attack, brute_force_attack, identify_hash_type

COLOURS = {
    "Very Weak": "\033[91m", "Weak": "\033[93m", "Fair": "\033[33m",
    "Strong": "\033[92m", "Very Strong": "\033[96m",
}
RISK_COLOURS = {
    "Critical": "\033[91m", "High": "\033[93m", "Medium": "\033[33m",
    "Low": "\033[92m", "None": "\033[96m", "Unknown": "\033[37m",
}
GRADE_COLOURS = {
    "A+": "\033[96m", "A": "\033[96m", "A-": "\033[96m",
    "B+": "\033[92m", "B": "\033[92m", "B-": "\033[92m",
    "C+": "\033[33m", "C": "\033[33m", "C-": "\033[33m",
    "D":  "\033[93m", "F":  "\033[91m",
}
RESET = "\033[0m"


def _c(label, text, use_colour, table=None):
    if not use_colour:
        return text
    t = table if table else COLOURS
    return f"{t.get(label, '')}{text}{RESET}"


def _bar(score, width=28):
    filled = round(score / 100 * width)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def print_individual_analysis(passwords, use_colour=True):
   
    print("  [1] INDIVIDUAL PASSWORD ANALYSIS")
    print(f"  {'─' * 44}")

    for i, pwd in enumerate(passwords, 1):
        a = analyze_password(pwd)
        label_c = _c(a.strength_label, a.strength_label, use_colour)
        risk_c  = _c(a.breach_risk, a.breach_risk, use_colour, RISK_COLOURS)
        grade_c = _c(a.final_grade, a.final_grade, use_colour, GRADE_COLOURS)

        print(f"\n  Password #{i}: {a.password}")
        print(f"  {'─' * 44}")
        print(f"  Length       : {a.length} characters")
        print(f"  Classes      : {', '.join(a.char_classes) or 'none'}")
        print(f"  Entropy      : {a.entropy_bits:.2f} bits")
        print(f"  Strength     : {_bar(a.strength_score)} {a.strength_score}/100  {label_c}")
        print(f"  Breach Risk  : {risk_c}  ({a.breach_count} mutations found in RockYou)")
        print(f"  GPU Crack    : {a.crack_time_label}  (RTX 4090 @ 10B hashes/sec)")
        print(f"  Final Grade  : {grade_c}  (score: {a.final_score:.1f}/100)")
        if a.suggestions:
            print(f"  Tip          : {a.suggestions[0]}")

    print()


def print_hash_cracking(passwords, breach_passwords):
    
    print("  [2] HASH CRACKING SIMULATION")
    print("  Using real RockYou breach data as dictionary")
    print(f"  {'─' * 44}")

    targets  = sorted(passwords, key=len)[:3]
    wordlist = breach_passwords[:20000]
    cracked  = 0

    for pwd in targets:
        h    = hash_password(pwd, "sha256")
        algo = identify_hash_type(h)
        r    = dictionary_attack(h, wordlist, "sha256", include_mutations=True)

        print(f"\n  Target : {repr(pwd)}")
        print(f"  Hash   : {h[:32]}...  [{', '.join(algo)}]")
        if r.cracked:
            cracked += 1
            print(f"  Result : ✓ CRACKED in {r.elapsed_seconds:.4f}s  ({r.attempts:,} attempts)")
        else:
            print(f"  Result : ✗ Not found  ({r.attempts:,} attempts tried)")

    shortest = min(passwords, key=len)
    bf = brute_force_attack(
        hash_password(shortest, "sha256"), "sha256",
        charset=string.ascii_lowercase + string.digits,
        max_length=4, max_attempts=200_000,
    )
    print(f"\n  Brute-force on {repr(shortest)}: ", end="")
    if bf.cracked:
        print(f"✓ CRACKED  ({bf.attempts:,} attempts  |  {bf.attempts_per_second:,}/sec)")
    else:
        print(f"✗ Not found within limit  (speed: {bf.attempts_per_second:,}/sec)")

    gpu_speed = 10_000_000_000
    multiplier = gpu_speed // max(bf.attempts_per_second, 1)
    print(f"\n  Result     : {cracked}/{len(targets)} passwords cracked by dictionary attack")
    print(f"  Dictionary : {len(wordlist):,} real RockYou entries  (top 20,000 most common)")
    print(f"  Your CPU   : ~{bf.attempts_per_second:,} hashes/sec")
    print(f"  RTX 4090   : {gpu_speed:,} hashes/sec  ({multiplier:,}x faster than your CPU)")
    print()


def print_final_grades(passwords, use_colour=True):
    results = analyze_batch(passwords)

    
    print("  [3] FINAL SECURITY GRADE REPORT")
    print(f"  Weights — Entropy: {GRADE_WEIGHTS['entropy']*100:.0f}%  |  "
          f"Breach: {GRADE_WEIGHTS['breach']*100:.0f}%  |  "
          f"Crack Time: {GRADE_WEIGHTS['crack_time']*100:.0f}%")
    print(f"  {'─' * 44}")

    print(f"\n  {'#':<3} {'Password':<20} {'Grade':<5}  {'Score':>6}  {'Verdict'}")
    print("  " + "-" * 66)

    for i, r in enumerate(results, 1):
        pwd_d   = r.password[:18] + ".." if len(r.password) > 20 else r.password
        grade_c = _c(r.final_grade, f"{r.final_grade:<3}", use_colour, GRADE_COLOURS)

        if r.final_grade == "F":
            if r.breach_risk in ("Critical", "High"):
                verdict = f"Fails — in breach data + cracks in {r.crack_time_label}"
            else:
                verdict = f"Fails — cracks in {r.crack_time_label}"
        elif r.final_grade == "D":
            verdict = f"Poor  — cracks in {r.crack_time_label}, breach: {r.breach_risk}"
        elif r.final_grade in ("C+", "C", "C-"):
            verdict = f"Weak  — cracks in {r.crack_time_label}"
        elif r.final_grade in ("B+", "B", "B-"):
            verdict = f"OK    — cracks in {r.crack_time_label}, breach: {r.breach_risk}"
        else:
            verdict = f"Strong — cracks in {r.crack_time_label}"

        print(f"  {i:<3} {pwd_d:<20} {grade_c}  {r.final_score:>6.1f}  {verdict}")

    print("  " + "-" * 66)

    from collections import Counter
    grade_dist = Counter(r.final_grade for r in results)
    dist_str = "  Distribution: " + "  ".join(
        f"{g}:{grade_dist[g]}" for g in ["A+","A","A-","B+","B","B-","C+","C","C-","D","F"]
        if g in grade_dist
    )
    print(f"\n{dist_str}\n")
    print("  Key insight: Grade = 40% entropy + 35% breach exposure + 25% crack time.")
    print("  A password can have HIGH entropy but still FAIL if it appears in breach data.")
    print()


def run_full_lab(use_colour=True):
    print("  LAB 2: PASSWORD SECURITY ANALYZER")
    print(f"  {'─' * 44}")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    breach_passwords = fetch_rockyou()
    load_breach_data(breach_passwords)
    print(f"  [INFO] Breach database loaded: {len(breach_passwords):,} real RockYou passwords\n")

    passwords = generate_password_set(breach_passwords)
    print("  Your 10 passwords (sampled from real breach data + generated):")
    for i, p in enumerate(passwords, 1):
        print(f"    {i:>2}. {p}")

    print_individual_analysis(passwords, use_colour)
    print_hash_cracking(passwords, breach_passwords)
    print_final_grades(passwords, use_colour)

    
    print("  DONE ")
    


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-colour", action="store_true")
    args = parser.parse_args()
    run_full_lab(use_colour=not args.no_colour)
