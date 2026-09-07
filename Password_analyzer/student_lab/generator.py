# LAB 2: Password Security Analyzer
# generator.py — Downloads real RockYou breach data and samples 10 passwords

import os
import random
import string
import urllib.request
import urllib.error
from typing import List, Tuple

ROCKYOU_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists"
    "/master/Passwords/Leaked-Databases/rockyou-75.txt"
)
CACHE_FILE = os.path.join(os.path.dirname(__file__), ".rockyou_cache.txt")


def fetch_rockyou(force_refresh: bool = False) -> List[str]:
    # Load from cache if available, otherwise download from SecLists GitHub
    if not force_refresh and os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8", errors="ignore") as fh:
                passwords = [line.strip() for line in fh if line.strip()]
            if len(passwords) > 1000:
                return passwords
        except OSError:
            pass

    print("  [INFO] Downloading RockYou breach data from SecLists...")
    req = urllib.request.Request(
        ROCKYOU_URL,
        headers={"User-Agent": "Mozilla/5.0 (Lab2-PasswordAnalyzer/1.0)"},
    )
    with urllib.request.urlopen(req, timeout=15) as response:
        raw = response.read().decode("utf-8", errors="ignore")

    passwords = _clean_passwords(raw.splitlines())

    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as fh:
            fh.write("\n".join(passwords))
        print(f"  [INFO] Downloaded {len(passwords):,} passwords. Cached locally.")
    except OSError:
        print(f"  [INFO] Downloaded {len(passwords):,} passwords (cache write failed — OK).")

    return passwords


def _clean_passwords(lines: List[str]) -> List[str]:
    # Strip, deduplicate, and filter invalid entries from breach file
    seen = set()
    cleaned = []
    for line in lines:
        pw = line.strip()
        if not pw or pw.startswith("#"):
            continue
        if len(pw) > 64:
            continue
        if not all(32 <= ord(c) < 127 for c in pw):
            continue
        if pw not in seen:
            seen.add(pw)
            cleaned.append(pw)
    return cleaned


def _classify(passwords: List[str]) -> Tuple[List[str], List[str], List[str]]:
    # Sort passwords into very_weak / weak / medium tiers by length and complexity
    very_weak, weak, medium = [], [], []
    for pw in passwords:
        has_digit   = any(c.isdigit()  for c in pw)
        has_alpha   = any(c.isalpha()  for c in pw)
        has_special = any(c in string.punctuation for c in pw)
        num_types   = sum([has_digit, has_alpha, has_special])

        if len(pw) <= 6 or (len(pw) <= 8 and num_types == 1):
            very_weak.append(pw)
        elif len(pw) <= 10 and num_types <= 2:
            weak.append(pw)
        elif len(pw) <= 14 and num_types >= 2:
            medium.append(pw)

    return very_weak, weak, medium


def _generate_strong(rng: random.Random, length: int) -> str:
    # Generate a strong password guaranteed to contain all 4 character classes
    pool = string.ascii_letters + string.digits + string.punctuation
    pwd = [
        rng.choice(string.ascii_lowercase),
        rng.choice(string.ascii_uppercase),
        rng.choice(string.digits),
        rng.choice(string.punctuation),
    ]
    pwd += [rng.choice(pool) for _ in range(length - 4)]
    rng.shuffle(pwd)
    return "".join(pwd)


def _generate_passphrase(rng: random.Random, breach_words: List[str]) -> str:
    # Build a passphrase from 3 real single-word RockYou entries joined by separator
    words = [p for p in breach_words if p.isalpha() and 4 <= len(p) <= 9]
    sep = rng.choice(["-", "_", " "])
    chosen = rng.sample(words, min(3, len(words)))
    return sep.join(chosen)


def generate_password_set(breach_passwords: List[str] = None) -> List[str]:
    # Sample 10 passwords: 7 from real breach data + passphrase + 2 generated strong
    # Uses os.urandom seed so output is different every run
    if breach_passwords is None:
        breach_passwords = fetch_rockyou()

    rng = random.Random(int.from_bytes(os.urandom(8), "big"))
    very_weak, weak, medium = _classify(breach_passwords)

    return (
        rng.sample(very_weak, 3)
        + rng.sample(weak, 2)
        + rng.sample(medium, 2)
        + [_generate_passphrase(rng, breach_passwords)]
        + [_generate_strong(rng, rng.randint(12, 14))]
        + [_generate_strong(rng, rng.randint(16, 20))]
    )
