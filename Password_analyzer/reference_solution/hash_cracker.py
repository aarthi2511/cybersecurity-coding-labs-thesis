# LAB 2: Password Security Analyzer
# hash_cracker.py — Dictionary and brute-force attack simulation using SHA-256/MD5/SHA-1

import hashlib
import itertools
import string
import time
from dataclasses import dataclass
from typing import Optional, List, Dict

SUPPORTED_ALGORITHMS = {"md5", "sha1", "sha256"}


@dataclass
class CrackResult:
    target_hash:        str
    algorithm:          str
    cracked:            bool  = False
    plaintext:          Optional[str] = None
    attack_type:        str   = ""
    attempts:           int   = 0
    elapsed_seconds:    float = 0.0
    attempts_per_second: float = 0.0


def hash_password(password: str, algorithm: str = "sha256") -> str:
    # Hash a password string and return the hex digest
    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm '{algorithm}'. Choose from: {sorted(SUPPORTED_ALGORITHMS)}")
    h = hashlib.new(algorithm)
    h.update(password.encode("utf-8"))
    return h.hexdigest()


def identify_hash_type(hash_str: str) -> List[str]:
    # Guess algorithm from hash length: 32=MD5, 40=SHA-1, 64=SHA-256
    length_map = {32: ["md5"], 40: ["sha1"], 64: ["sha256"]}
    return length_map.get(len(hash_str.strip()), ["unknown"])


def dictionary_attack(
    target_hash: str,
    wordlist: List[str],
    algorithm: str = "sha256",
    include_mutations: bool = True,
) -> CrackResult:
    # Try every word in wordlist (+ mutations) against the target hash
    target_hash = target_hash.lower()
    result = CrackResult(
        target_hash=target_hash,
        algorithm=algorithm,
        attack_type="dictionary+mutations" if include_mutations else "dictionary",
    )
    start = time.perf_counter()

    def _candidates(word: str):
        yield word
        if include_mutations:
            yield word.capitalize()
            yield word.upper()
            for i in range(100):
                yield f"{word}{i}"
            leet = word.lower()
            for plain, sub in [("a", "@"), ("e", "3"), ("i", "1"), ("o", "0"), ("s", "$")]:
                leet = leet.replace(plain, sub)
            yield leet

    for word in wordlist:
        for candidate in _candidates(word):
            result.attempts += 1
            if hash_password(candidate, algorithm) == target_hash:
                result.cracked   = True
                result.plaintext = candidate
                break
        if result.cracked:
            break

    result.elapsed_seconds = round(time.perf_counter() - start, 4)
    if result.elapsed_seconds > 0:
        result.attempts_per_second = round(result.attempts / result.elapsed_seconds)
    return result


def brute_force_attack(
    target_hash: str,
    algorithm: str = "sha256",
    charset: str = string.ascii_lowercase + string.digits,
    max_length: int = 4,
    max_attempts: int = 500_000,
) -> CrackResult:
    # Try every combination of charset characters up to max_length
    target_hash = target_hash.lower()
    result = CrackResult(target_hash=target_hash, algorithm=algorithm, attack_type="brute-force")
    start = time.perf_counter()

    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            if result.attempts >= max_attempts:
                break
            candidate = "".join(combo)
            result.attempts += 1
            if hash_password(candidate, algorithm) == target_hash:
                result.cracked   = True
                result.plaintext = candidate
                break
        if result.cracked or result.attempts >= max_attempts:
            break

    result.elapsed_seconds = round(time.perf_counter() - start, 4)
    if result.elapsed_seconds > 0:
        result.attempts_per_second = round(result.attempts / result.elapsed_seconds)
    return result


def crack_statistics(results: List[CrackResult]) -> Dict:
    # Summarise a list of CrackResult objects into aggregate stats
    total = len(results)
    if total == 0:
        return {}
    cracked = [r for r in results if r.cracked]
    fastest = min((r for r in cracked), key=lambda r: r.elapsed_seconds, default=None)
    slowest = max((r for r in cracked), key=lambda r: r.elapsed_seconds, default=None)
    return {
        "total":             total,
        "cracked":           len(cracked),
        "failed":            total - len(cracked),
        "crack_rate_pct":    round(len(cracked) / total * 100, 1),
        "avg_attempts":      round(sum(r.attempts for r in results) / total),
        "avg_time_seconds":  round(sum(r.elapsed_seconds for r in results) / total, 4),
        "fastest_crack":     fastest.plaintext if fastest else None,
        "slowest_crack":     slowest.plaintext if slowest else None,
    }
