
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(__file__))

try:
    from password_analyzer import (
        detect_char_classes,
        calculate_breach_risk,
        estimate_crack_time,
        calculate_final_grade,
        calculate_entropy,
        load_breach_data,
        GRADE_WEIGHTS,
        GPU_HASHES_PER_SEC,
    )
except ImportError as e:
    pytest.exit(
        f"\n\n  ERROR: Could not import password_analyzer.py\n"
        f"  Make sure test_lab2.py is in the same folder as password_analyzer.py\n"
        f"  Details: {e}\n",
        returncode=1,
    )

_CACHE_FILE = os.path.join(os.path.dirname(__file__), ".rockyou_cache.txt")

if os.path.exists(_CACHE_FILE):
    with open(_CACHE_FILE, "r", encoding="utf-8", errors="ignore") as _f:
        _breach_passwords = [line.strip() for line in _f if line.strip()]
    load_breach_data(_breach_passwords)
    print(f"\n  [INFO] Loaded {len(_breach_passwords):,} real RockYou passwords for testing")
else:
    
    try:
        from generator import fetch_rockyou
        _breach_passwords = fetch_rockyou()
        load_breach_data(_breach_passwords)
        print(f"\n  [INFO] Downloaded {len(_breach_passwords):,} RockYou passwords for testing")
    except Exception:
        pytest.exit(
            "\n\n  ERROR: .rockyou_cache.txt not found and download failed.\n"
            "  Run the lab first:  python report_generator.py\n"
            "  Then run tests again.\n",
            returncode=1,
        )

#  TASK 1 — detect_char_classes(password)

class TestTask1DetectCharClasses:

    def test_lowercase_only(self):
        """'hello' contains only lowercase letters → pool = 26"""
        classes, pool = detect_char_classes("hello")
        assert "lowercase" in classes, (
            "Expected 'lowercase' in classes for 'hello' — "
            "check your loop detects lowercase letters"
        )
        assert pool == 26, (
            f"Expected pool=26 for lowercase-only password, got {pool} — "
            "check you are adding 26 for the lowercase class"
        )

    def test_digits_only(self):
        """'12345' contains only digits → pool = 10"""
        classes, pool = detect_char_classes("12345")
        assert "digits" in classes, (
            "Expected 'digits' in classes for '12345'"
        )
        assert pool == 10, (
            f"Expected pool=10 for digits-only password, got {pool}"
        )

    def test_all_four_classes(self):
        """'Hello1!' has lowercase + uppercase + digits + special → pool = 94"""
        classes, pool = detect_char_classes("Hello1!")
        for expected_class in ["lowercase", "uppercase", "digits", "special"]:
            assert expected_class in classes, (
                f"Expected '{expected_class}' in classes for 'Hello1!' — "
                f"got {classes}"
            )
        assert pool == 94, (
            f"Expected pool=94 for all-4-class password (26+26+10+32), got {pool}"
        )

    def test_empty_password(self):
        """Empty string → no classes, pool = 0"""
        classes, pool = detect_char_classes("")
        assert classes == [], (
            f"Expected empty class list for empty password, got {classes}"
        )
        assert pool == 0, (
            f"Expected pool=0 for empty password, got {pool}"
        )

    def test_uppercase_only(self):
        """'HELLO' contains only uppercase → pool = 26, no lowercase"""
        classes, pool = detect_char_classes("HELLO")
        assert "uppercase" in classes, (
            "Expected 'uppercase' in classes for 'HELLO'"
        )
        assert "lowercase" not in classes, (
            "Did not expect 'lowercase' in classes for 'HELLO' — "
            "check you are not accidentally adding classes that are not present"
        )
        assert pool == 26, (
            f"Expected pool=26 for uppercase-only password, got {pool}"
        )

#  TASK 2 — calculate_breach_risk(password)

class TestTask2BreachRisk:

    def test_common_password_is_critical(self):
        """'password' is rank 1 in RockYou — must be Critical"""
        count, risk = calculate_breach_risk("password")
        assert risk == "Critical", (
            f"Expected 'Critical' for 'password' (rank 1 in RockYou), got '{risk}' — "
            "check your top-1000 rank threshold"
        )

    def test_random_strong_password_is_none(self):
        """A randomly generated strong password should have 0 breach matches"""
        count, risk = calculate_breach_risk("xK9#mZ2$vQpR")
        assert risk == "None", (
            f"Expected 'None' for strong random password, got '{risk}' — "
            "check your mutation list is not accidentally matching random strings"
        )
        assert count == 0, (
            f"Expected count=0 for strong random password, got count={count}"
        )

    def test_mutation_count_is_integer(self):
        """count must be an integer between 0 and 12"""
        count, risk = calculate_breach_risk("shadow")
        assert isinstance(count, int), (
            f"Expected count to be an integer, got {type(count).__name__}"
        )
        assert 0 <= count <= 12, (
            f"count must be between 0 and 12 (you have 12 mutations), got {count}"
        )

    def test_risk_label_is_valid_string(self):
        """risk label must be one of the 5 valid values"""
        valid_labels = {"None", "Low", "Medium", "High", "Critical", "Unknown"}
        for password in ["hello", "abc123", "xK9#mZ2$vQpR", "password"]:
            count, risk = calculate_breach_risk(password)
            assert risk in valid_labels, (
                f"Invalid risk label '{risk}' for password '{password}' — "
                f"must be one of: {valid_labels}"
            )

    def test_returns_tuple_of_two(self):
        """Function must return exactly 2 values: (count, risk)"""
        result = calculate_breach_risk("hello")
        assert result is not None, (
            "calculate_breach_risk() returned None — did you forget the return statement?"
        )
        assert len(result) == 2, (
            f"Expected (count, risk) tuple with 2 values, got {len(result)} values"
        )

#  TASK 3 — estimate_crack_time(password)

class TestTask3CrackTime:

    def test_weak_password_cracks_fast(self):
        """'hello' has low entropy — must crack in under 1 minute on GPU"""
        seconds, label = estimate_crack_time("hello")
        assert seconds < 60, (
            f"Expected 'hello' to crack in under 60 seconds on GPU, got {seconds:.2f}s — "
            "check your formula uses GPU_HASHES_PER_SEC not CPU speed"
        )
        assert label == "under 1 minute", (
            f"Expected label 'under 1 minute' for 'hello', got '{label}'"
        )

    def test_strong_password_takes_very_long(self):
        """Strong 16-char password should take over 100 years"""
        seconds, label = estimate_crack_time("S.imWv0|qwH5^~8B")
        assert seconds > 3_153_600_000, (
            f"Expected very long crack time for strong password, got {seconds:.2f}s — "
            "check 2**entropy is not being calculated incorrectly"
        )

    def test_formula_uses_gpu_speed(self):
        """Verify the formula divides by GPU_HASHES_PER_SEC, not a slower speed"""
        # 'mrbean' entropy ~28.2 bits
        # correct:  (2^28.2 / 10,000,000,000) / 2  ≈  0.017 seconds
        # wrong:    (2^28.2 / 1,500,000) / 2        ≈  112 seconds
        seconds, label = estimate_crack_time("mrbean")
        assert seconds < 10, (
            f"Expected 'mrbean' to crack in under 10 seconds at GPU speed, got {seconds:.2f}s — "
            f"check you are using GPU_HASHES_PER_SEC={GPU_HASHES_PER_SEC:,} not CPU speed"
        )

    def test_returns_tuple_of_two(self):
        """Function must return (seconds, label) — two values"""
        result = estimate_crack_time("hello")
        assert result is not None, (
            "estimate_crack_time() returned None — did you forget the return statement?"
        )
        assert len(result) == 2, (
            f"Expected (seconds, label) tuple, got {len(result)} values"
        )

    def test_stronger_password_takes_longer(self):
        """A stronger password must always take longer than a weaker one"""
        weak_sec, _   = estimate_crack_time("hello")
        strong_sec, _ = estimate_crack_time("xK9#mZ2$vQpR")
        assert strong_sec > weak_sec, (
            f"Strong password crack time ({strong_sec:.2f}s) should be greater than "
            f"weak password crack time ({weak_sec:.2f}s) — "
            "check your entropy calculation feeds correctly into the formula"
        )

#  TASK 4 — calculate_final_grade(password)

class TestTask4FinalGrade:

    def test_common_password_fails(self):
        """'password' is rank 1 in RockYou + weak → must grade F"""
        score, grade = calculate_final_grade("password")
        assert grade == "F", (
            f"Expected grade 'F' for 'password', got '{grade}' (score={score}) — "
            "check your breach_score maps 'Critical' to 0"
        )

    def test_strong_password_grades_well(self):
        """Strong random 16-char password not in breach data → must grade A or better"""
        score, grade = calculate_final_grade("S.imWv0|qwH5^~8B")
        assert grade in ("A+", "A", "A-"), (
            f"Expected grade A/A+/A- for strong password, got '{grade}' (score={score}) — "
            "check your entropy_score and crack_score calculations"
        )

    def test_score_is_between_0_and_100(self):
        """Final score must always be between 0 and 100"""
        for password in ["password", "hello", "xK9#mZ2$vQpR", "S.imWv0|qwH5^~8B", "abc"]:
            score, grade = calculate_final_grade(password)
            assert 0 <= score <= 100, (
                f"Score must be between 0 and 100, got {score} for '{password}'"
            )

    def test_grade_is_valid_letter(self):
        """Grade must always be one of the valid letter grades"""
        valid_grades = {"A+","A","A-","B+","B","B-","C+","C","C-","D","F"}
        for password in ["password", "hello", "mrbean", "xK9#mZ2$vQpR", "S.imWv0|qwH5^~8B"]:
            score, grade = calculate_final_grade(password)
            assert grade in valid_grades, (
                f"Invalid grade '{grade}' for '{password}' — "
                f"must be one of: {sorted(valid_grades)}"
            )

    def test_weights_sum_to_one(self):
        """GRADE_WEIGHTS must sum to exactly 1.0 (100%)"""
        total = sum(GRADE_WEIGHTS.values())
        assert abs(total - 1.0) < 0.001, (
            f"GRADE_WEIGHTS must sum to 1.0, got {total:.3f} — "
            "do not change the weights in GRADE_WEIGHTS"
        )

    def test_returns_tuple_of_two(self):
        """Function must return (score, grade) — two values"""
        result = calculate_final_grade("hello")
        assert result is not None, (
            "calculate_final_grade() returned None — did you forget the return statement?"
        )
        assert len(result) == 2, (
            f"Expected (score, grade) tuple, got {len(result)} values"
        )

#  INTEGRATION TESTS

class TestIntegration:

    def test_higher_entropy_means_longer_crack_time(self):
        """More entropy must always mean longer crack time — Tasks 1 and 3 connected"""
        passwords   = ["abc", "hello", "xK9#mZ2$vQpR", "S.imWv0|qwH5^~8B"]
        entropies   = [calculate_entropy(p) for p in passwords]
        crack_times = [estimate_crack_time(p)[0] for p in passwords]

        for i in range(len(passwords) - 1):
            assert entropies[i] <= entropies[i+1], (
                f"Entropy of '{passwords[i]}' should be <= '{passwords[i+1]}'"
            )
            assert crack_times[i] <= crack_times[i+1], (
                f"Crack time of '{passwords[i]}' should be <= '{passwords[i+1]}' "
                f"— Tasks 1 and 3 are not connected correctly"
            )

    def test_breach_data_reduces_final_grade(self):
        """A password in real RockYou data must grade lower than a clean password"""
        # 'password' is rank 1 in real RockYou — Critical breach
        # 'xK9#mZ2$' is not in real RockYou — None breach
        _, breach_grade = calculate_final_grade("password")
        _, clean_grade  = calculate_final_grade("xK9#mZ2$")

        grade_order = ["F","D","C-","C","C+","B-","B","B+","A-","A","A+"]
        breach_rank = grade_order.index(breach_grade) if breach_grade in grade_order else 0
        clean_rank  = grade_order.index(clean_grade)  if clean_grade  in grade_order else 0

        assert clean_rank > breach_rank, (
            f"A clean password should grade higher than a breached one — "
            f"'password'={breach_grade}, 'xK9#mZ2$'={clean_grade} — "
            "check your breach_score is reducing the final score (Task 4)"
        )

    def test_no_task_returns_none(self):
        """None of the 4 tasks should return None for a normal password"""
        pwd = "TestPass1!"
        assert detect_char_classes(pwd)   is not None, "Task 1 returned None"
        assert calculate_breach_risk(pwd) is not None, "Task 2 returned None"
        assert estimate_crack_time(pwd)   is not None, "Task 3 returned None"
        assert calculate_final_grade(pwd) is not None, "Task 4 returned None"