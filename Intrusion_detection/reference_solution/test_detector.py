
"""
Run:
    pytest test_detector.py -v
Expected: All tests pass (100%)
"""

from datetime import datetime, timedelta

import pytest

from detector import IntrusionDetector

# FIXTURES

@pytest.fixture
def detector():
    return IntrusionDetector()

@pytest.fixture
def base_time():
    return datetime(2024, 1, 1, 12, 0, 0)

@pytest.fixture
def make_event(base_time):
    """Factory fixture to build authentication events."""
    def _make_event(ip, user, status, seconds_offset=0):
        return {
            "ip": ip,
            "user": user,
            "status": status,
            "timestamp": base_time + timedelta(seconds=seconds_offset)
        }
    return _make_event

def feed_events(detector, events):
    """Helper: process a list of events, return all alerts combined."""
    alerts = []
    for event in events:
        alerts.extend(detector.process_event(event))
    return alerts

def alerts_of_type(alerts, alert_type):
    """Helper: filter alerts by type."""
    return [a for a in alerts if a["type"] == alert_type]


# FAST BRUTE-FORCE TESTS

class TestFastBruteForce:

    def test_detects_five_failures_three_users(self, detector, make_event):
        """5 failures from 3+ users within 60s triggers HIGH alert."""
        users = ["joe", "mike", "jack", "leo"]
        events = [make_event("203.0.113.1", users[i % len(users)], "Failed", i * 10)
                  for i in range(5)]

        alerts = feed_events(detector, events)

        assert len(alerts) == 1
        assert alerts[0]["type"] == "FAST_BRUTE_FORCE"
        assert alerts[0]["severity"] == "HIGH"
        assert alerts[0]["attempts"] >= 5

    def test_no_alert_with_few_attempts(self, detector, make_event):
        """3 failures (below threshold of 5) should not trigger."""
        events = [make_event("203.0.113.2", "joe", "Failed", i * 10) for i in range(3)]

        alerts = feed_events(detector, events)

        assert alerts == []

    def test_no_alert_single_user(self, detector, make_event):
        """10 failures against a single user should not trigger (needs 3+ users)."""
        events = [make_event("203.0.113.3", "joe", "Failed", i * 5) for i in range(10)]

        alerts = feed_events(detector, events)

        assert alerts_of_type(alerts, "FAST_BRUTE_FORCE") == []

    def test_no_alert_two_users_only(self, detector, make_event):
        """Only 2 distinct users, even with enough failures, should not trigger."""
        users = ["joe", "mike"]
        events = [make_event("203.0.113.9", users[i % 2], "Failed", i * 5) for i in range(8)]

        alerts = feed_events(detector, events)

        assert alerts_of_type(alerts, "FAST_BRUTE_FORCE") == []

    def test_no_duplicate_alerts_same_ip(self, detector, make_event):
        """Same IP should only trigger FAST_BRUTE_FORCE once, even with more failures."""
        users = ["joe", "mike", "jack"]
        events = [make_event("203.0.113.4", users[i % len(users)], "Failed", i * 5)
                  for i in range(10)]

        alerts = feed_events(detector, events)

        assert len(alerts_of_type(alerts, "FAST_BRUTE_FORCE")) == 1

    def test_time_window_expiry(self, detector, make_event):
        """Failures outside the 60s window shouldn't count towards the threshold."""
        users = ["joe", "mike", "jack"]
        # 3 failures now
        early = [make_event("203.0.113.5", users[i], "Failed", i * 10) for i in range(3)]
        # 2 more, 120s later (outside window) -> only 2 in-window at that point
        late = [make_event("203.0.113.5", users[i], "Failed", 120 + i * 10) for i in range(2)]

        alerts = feed_events(detector, early + late)

        assert alerts_of_type(alerts, "FAST_BRUTE_FORCE") == []

    def test_ips_tracked_independently(self, detector, make_event):
        """Different IPs must not share failure counts."""
        users = ["joe", "mike", "jack"]
        ip1_events = [make_event("203.0.113.6", users[i], "Failed", i * 10) for i in range(3)]
        ip2_events = [make_event("203.0.113.7", users[i % 3], "Failed", i * 10) for i in range(5)]

        alerts = feed_events(detector, ip1_events + ip2_events)
        fast_alerts = alerts_of_type(alerts, "FAST_BRUTE_FORCE")

        assert len(fast_alerts) == 1
        assert fast_alerts[0]["ip"] == "203.0.113.7"

    def test_alert_contains_location(self, detector, make_event):
        """Alert payload should include a resolved location string."""
        users = ["joe", "mike", "jack"]
        events = [make_event("203.0.113.50", users[i % len(users)], "Failed", i * 10) for i in range(5)]

        alerts = feed_events(detector, events)

        assert "location" in alerts[0]

    @pytest.mark.parametrize("num_failures", [5, 6, 10, 20])
    def test_detects_at_or_above_threshold(self, detector, make_event, num_failures):
        """Threshold (5) and anything above it should trigger exactly once."""
        users = ["joe", "mike", "jack", "leo"]
        events = [make_event("203.0.113.8", users[i % len(users)], "Failed", i * 5)
                  for i in range(num_failures)]

        alerts = feed_events(detector, events)

        assert len(alerts_of_type(alerts, "FAST_BRUTE_FORCE")) == 1


# SLOW BRUTE-FORCE TESTS

class TestSlowBruteForce:

    def test_detects_ten_failures_over_ten_minutes(self, detector, make_event):
        """10 failures spread across up to 10 minutes with 3+ users triggers MEDIUM alert."""
        users = ["joe", "mike", "jack", "leo"]
        events = [make_event("203.0.113.20", users[i % len(users)], "Failed", i * 50)
                  for i in range(10)]

        alerts = feed_events(detector, events)
        slow_alerts = alerts_of_type(alerts, "SLOW_BRUTE_FORCE")

        assert len(slow_alerts) == 1
        assert slow_alerts[0]["severity"] == "MEDIUM"

    def test_no_alert_below_threshold(self, detector, make_event):
        """9 failures (below threshold of 10) should not trigger slow brute-force."""
        users = ["joe", "mike", "jack"]
        events = [make_event("203.0.113.21", users[i % 3], "Failed", i * 50) for i in range(9)]

        alerts = feed_events(detector, events)

        assert alerts_of_type(alerts, "SLOW_BRUTE_FORCE") == []

    def test_not_triggered_if_fast_already_fired(self, detector, make_event):
        """If FAST_BRUTE_FORCE already alerted for this IP, slow check is skipped."""
        users = ["joe", "mike", "jack", "leo"]
        # First 5 quick failures -> triggers fast brute force
        fast_events = [make_event("203.0.113.22", users[i % 4], "Failed", i * 5) for i in range(5)]
        # 5 more slower failures for same IP
        slow_events = [make_event("203.0.113.22", users[i % 4], "Failed", 300 + i * 50) for i in range(5)]

        alerts = feed_events(detector, fast_events + slow_events)

        assert len(alerts_of_type(alerts, "FAST_BRUTE_FORCE")) == 1
        assert alerts_of_type(alerts, "SLOW_BRUTE_FORCE") == []

    def test_outside_ten_minute_window_not_counted(self, detector, make_event):
        """Failures older than the 10-minute window should not count."""
        users = ["joe", "mike", "jack", "leo"]
        # 4 failures at t=0
        first_batch = [make_event("203.0.113.23", users[i], "Failed", i * 5) for i in range(4)]
        # 4 more failures 700s later (outside 600s window from the first batch)
        second_batch = [make_event("203.0.113.23", users[i], "Failed", 700 + i * 5) for i in range(4)]

        alerts = feed_events(detector, first_batch + second_batch)

        assert alerts_of_type(alerts, "SLOW_BRUTE_FORCE") == []


# SUCCESS AFTER FAILURE (ACCOUNT COMPROMISE) TESTS

class TestSuccessAfterFailure:

    def test_detects_compromise_after_five_failures(self, detector, make_event):
        """5 failures followed by a success triggers CRITICAL alert."""
        ip, user = "203.0.113.30", "joe"
        events = [make_event(ip, user, "Failed", i * 30) for i in range(5)]
        events.append(make_event(ip, user, "Accepted", 150))

        alerts = feed_events(detector, events)
        success_alerts = alerts_of_type(alerts, "SUCCESS_AFTER_FAILURE")

        assert len(success_alerts) == 1
        assert success_alerts[0]["severity"] == "CRITICAL"
        assert success_alerts[0]["compromised_account"] == user

    def test_no_alert_without_prior_failures(self, detector, make_event):
        """A success with no prior failures should not trigger."""
        event = make_event("192.168.1.10", "joe", "Accepted", 0)

        alerts = detector.process_event(event)

        assert alerts_of_type(alerts, "SUCCESS_AFTER_FAILURE") == []

    def test_no_alert_below_failure_threshold(self, detector, make_event):
        """Only 3 failures (below threshold of 5) then success should not trigger."""
        ip, user = "203.0.113.31", "joe"
        events = [make_event(ip, user, "Failed", i * 30) for i in range(3)]
        events.append(make_event(ip, user, "Accepted", 100))

        alerts = feed_events(detector, events)

        assert alerts_of_type(alerts, "SUCCESS_AFTER_FAILURE") == []

    def test_failures_outside_window_not_counted(self, detector, make_event):
        """Failures older than the 5-minute window should not count towards compromise."""
        ip, user = "203.0.113.32", "joe"
        old_failures = [make_event(ip, user, "Failed", i * 10) for i in range(5)]
        # success occurs 400s later - outside the 300s success window
        success = make_event(ip, user, "Accepted", 400)

        alerts = feed_events(detector, old_failures + [success])

        assert alerts_of_type(alerts, "SUCCESS_AFTER_FAILURE") == []

    def test_alert_identifies_correct_user(self, detector, make_event):
        """compromised_account field must match the user who succeeded."""
        ip = "203.0.113.33"
        events = [make_event(ip, "victim", "Failed", i * 20) for i in range(5)]
        events.append(make_event(ip, "victim", "Accepted", 120))

        alerts = feed_events(detector, events)
        success_alerts = alerts_of_type(alerts, "SUCCESS_AFTER_FAILURE")

        assert success_alerts[0]["compromised_account"] == "victim"


# DISTRIBUTED ATTACK TESTS

class TestDistributedAttack:

    def test_detects_three_ips_attacking_same_user(self, detector, make_event):
        """3 distinct IPs each with 3+ failures against the same user triggers HIGH alert."""
        user = "admin"
        ips = ["203.0.113.40", "203.0.113.41", "203.0.113.42"]
        events = []
        for ip in ips:
            events += [make_event(ip, user, "Failed", i * 20) for i in range(3)]

        alerts = feed_events(detector, events)
        dist_alerts = alerts_of_type(alerts, "DISTRIBUTED_ATTACK")

        assert len(dist_alerts) == 1
        assert dist_alerts[0]["severity"] == "HIGH"
        assert len(dist_alerts[0]["source_ips"]) == 3

    def test_no_alert_with_single_ip(self, detector, make_event):
        """All failures from one IP should not trigger distributed attack."""
        events = [make_event("203.0.113.43", "admin", "Failed", i * 20) for i in range(10)]

        alerts = feed_events(detector, events)

        assert alerts_of_type(alerts, "DISTRIBUTED_ATTACK") == []

    def test_no_alert_with_two_ips(self, detector, make_event):
        """Only 2 attacking IPs (below threshold of 3) should not trigger."""
        user = "admin"
        events = []
        for ip in ["203.0.113.44", "203.0.113.45"]:
            events += [make_event(ip, user, "Failed", i * 20) for i in range(3)]

        alerts = feed_events(detector, events)

        assert alerts_of_type(alerts, "DISTRIBUTED_ATTACK") == []

    def test_ip_below_per_ip_threshold_not_counted(self, detector, make_event):
        """An IP with fewer than 3 failures shouldn't count towards the distributed threshold."""
        user = "admin"
        events = []
        # Two IPs meet the per-IP threshold, one does not
        events += [make_event("203.0.113.46", user, "Failed", i * 20) for i in range(3)]
        events += [make_event("203.0.113.47", user, "Failed", i * 20) for i in range(3)]
        events += [make_event("203.0.113.48", user, "Failed", i * 20) for i in range(2)]  # only 2

        alerts = feed_events(detector, events)

        assert alerts_of_type(alerts, "DISTRIBUTED_ATTACK") == []

    def test_no_duplicate_alerts_for_same_user(self, detector, make_event):
        """Once triggered for a user, subsequent failures shouldn't re-trigger."""
        user = "admin"
        ips = ["203.0.113.49", "203.0.113.50", "203.0.113.51", "203.0.113.52"]
        events = []
        for ip in ips:
            events += [make_event(ip, user, "Failed", i * 20) for i in range(3)]

        alerts = feed_events(detector, events)

        assert len(alerts_of_type(alerts, "DISTRIBUTED_ATTACK")) == 1

    def test_different_users_tracked_independently(self, detector, make_event):
        """Distributed attack detection for one user shouldn't affect another."""
        ips = ["203.0.113.53", "203.0.113.54", "203.0.113.55"]
        events = []
        for ip in ips:
            events += [make_event(ip, "admin", "Failed", i * 20) for i in range(3)]
        # A different user with failures from only 1 IP
        events += [make_event("203.0.113.56", "joe", "Failed", i * 20) for i in range(3)]

        alerts = feed_events(detector, events)
        dist_alerts = alerts_of_type(alerts, "DISTRIBUTED_ATTACK")

        assert len(dist_alerts) == 1
        assert dist_alerts[0]["user"] == "admin"


# SUSPICIOUS LOCATION TESTS

class TestSuspiciousLocation:

    def test_detects_login_from_high_risk_country(self, detector, make_event):
        """Successful login from a suspicious country (CN) triggers MEDIUM alert."""
        event = make_event("203.0.113.50", "joe", "Accepted")

        alerts = detector.process_event(event)
        loc_alerts = alerts_of_type(alerts, "SUSPICIOUS_LOCATION")

        assert len(loc_alerts) == 1
        assert loc_alerts[0]["severity"] == "MEDIUM"
        assert loc_alerts[0]["country"] == "CN"

    def test_no_alert_from_safe_country(self, detector, make_event):
        """Login from a non-suspicious country (US) should not trigger."""
        event = make_event("198.51.100.10", "joe", "Accepted")

        alerts = detector.process_event(event)

        assert alerts_of_type(alerts, "SUSPICIOUS_LOCATION") == []

    def test_no_alert_from_internal_ip(self, detector, make_event):
        """Internal network IPs should never trigger suspicious location."""
        event = make_event("192.168.1.10", "joe", "Accepted")

        alerts = detector.process_event(event)

        assert alerts_of_type(alerts, "SUSPICIOUS_LOCATION") == []

    def test_no_alert_on_failed_login(self, detector, make_event):
        """Suspicious location only checked on successful (Accepted) logins."""
        event = make_event("203.0.113.50", "joe", "Failed")

        alerts = detector.process_event(event)

        assert alerts_of_type(alerts, "SUSPICIOUS_LOCATION") == []

    @pytest.mark.parametrize("country_ip,country_code", [
        ("203.0.113.50", "CN"),
        ("203.0.113.60", "RU"),
    ])
    def test_multiple_suspicious_countries(self, detector, make_event, country_ip, country_code):
        """Multiple high-risk countries should all be flagged."""
        event = make_event(country_ip, "joe", "Accepted")

        alerts = detector.process_event(event)
        loc_alerts = alerts_of_type(alerts, "SUSPICIOUS_LOCATION")

        assert len(loc_alerts) == 1
        assert loc_alerts[0]["country"] == country_code


# IMPOSSIBLE TRAVEL TESTS

class TestImpossibleTravel:

    def test_detects_impossible_travel(self, detector, make_event):
        """Login from US then CN 60s later (11000km) triggers HIGH alert."""
        user = "leo"
        first = make_event("198.51.100.10", user, "Accepted", 0)
        second = make_event("203.0.113.50", user, "Accepted", 60)

        detector.process_event(first)
        alerts = detector.process_event(second)
        travel_alerts = alerts_of_type(alerts, "IMPOSSIBLE_TRAVEL")

        assert len(travel_alerts) == 1
        assert travel_alerts[0]["severity"] == "HIGH"
        assert travel_alerts[0]["distance_km"] > 1000
        assert travel_alerts[0]["previous_location"] == "US"
        assert travel_alerts[0]["current_location"] == "CN"

    def test_no_alert_same_country(self, detector, make_event):
        """Two logins from the same country should never trigger impossible travel."""
        user = "leo"
        first = make_event("198.51.100.10", user, "Accepted", 0)
        second = make_event("198.51.100.11", user, "Accepted", 60)

        detector.process_event(first)
        alerts = detector.process_event(second)

        assert alerts_of_type(alerts, "IMPOSSIBLE_TRAVEL") == []

    def test_no_alert_with_sufficient_travel_time(self, detector, make_event):
        """A 2-hour gap is enough time to travel; should not trigger."""
        user = "leo"
        first = make_event("198.51.100.10", user, "Accepted", 0)
        second = make_event("203.0.113.50", user, "Accepted", 7200)

        detector.process_event(first)
        alerts = detector.process_event(second)

        assert alerts_of_type(alerts, "IMPOSSIBLE_TRAVEL") == []

    def test_first_login_never_triggers(self, detector, make_event):
        """A user's very first login has no prior location to compare against."""
        event = make_event("203.0.113.50", "leo", "Accepted", 0)

        alerts = detector.process_event(event)

        assert alerts_of_type(alerts, "IMPOSSIBLE_TRAVEL") == []

    def test_users_tracked_independently(self, detector, make_event):
        """Impossible travel for one user should not affect another user."""
        leo_first = make_event("198.51.100.10", "leo", "Accepted", 0)
        leo_second = make_event("203.0.113.50", "leo", "Accepted", 60)
        joe_first = make_event("203.0.113.50", "joe", "Accepted", 120)

        detector.process_event(leo_first)
        leo_alerts = detector.process_event(leo_second)
        joe_alerts = detector.process_event(joe_first)

        assert len(alerts_of_type(leo_alerts, "IMPOSSIBLE_TRAVEL")) == 1
        assert alerts_of_type(joe_alerts, "IMPOSSIBLE_TRAVEL") == []

    def test_location_updates_after_alert(self, detector, make_event):
        """After an impossible-travel alert, the user's location should update
        so a third, nearby login doesn't also alert."""
        user = "leo"
        e1 = make_event("198.51.100.10", user, "Accepted", 0)      # US
        e2 = make_event("203.0.113.50", user, "Accepted", 60)      # CN (impossible travel #1)
        e3 = make_event("203.0.113.51", user, "Accepted", 120)     # still CN region

        detector.process_event(e1)
        alerts2 = detector.process_event(e2)
        alerts3 = detector.process_event(e3)

        assert len(alerts_of_type(alerts2, "IMPOSSIBLE_TRAVEL")) == 1
        # third login also from CN -> same country as last update, should not re-trigger
        assert alerts_of_type(alerts3, "IMPOSSIBLE_TRAVEL") == []

    def test_internal_ip_does_not_trigger(self, detector, make_event):
        """Internal IPs have no geolocation and should not trigger travel detection."""
        user = "leo"
        e1 = make_event("198.51.100.10", user, "Accepted", 0)
        e2 = make_event("192.168.1.10", user, "Accepted", 60)

        detector.process_event(e1)
        alerts = detector.process_event(e2)

        assert alerts_of_type(alerts, "IMPOSSIBLE_TRAVEL") == []


# CROSS-CUTTING / INTEGRATION TESTS
class TestIntegration:

    def test_fast_brute_force_then_compromise_then_location(self, detector, make_event):
        """A realistic attack chain should raise multiple distinct alert types."""
        ip = "203.0.113.50"  # Beijing
        users = ["joe", "mike", "leo"]
        events = [make_event(ip, users[i % 3], "Failed", i * 10) for i in range(5)]
        events.append(make_event(ip, "joe", "Accepted", 100))

        alerts = feed_events(detector, events)
        types = {a["type"] for a in alerts}

        assert "FAST_BRUTE_FORCE" in types
        assert "SUCCESS_AFTER_FAILURE" in types
        assert "SUSPICIOUS_LOCATION" in types

    def test_process_event_returns_list(self, detector, make_event):
        """process_event should always return a list, even when empty."""
        result = detector.process_event(make_event("192.168.1.10", "joe", "Accepted", 0))
        assert isinstance(result, list)

    def test_all_alerts_have_required_fields(self, detector, make_event):
        """Every alert dict should always include 'type', 'severity', and 'time'."""
        ip = "203.0.113.50"
        users = ["joe", "mike", "leo"]
        events = [make_event(ip, users[i % 3], "Failed", i * 10) for i in range(5)]
        events.append(make_event(ip, "joe", "Accepted", 100))

        alerts = feed_events(detector, events)

        for alert in alerts:
            assert "type" in alert
            assert "severity" in alert
            assert "time" in alert
            assert alert["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))