# detector.py - Student Version: Intrusion Detection System
#
# YOUR TASK: Implement 4 detection algorithms by following the examples provided.
#
# COMPLETED (for reference):
#   ✅ Fast Brute-Force Detection
#   ✅ Suspicious Location Detection
#
# TO DO (implement these):
#   📝 Slow Brute-Force Detection
#   📝 Success After Failure Detection
#   📝 Distributed Attack Detection
#   📝 Impossible Travel Detection
#
# TIME ESTIMATE: 90-120 minutes total

from datetime import timedelta
from collections import defaultdict
from typing import List, Dict

from config import (
    FAILED_THRESHOLD_FAST,
    TIME_WINDOW_FAST_SECONDS,
    FAILED_THRESHOLD_SLOW,
    TIME_WINDOW_SLOW_SECONDS,
    FAILED_BEFORE_SUCCESS,
    SUCCESS_TIME_WINDOW_SECONDS,
    DISTRIBUTED_ATTACK_THRESHOLD,
    DISTRIBUTED_TIME_WINDOW,
    DISTRIBUTED_FAILED_PER_IP,
    IMPOSSIBLE_TRAVEL_TIME_WINDOW,
    IMPOSSIBLE_TRAVEL_MIN_DISTANCE,
    SEVERITY_LEVELS
)

from geolocation import get_geolocator


class IntrusionDetector:
    """
    Intrusion detection system with 6 detection algorithms.
    
    Students will implement 4 of these algorithms:
    1. Fast brute-force attacks      ✅ COMPLETE (example)
    2. Slow brute-force attacks      📝 TODO
    3. Success after failure         📝 TODO
    4. Distributed attacks           📝 TODO
    5. Suspicious location           ✅ COMPLETE (example)
    6. Impossible travel             📝 TODO
    """
    
    def __init__(self):
        # Time windows
        self.fast_window = timedelta(seconds=TIME_WINDOW_FAST_SECONDS)
        self.slow_window = timedelta(seconds=TIME_WINDOW_SLOW_SECONDS)
        self.success_window = timedelta(seconds=SUCCESS_TIME_WINDOW_SECONDS)
        self.distributed_window = timedelta(seconds=DISTRIBUTED_TIME_WINDOW)
        self.travel_window = timedelta(seconds=IMPOSSIBLE_TRAVEL_TIME_WINDOW)
        
        # Per-IP tracking
        self.failed_attempts = defaultdict(list)  # IP -> [timestamps]
        self.user_attempts = defaultdict(set)     # IP -> {users}
        self.all_events = defaultdict(list)       # IP -> [events]
        
        # Per-user tracking (for distributed attacks)
        self.user_failed_by_ip = defaultdict(lambda: defaultdict(list))  # user -> IP -> [timestamps]
        
        # Per-user location tracking (for impossible travel)
        self.user_last_location = {}  # user -> (country, timestamp)
        
        # Alert tracking
        self.alerted_ips = set()
        
        # Geolocation service
        self.geolocator = get_geolocator()
    
    def process_event(self, event: Dict) -> List[Dict]:
        """
        Process a single authentication event and return any alerts.
        
        This method is COMPLETE - you don't need to modify it.
        It calls your detection methods automatically.
        
        Args:
            event: Dictionary with keys: timestamp, status, user, ip
            
        Returns:
            List of alert dictionaries
        """
        alerts = []
        
        ip = event["ip"]
        timestamp = event["timestamp"]
        status = event["status"]
        user = event["user"]
        
        # Store event
        self.all_events[ip].append(event)
        
        # Track failed attempts
        if status == "Failed":
            self.failed_attempts[ip].append(timestamp)
            self.user_attempts[ip].add(user)
            self.user_failed_by_ip[user][ip].append(timestamp)
        
        # ========================================
        # DETECTION ALGORITHMS
        # ========================================
        
        # 1. Fast Brute-Force Detection ✅ COMPLETE (example)
        fast_alerts = self._detect_fast_brute_force(ip, timestamp)
        alerts.extend(fast_alerts)
        
        # 2. Slow Brute-Force Detection 📝 TODO (you implement this)
        if not fast_alerts:
            slow_alerts = self._detect_slow_brute_force(ip, timestamp)
            alerts.extend(slow_alerts)
        
        # 3. Success After Failure (Account Compromise) 📝 TODO (you implement this)
        if status == "Accepted":
            compromise_alerts = self._detect_account_compromise(ip, user, timestamp)
            alerts.extend(compromise_alerts)
            
            # 5. Suspicious Location Detection ✅ COMPLETE (example)
            location_alerts = self._detect_suspicious_location(ip, user, timestamp)
            alerts.extend(location_alerts)
            
            # 6. Impossible Travel Detection 📝 TODO (you implement this)
            travel_alerts = self._detect_impossible_travel(ip, user, timestamp)
            alerts.extend(travel_alerts)
        
        # 4. Distributed Attack Detection (on failed attempts) 📝 TODO (you implement this)
        if status == "Failed":
            distributed_alerts = self._detect_distributed_attack(user, timestamp)
            alerts.extend(distributed_alerts)
        
        return alerts
    
    # ✅ EXAMPLE 1: FAST BRUTE-FORCE (COMPLETE)
    # Study this example to understand the pattern!
    
    def _detect_fast_brute_force(self, ip: str, current_time) -> List[Dict]:
        """
        ✅ COMPLETE EXAMPLE - Study this code!
        
        Detect rapid brute-force attacks.
        
        Algorithm:
        1. Check if we already alerted on this IP (avoid duplicates)
        2. Count failures in last 60 seconds
        3. Check if >= 5 failures AND >= 3 different usernames
        4. If yes, create alert and mark IP as alerted
        
        Returns:
            List with one alert, or empty list
        """
        # Step 1: Avoid duplicate alerts
        if ip in self.alerted_ips:
            return []
        
        # Step 2: Count recent failures (within time window)
        recent_failures = [
            t for t in self.failed_attempts[ip]
            if current_time - t <= self.fast_window
        ]
        
        # Step 3: Check thresholds
        if (len(recent_failures) >= FAILED_THRESHOLD_FAST
                and len(self.user_attempts[ip]) >= 3):
            
            # Step 4: Mark as alerted and create alert
            self.alerted_ips.add(ip)
            return [self._build_alert(ip, current_time, len(recent_failures),
                                      "FAST_BRUTE_FORCE")]
        
        return []
    
    # 📝 TODO 1: SLOW BRUTE-FORCE (YOU IMPLEMENT THIS)#########
    # Follow the pattern from fast brute-force above!

    def _detect_slow_brute_force(self, ip: str, current_time) -> List[Dict]:
        """
        📝 TODO: Implement slow brute-force detection
        
        Algorithm (similar to fast brute-force, but different thresholds):
        1. Check if we already alerted on this IP
        2. Count failures in last 10 minutes (use self.slow_window)
        3. Check if >= 10 failures AND >= 3 different usernames
        4. If yes, create alert using _build_alert
        
        Hints:
        - self.failed_attempts[ip] contains all failure timestamps
        - Use list comprehension to filter by time window
        - self.user_attempts[ip] contains the set of users tried
        - FAILED_THRESHOLD_SLOW is the threshold (10)
        - Use _build_alert helper to create the alert
        
        Returns:
            List with one alert, or empty list
        """
        # YOUR CODE HERE
        return []  # TODO: Remove this and implement the method
    
    # 📝 TODO 2: SUCCESS AFTER FAILURE (YOU IMPLEMENT THIS)#######
    
    def _detect_account_compromise(self, ip: str, user: str, current_time) -> List[Dict]:
        """
        📝 TODO: Detect successful login after multiple failures
        
        This detects when an attacker successfully guesses a password
        after many failed attempts.
        Algorithm:
        1. Count recent failures from this IP (last 5 minutes)
        2. If >= 5 failures in the window, account is compromised!
        3. Create CRITICAL alert
        
        Hints:
        - self.failed_attempts[ip] has failure timestamps
        - self.success_window is the 5-minute time window
        - FAILED_BEFORE_SUCCESS is the threshold (5)
        - Alert should include "compromised_account" field
        
        Returns:
            List with one alert, or empty list
        """
        # YOUR CODE HERE
        return []  # TODO: Remove this and implement the method
    
    # 📝 TODO 3: DISTRIBUTED ATTACK (YOU IMPLEMENT THIS)#########
    
    def _detect_distributed_attack(self, user: str, current_time) -> List[Dict]:
        """
        📝 TODO: Detect attacks from multiple IPs against same user
        
        This detects coordinated attacks where multiple attackers
        (from different IPs) target the same user account.
        Algorithm:
        1. Look at all IPs that failed against this user
        2. For each IP, count failures in last 10 minutes
        3. Keep IPs with >= 3 failures each
        4. If >= 3 different IPs meet criteria, it's distributed attack!
        5. Create alert with list of attacking IPs
        
        Hints:
        - self.user_failed_by_ip[user] is a dict: {ip: [timestamps]}
        - self.distributed_window is the 10-minute window
        - DISTRIBUTED_FAILED_PER_IP = 3 (min failures per IP)
        - DISTRIBUTED_ATTACK_THRESHOLD = 3 (min number of IPs)
        - Alert should include "source_ips" field with list of IPs
        
        Returns:
            List with one alert, or empty list
        """
        # YOUR CODE HERE
        return []  # TODO: Remove this and implement the method
    
    # ✅ EXAMPLE 2: SUSPICIOUS LOCATION (COMPLETE)#########
    # Study this example to see how geolocation works!
    
    def _detect_suspicious_location(self, ip: str, user: str, current_time) -> List[Dict]:
        """
        ✅ COMPLETE EXAMPLE - Study this code!
        
        Detect login from suspicious/high-risk country.
        
        Algorithm:
        1. Look up IP geolocation
        2. Check if country is in suspicious list (CN, RU, KP, IR)
        3. If yes, generate MEDIUM severity alert
        """
        geo_info = self.geolocator.lookup(ip)
        
        if geo_info and not geo_info.get("internal"):
            country = geo_info.get("country", "")
            
            if self.geolocator.is_suspicious_country(country):
                return [{
                    "ip": ip,
                    "user": user,
                    "time": current_time,
                    "type": "SUSPICIOUS_LOCATION",
                    "severity": SEVERITY_LEVELS["SUSPICIOUS_LOCATION"],
                    "location": self.geolocator.get_location_string(ip),
                    "country": country,
                    "message": f"Successful login from high-risk country: {country}"
                }]
        
        return []
    
    # 📝 TODO 4: IMPOSSIBLE TRAVEL (YOU IMPLEMENT THIS)##########
    # Follow the pattern from suspicious location above!
    
    def _detect_impossible_travel(self, ip: str, user: str, current_time) -> List[Dict]:
        """
        📝 TODO: Detect impossible travel between distant locations
        
        This detects when the same user logs in from two countries
        that are too far apart, too quickly (physically impossible).
        Algorithm:
        1. Look up current location (country) from IP
        2. Check if user has a previous login location saved
        3. If yes, calculate time difference and distance between countries
        4. If time_diff <= 1 hour AND distance >= 1000 km, it's impossible!
        5. Create alert and update user's location
        
        Hints:
        - self.geolocator.lookup(ip) gets location info
        - self.user_last_location[user] stores (country, timestamp)
        - self.geolocator.get_distance(country1, country2) calculates km
        - self.travel_window is the 1-hour window
        - IMPOSSIBLE_TRAVEL_MIN_DISTANCE is the threshold (1000 km)
        - Always update user_last_location at the end
        
        Returns:
            List with one alert, or empty list
        """
        # YOUR CODE HERE
        return []  # TODO: Remove this and implement the method
    
    # HELPER METHODS (COMPLETE - DON'T MODIFY)########
    
    def _build_alert(self, ip: str, timestamp, attempt_count: int, 
                     alert_type: str) -> Dict:
        """
        Helper to build brute-force alert dictionary.
        You can use this in your implementations!
        """
        geo_info = self.geolocator.lookup(ip)
        users_list = sorted(list(self.user_attempts[ip]))
        
        alert = {
            "ip": ip,
            "time": timestamp,
            "type": alert_type,
            "severity": SEVERITY_LEVELS[alert_type],
            "attempts": attempt_count,
            "users": users_list
        }
        
        if geo_info and not geo_info.get("internal"):
            alert["location"] = self.geolocator.get_location_string(ip)
        
        return alert