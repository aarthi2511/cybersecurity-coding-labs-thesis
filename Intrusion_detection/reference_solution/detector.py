# detector.py - Simplified Intrusion Detection (5 Detection Types)

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
    
    Detection types:
    1. Fast brute-force attacks
    2. Slow brute-force attacks
    3. Success after failure (account compromise)
    4. Distributed attacks (same user, multiple IPs)
    5. Suspicious location (high-risk countries)
    6. Impossible travel (same user, distant locations)
    """
    def __init__(self):   
        self.fast_window = timedelta(seconds=TIME_WINDOW_FAST_SECONDS)
        self.slow_window = timedelta(seconds=TIME_WINDOW_SLOW_SECONDS)
        self.success_window = timedelta(seconds=SUCCESS_TIME_WINDOW_SECONDS)
        self.distributed_window = timedelta(seconds=DISTRIBUTED_TIME_WINDOW)
        self.travel_window = timedelta(seconds=IMPOSSIBLE_TRAVEL_TIME_WINDOW) 
        self.failed_attempts = defaultdict(list) 
        self.user_attempts = defaultdict(set)     
        self.all_events = defaultdict(list)       
        self.user_failed_by_ip = defaultdict(lambda: defaultdict(list))
        self.user_last_location = {}
        self.alerted_ips = set()
        self.alerted_users = set()
        self.geolocator = get_geolocator()
    
    def process_event(self, event: Dict) -> List[Dict]:
        """
        Process a single authentication event and return any alerts.
        """
        alerts = []
        ip = event["ip"]
        timestamp = event["timestamp"]
        status = event["status"]
        user = event["user"]
        self.all_events[ip].append(event)
        if status == "Failed":
            self.failed_attempts[ip].append(timestamp)
            self.user_attempts[ip].add(user)
            self.user_failed_by_ip[user][ip].append(timestamp)

        # DETECTION ALGORITHMS
        
        # 1. Fast Brute-Force Detection
        fast_alerts = self._detect_fast_brute_force(ip, timestamp)
        alerts.extend(fast_alerts)
        
        # 2. Slow Brute-Force Detection (only if no fast attack)
        if not fast_alerts:
            slow_alerts = self._detect_slow_brute_force(ip, timestamp)
            alerts.extend(slow_alerts)
        
        # 3. Success After Failure (Account Compromise)
        if status == "Accepted":
            compromise_alerts = self._detect_account_compromise(ip, user, timestamp)
            alerts.extend(compromise_alerts)
            
            # 5. Suspicious Location Detection (on successful login)
            location_alerts = self._detect_suspicious_location(ip, user, timestamp)
            alerts.extend(location_alerts)
            
            # 6. Impossible Travel Detection (on successful login)
            travel_alerts = self._detect_impossible_travel(ip, user, timestamp)
            alerts.extend(travel_alerts)
        
        # 4. Distributed Attack Detection (on failed attempts)
        if status == "Failed":
            distributed_alerts = self._detect_distributed_attack(user, timestamp)
            alerts.extend(distributed_alerts)
        
        return alerts
    
    def _detect_fast_brute_force(self, ip: str, current_time) -> List[Dict]:
        """
        - Count failures in last 60 seconds
        - If >= 5 failures AND >= 3 different users
        - Generate HIGH severity alert
        """
        if ip in self.alerted_ips:
            return []
        recent_failures = [
            t for t in self.failed_attempts[ip]
            if current_time - t <= self.fast_window
        ]
        self.failed_attempts[ip] = recent_failures
        if (len(recent_failures) >= FAILED_THRESHOLD_FAST and
            len(self.user_attempts[ip]) >= 3):
            self.alerted_ips.add(ip)
            return [{
                "ip": ip,
                "time": current_time,
                "attempts": len(recent_failures),
                "type": "FAST_BRUTE_FORCE",
                "severity": SEVERITY_LEVELS["FAST_BRUTE_FORCE"],
                "users": list(self.user_attempts[ip]),
                "location": self.geolocator.get_location_string(ip)
            }]
        return []
    
    def _detect_slow_brute_force(self, ip: str, current_time) -> List[Dict]:
        """
        - Count failures in last 10 minutes
        - If >= 10 failures AND >= 3 different users
        - Generate MEDIUM severity alert
        """
        if ip in self.alerted_ips:
            return []
        slow_failures = [
            t for t in self.failed_attempts[ip]
            if current_time - t <= self.slow_window
        ]
        if (len(slow_failures) >= FAILED_THRESHOLD_SLOW and
            len(self.user_attempts[ip]) >= 3): 
            self.alerted_ips.add(ip)  
            return [{
                "ip": ip,
                "time": current_time,
                "attempts": len(slow_failures),
                "type": "SLOW_BRUTE_FORCE",
                "severity": SEVERITY_LEVELS["SLOW_BRUTE_FORCE"],
                "users": list(self.user_attempts[ip]),
                "location": self.geolocator.get_location_string(ip)
            }]   
        return []
    def _detect_account_compromise(self, ip: str, user: str, current_time) -> List[Dict]:
        """
        - Count recent failures from this IP (last 5 minutes)
        - If >= 5 failures before this success
        - Generate CRITICAL severity alert
        """
        recent_failures = [
            e for e in self.all_events[ip]
            if (e["status"] == "Failed" and
                current_time - e["timestamp"] <= self.success_window)
        ] 
        if len(recent_failures) >= FAILED_BEFORE_SUCCESS:
            return [{
                "ip": ip,
                "time": current_time,
                "attempts": len(recent_failures),
                "type": "SUCCESS_AFTER_FAILURE",
                "severity": SEVERITY_LEVELS["SUCCESS_AFTER_FAILURE"],
                "users": [user],
                "compromised_account": user,
                "location": self.geolocator.get_location_string(ip)
            }]
        return []
    
    def _detect_distributed_attack(self, user: str, current_time) -> List[Dict]:
        """
        - For each user, track failures per IP
        - Count IPs with >= 3 failures in last 10 minutes
        - If >= 3 different IPs attacking same user
        - Generate HIGH severity alert
        """
        alert_key = f"distributed_{user}"
        if alert_key in self.alerted_users:
            return [] 
        attacking_ips = {}
        for ip, failures in self.user_failed_by_ip[user].items():
            recent_failures = [
                t for t in failures
                if current_time - t <= self.distributed_window
            ]
            if len(recent_failures) >= DISTRIBUTED_FAILED_PER_IP:
                attacking_ips[ip] = len(recent_failures)
        if len(attacking_ips) >= DISTRIBUTED_ATTACK_THRESHOLD:
            self.alerted_users.add(alert_key)
            total_attempts = sum(attacking_ips.values())
            return [{
                "user": user,
                "time": current_time,
                "source_ips": list(attacking_ips.keys()),
                "attempts": total_attempts,
                "type": "DISTRIBUTED_ATTACK",
                "severity": SEVERITY_LEVELS["DISTRIBUTED_ATTACK"],
                "ip_count": len(attacking_ips),
                "message": f"User '{user}' targeted from {len(attacking_ips)} different IPs"
            }]

        return []

    def _detect_suspicious_location(self, ip: str, user: str, current_time) -> List[Dict]:
        """
        - Lookup IP geolocation
        - Check if country is in suspicious list (CN, RU, KP, IR)
        - If yes, generate MEDIUM severity alert
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
 
    def _detect_impossible_travel(self, ip: str, user: str, current_time) -> List[Dict]:
        """
        - Check user's last login location and time
        - If from different country within travel_window
        - Calculate distance between countries
        - If distance > IMPOSSIBLE_TRAVEL_MIN_DISTANCE, alert
        """
        geo_info = self.geolocator.lookup(ip)   
        if not geo_info or geo_info.get("internal"):
            return [] 
        current_country = geo_info.get("country")
        if not current_country:
            return []  
        if user in self.user_last_location:
            prev_country, prev_time = self.user_last_location[user]
            time_diff = current_time - prev_time          
            if time_diff <= self.travel_window and current_country != prev_country:
                distance = self.geolocator.get_distance(prev_country, current_country)
          
                if distance and distance >= IMPOSSIBLE_TRAVEL_MIN_DISTANCE:
                    alert = {
                        "user": user,
                        "time": current_time,
                        "type": "IMPOSSIBLE_TRAVEL",
                        "severity": SEVERITY_LEVELS["IMPOSSIBLE_TRAVEL"],
                        "previous_location": prev_country,
                        "current_location": current_country,
                        "current_ip": ip,
                        "distance_km": distance,
                        "time_diff_minutes": int(time_diff.total_seconds() / 60),
                        "message": f"User '{user}' logged in from {current_country} "
                                   f"only {int(time_diff.total_seconds() / 60)} minutes "
                                   f"after login from {prev_country} "
                                   f"({distance} km apart)"
                    }
                    self.user_last_location[user] = (current_country, current_time)
                    return [alert]
        self.user_last_location[user] = (current_country, current_time)
        return []