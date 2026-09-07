# config.py - Simplified Configuration for 6 Detection Types

# ============================================================
# LOG GENERATION SETTINGS
# ============================================================

# RANDOM LOG GENERATION - Different every run
# Each time students run the lab, they get completely different:
# - Attack IP addresses
# - User patterns
# - Distributed attack IPs
# - Suspicious location IPs

RANDOM_SEED = None  #  different logs every single run

TOTAL_LOG_ENTRIES = 500

# NETWORK ASSUMPTIONS

INTERNAL_IP_PREFIX = "192.168."

# DETECTION PARAMETERS

# Fast brute-force attack detection
FAILED_THRESHOLD_FAST = 5
TIME_WINDOW_FAST_SECONDS = 60

# Slow brute-force attack detection
FAILED_THRESHOLD_SLOW = 10
TIME_WINDOW_SLOW_SECONDS = 600  # 10 minutes

# Success-after-failure detection (account compromise)
FAILED_BEFORE_SUCCESS = 5
SUCCESS_TIME_WINDOW_SECONDS = 300  # 5 minutes

# Distributed attack detection (same user, multiple IPs)
DISTRIBUTED_ATTACK_THRESHOLD = 3  
DISTRIBUTED_TIME_WINDOW = 600  # 10 minutes
DISTRIBUTED_FAILED_PER_IP = 3  

# Impossible travel detection (same user, distant locations)
IMPOSSIBLE_TRAVEL_TIME_WINDOW = 3600  # 1 hour
IMPOSSIBLE_TRAVEL_MIN_DISTANCE = 1000  # km (approximate)

# GEOLOCATION SETTINGS
ENABLE_GEOLOCATION = True
GEOLOCATION_CACHE_FILE = "geo_cache.json"

# High-risk countries (suspicious locations)
SUSPICIOUS_COUNTRY_LIST = ["CN", "RU", "KP", "IR"]

# SEVERITY LEVELS
SEVERITY_LEVELS = {
    "FAST_BRUTE_FORCE": "HIGH",
    "SLOW_BRUTE_FORCE": "MEDIUM",
    "SUCCESS_AFTER_FAILURE": "CRITICAL",
    "DISTRIBUTED_ATTACK": "HIGH",
    "SUSPICIOUS_LOCATION": "MEDIUM",
    "IMPOSSIBLE_TRAVEL": "HIGH"
}