# generator.py - Simplified Log Generator

import random
from datetime import datetime, timedelta
from config import RANDOM_SEED, TOTAL_LOG_ENTRIES

USERS = ["joe", "mike", "jack", "leo"]

INTERNAL_IPS = ["192.168.1.10", "192.168.1.11"]

ATTACKER_IP_POOL = [
    "203.0.113.50", "203.0.113.51", "203.0.113.52", "203.0.113.53",
    "203.0.113.60", "203.0.113.61", "203.0.113.62", "203.0.113.63",
]

DISTRIBUTED_IP_POOL = [
    "198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.13",
    "198.51.100.20", "198.51.100.21", "198.51.100.22", "198.51.100.23",
]

SUSPICIOUS_IP_POOL = [
    "123.125.114.144", "123.125.114.145", "123.125.114.146",  # Shanghai
    "110.242.68.66", "110.242.68.67", "110.242.68.68",         # Beijing
]

ATTACKER_IPS = []
SUSPICIOUS_IP = None
IMPOSSIBLE_TRAVEL_IP_US = None
IMPOSSIBLE_TRAVEL_IP_CN = None


def generate_logs(filename="auth.log"):
    """
    Generate realistic authentication logs with 6 attack scenarios.
    
    Scenarios:
    1. Normal internal traffic (scattered throughout)
    2. Fast brute-force attack (entries 200-245)
    3. Account compromise after brute-force (entry 246)
    4. Distributed attack - same user, multiple IPs (entries 300-340)
    5. Suspicious location - login from high-risk country (entries 400-410)
    6. Impossible travel - same user, distant locations (entries 450-460)
    """
    global ATTACKER_IPS, SUSPICIOUS_IP, IMPOSSIBLE_TRAVEL_IP_US, IMPOSSIBLE_TRAVEL_IP_CN
    
    if RANDOM_SEED is not None:
        random.seed(RANDOM_SEED)
    
    ATTACKER_IPS = [
        random.choice(ATTACKER_IP_POOL),      # Fast brute-force
        random.choice(ATTACKER_IP_POOL),      # Slow brute-force
    ]
    
    # Distributed attack needs 3 UNIQUE IPs
    distributed_ips = random.sample(DISTRIBUTED_IP_POOL, 3)  # Picks 3 unique
    ATTACKER_IPS.extend(distributed_ips)
    
    SUSPICIOUS_IP = random.choice(SUSPICIOUS_IP_POOL)
    IMPOSSIBLE_TRAVEL_IP_US = random.choice(DISTRIBUTED_IP_POOL)
    IMPOSSIBLE_TRAVEL_IP_CN = random.choice(ATTACKER_IP_POOL)
    
    start_time = datetime.now()
    
    with open(filename, "w") as f:
        for i in range(TOTAL_LOG_ENTRIES):
            timestamp = start_time + timedelta(seconds=i * 3)
            
            # SCENARIO SELECTION
            
            if 200 <= i <= 245:
                # SCENARIO 1: Fast brute-force attack (46 rapid attempts)
                ip = ATTACKER_IPS[0]
                status = "Failed"
                user = random.choice(USERS)  
            
            elif i == 246:
                # SCENARIO 2: Successful compromise after brute-force
                ip = ATTACKER_IPS[0]
                status = "Accepted"
                user = "joe"
            
            elif i % 40 == 0 and not (200 <= i <= 246 or 300 <= i <= 340 or 400 <= i <= 410):
                # SCENARIO 3: Slow brute-force 
                ip = ATTACKER_IPS[1]
                status = "Failed"
                user = random.choice(USERS)
            
            elif 300 <= i <= 340 and i % 3 == 0:
                # SCENARIO 4: Distributed attack - same user, multiple IPs
                ip = random.choice(ATTACKER_IPS[2:5])  
                status = "Failed"
                user = "admin"  
            
            elif 400 <= i <= 410:
                # SCENARIO 5: Suspicious location (login from China)
                ip = SUSPICIOUS_IP
                status = "Accepted" if i == 408 else "Failed"
                user = "mike"
            
            elif 450 <= i <= 500:
                # SCENARIO 6: Impossible travel (leo logs in from USA then China quickly)
                if i == 450:
                    # Login from USA (New York)
                    ip = IMPOSSIBLE_TRAVEL_IP_US
                    status = "Accepted"
                    user = "leo"
                elif i == 470:
                    # Login from China (Beijing) 60 seconds later - IMPOSSIBLE!
                    ip = IMPOSSIBLE_TRAVEL_IP_CN
                    status = "Accepted"
                    user = "leo"
                else:
                    # Normal traffic
                    ip = random.choice(INTERNAL_IPS)
                    status = "Accepted"
                    user = "joe" if ip == INTERNAL_IPS[0] else "mike"
            
            else:
                # Normal legitimate traffic - internal users always succeed
                ip = random.choice(INTERNAL_IPS)
                status = "Accepted"
                user = "joe" if ip == INTERNAL_IPS[0] else "mike"
            
            log_entry = (
                f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} "
                f"sshd: {status} password for {user} from {ip}\n"
            )
            f.write(log_entry)
    
    print(f"Generated {TOTAL_LOG_ENTRIES} log entries with attack scenarios:")
    print("  ✓ Fast brute-force (entries 200-246)")
    print("  ✓ Slow brute-force (scattered)")
    print("  ✓ Distributed attack (entries 300-340)")
    print("  ✓ Suspicious location (entries 400-410)")
    print("  ✓ Impossible travel (entries 450, 470)")


if __name__ == "__main__":
    generate_logs()