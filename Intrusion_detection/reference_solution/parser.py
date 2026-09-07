# parser.py - Simple Log Parser

from datetime import datetime
from typing import List, Dict


def parse_log(filename="auth.log") -> List[Dict]:
    
    events = []
    
    try:
        with open(filename, "r") as f:
            for line_num, line in enumerate(f, 1):
                try:
                    parts = line.strip().split()
                    
                    # Parse timestamp
                    timestamp = datetime.strptime(
                        parts[0] + " " + parts[1],
                        "%Y-%m-%d %H:%M:%S"
                    )
                    
                    # Parse status (Failed or Accepted)
                    status = parts[3]
                    
                    # Parse username
                    user = parts[6]
                    
                    # Parse IP address (last element)
                    ip = parts[-1]
                    
                    events.append({
                        "timestamp": timestamp,
                        "status": status,
                        "user": user,
                        "ip": ip
                    })
                    
                except (IndexError, ValueError) as e:
                    # Skip malformed lines
                    print(f"Warning: Skipping malformed line {line_num}")
                    continue
    
    except FileNotFoundError:
        print(f"Error: Log file '{filename}' not found")
        return []
     
    return events