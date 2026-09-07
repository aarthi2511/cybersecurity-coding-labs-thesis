# reporter.py - Simple Alert Reporter

from collections import defaultdict


class AlertReporter:
    
    def __init__(self):
        self.total_alerts = 0
        self.severity_count = defaultdict(int)
        self.attack_type_count = defaultdict(int)
    
    def report(self, alert: dict):
      
        self.total_alerts += 1
        
        severity = alert.get("severity", "UNKNOWN")
        attack_type = alert.get("type", "UNKNOWN")
        self.severity_count[severity] += 1
        self.attack_type_count[attack_type] += 1
        
        print("\n" + "=" * 60)
        print(f"=== SECURITY ALERT [{severity}] ===")
        print("=" * 60)
        print(f"Type        : {attack_type}")
        print(f"Severity    : {severity}")
        print(f"Time        : {alert.get('time', 'Unknown')}")
        
        if "ip" in alert:
            print(f"Source IP   : {alert['ip']}")
            if "location" in alert:
                print(f"Location    : {alert['location']}")
       
        if "attempts" in alert:
            print(f"Attempts    : {alert['attempts']}")
     
        if "users" in alert:
            users = alert["users"]
            if len(users) <= 5:
                print(f"Users       : {', '.join(users)}")
            else:
                print(f"Users       : {', '.join(users[:5])} (+{len(users)-5} more)")
        
        if "compromised_account" in alert:
            print(f"⚠️  COMPROMISED: Account '{alert['compromised_account']}' may be breached!")
      
        if alert.get("type") == "IMPOSSIBLE_TRAVEL":
            if "user" in alert:
                print(f"User        : {alert['user']}")
            if "previous_location" in alert:
                print(f"Previous    : {alert['previous_location']}")
            if "current_location" in alert:
                print(f"Current     : {alert['current_location']}")
            if "distance_km" in alert:
                print(f"Distance    : {alert['distance_km']} km")
            if "time_diff_minutes" in alert:
                print(f"Time Gap    : {alert['time_diff_minutes']} minutes")
        
        if "source_ips" in alert:
            print(f"Source IPs  : {len(alert['source_ips'])} different addresses")
            for ip in alert['source_ips'][:3]:
                print(f"            - {ip}")
            if len(alert['source_ips']) > 3:
                print(f"            ... and {len(alert['source_ips'])-3} more")
        
        if "message" in alert:
            print(f"Details     : {alert['message']}")
        
        print("=" * 60)
    
    def summary(self):
        """
        Display summary of all alerts.
        """
        print("\n" + "=" * 60)
        print("=== DETECTION SUMMARY ===")
        print("=" * 60)
        
        if self.total_alerts == 0:
            print("No suspicious activity detected.")
            print("=" * 60)
            return
        
        print(f"Total Alerts: {self.total_alerts}")
        print()
  
        print("By Severity:")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = self.severity_count.get(severity, 0)
            if count > 0:
                print(f"  {severity:12s}: {count}")
        print()
     
        print("By Attack Type:")
        for attack_type in sorted(self.attack_type_count.keys()):
            count = self.attack_type_count[attack_type]
            print(f"  {attack_type:30s}: {count}")
        
        print("=" * 60)