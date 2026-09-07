# main.py
# ============================================================
# LAB 1: Log-Based Intrusion Detection System
# Main Pipeline - No changes needed here
# ============================================================

from generator import generate_logs
from parser    import parse_log
from detector  import IntrusionDetector
from reporter  import AlertReporter


def main():
    print("=" * 60)
    print("  LOG-BASED INTRUSION DETECTION SYSTEM")
    print("=" * 60)
    print()

    # Step 1 - Generate logs
    print("[1/4] Generating authentication logs...")
    generate_logs()
    print()

    # Step 2 - Parse logs
    print("[2/4] Parsing log file...")
    events = parse_log()
    print(f"      Parsed {len(events)} events")
    print()

    # Step 3 - Detect attacks
    print("[3/4] Analysing events for intrusions...")
    detector = IntrusionDetector()
    reporter = AlertReporter()

    for event in events:
        alerts = detector.process_event(event)
        for alert in alerts:
            reporter.report(alert)

    print("      Analysis complete")
    print()

    # Step 4 - Summary
    print("[4/4] Generating summary...")
    reporter.summary()
    print()
    print("Done!")


if __name__ == "__main__":
    main()