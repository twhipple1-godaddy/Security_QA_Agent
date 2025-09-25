#!/usr/bin/env python3
import os
import sys

# Ensure project root on path
PROJECT_ROOT = "/Users/twhipple1/Documents/GitHub/Security_QA_Agent"
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from scripts.soc_qa_agent import SOCQAAgent


def main() -> int:
    earliest = os.getenv("EARLIEST", "-30d@d")
    latest = os.getenv("LATEST", "-1d@d")
    try:
        limit = int(os.getenv("LIMIT", "50"))
    except ValueError:
        limit = 50

    print(f"Fetching incidents earliest={earliest} latest={latest}")
    agent = SOCQAAgent()
    incidents = agent.get_closed_incidents(earliest=earliest, latest=latest)
    print(f"Found {len(incidents)} incidents")

    success = 0
    fail = 0

    # Process a bounded batch
    for idx, it in enumerate(incidents[:limit], start=1):
        try:
            report = agent.analyze_incident(
                it.get("incident_id"),
                it.get("title"),
                it.get("analyst", "unknown"),
                it.get("notable_data", []),
                it.get("audit_data", []),
            )
            if agent.save_report_to_splunk(report):
                success += 1
            else:
                fail += 1
        except Exception as e:
            fail += 1
            print(f"Error on {it.get('incident_id')}: {e}")

    print(f"Completed. Success: {success}, Fail: {fail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


