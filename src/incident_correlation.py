import json
import uuid
from pathlib import Path
from collections import defaultdict

INPUT_FILE = Path("data/normalized_alerts.json")
OUTPUT_FILE = Path("data/incidents.json")


def load_alerts(path: Path) -> list:
    if not path.exists():
        raise FileNotFoundError(f"Missing input file: {path}")

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def calculate_severity(alert_count: int) -> str:
    if alert_count >= 5:
        return "Critical"
    elif alert_count >= 3:
        return "High"
    elif alert_count >= 2:
        return "Medium"
    return "Low"


def correlate_alerts(alerts: list) -> list:
    grouped = defaultdict(list)

    for alert in alerts:
        grouped[alert["source_ip"]].append(alert)

    incidents = []

    for source_ip, alerts in grouped.items():
        timestamps = [a["timestamp"] for a in alerts]

        incident = {
            "incident_id": str(uuid.uuid4()),
            "source_ip": source_ip,
            "attack_type": alerts[0]["attack_type"],
            "first_seen": min(timestamps),
            "last_seen": max(timestamps),
            "alert_count": len(alerts),
            "severity": calculate_severity(len(alerts)),
            "alerts": alerts
        }

        incidents.append(incident)

    return incidents


def save_incidents(incidents: list, path: Path):
    with path.open("w", encoding="utf-8") as f:
        json.dump(incidents, f, indent=2)


def main():
    alerts = load_alerts(INPUT_FILE)
    incidents = correlate_alerts(alerts)
    save_incidents(incidents, OUTPUT_FILE)

    print(f"Generated {len(incidents)} incidents.")


if __name__ == "__main__":
    main()
