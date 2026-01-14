import json
from pathlib import Path

INPUT_FILE = Path("data/incidents.json")
OUTPUT_FILE = Path("data/ai_incident_reports.json")


def load_incidents(path: Path) -> list:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def analyze_incident(incident: dict) -> dict:
    alert_count = incident["alert_count"]
    severity = incident["severity"]

    # Heuristic risk scoring
    risk_score = min(100, alert_count * 25)

    business_impact = "Low"
    if risk_score >= 75:
        business_impact = "High"
    elif risk_score >= 50:
        business_impact = "Medium"

    return {
        "incident_id": incident["incident_id"],
        "threat_classification": "Web Application Attack",
        "risk_score": risk_score,
        "business_impact": business_impact,
        "recommended_actions": [
            "Block source IP at firewall or WAF",
            "Review web server and application logs",
            "Validate input sanitization and patch application",
            "Monitor for additional attack attempts"
        ],
        "summary": (
            f"AI analysis identified a {incident['attack_type']} "
            f"originating from {incident['source_ip']} with "
            f"{alert_count} correlated alerts. "
            f"Risk score assessed at {risk_score}, "
            f"indicating {business_impact} business impact."
        )
    }


def save_reports(reports: list, path: Path):
    with path.open("w", encoding="utf-8") as f:
        json.dump(reports, f, indent=2)


def main():
    incidents = load_incidents(INPUT_FILE)
    reports = [analyze_incident(i) for i in incidents]
    save_reports(reports, OUTPUT_FILE)

    print(f"Generated {len(reports)} AI incident reports.")


if __name__ == "__main__":
    main()
