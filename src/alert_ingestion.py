import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

# File paths
INPUT_FILE = Path("data/web_sql_injection_alerts.json")
OUTPUT_FILE = Path("data/normalized_alerts.json")


def normalize_alert(alert: dict) -> dict:
    """
    Normalize a raw SIEM alert into a canonical SOC event schema.
    """
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": alert.get(
            "timestamp",
            datetime.now(timezone.utc).isoformat()
        ),
        "source_ip": alert.get("src_ip", "unknown"),
        "destination": alert.get("dest", "unknown"),
        "attack_type": "SQL Injection",
        "severity": alert.get("severity", "High"),
        "raw_signature": alert.get("signature", "unknown"),
        "confidence": 0.85
    }


def load_alerts(file_path: Path) -> list:
    """
    Load alerts from a JSON file.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        return json.load(f)


def save_alerts(alerts: list, file_path: Path) -> None:
    """
    Save normalized alerts to a JSON file.
    """
    # Create parent directory if it doesn't exist
    file_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(file_path, 'w') as f:
        json.dump(alerts, f, indent=2)


def main():
    """
    Main processing function.
    """
    try:
        # Load raw alerts
        raw_alerts = load_alerts(INPUT_FILE)
        print(f"Loaded {len(raw_alerts)} alerts from {INPUT_FILE}")
        
        # Normalize alerts
        normalized_alerts = [normalize_alert(alert) for alert in raw_alerts]
        
        # Save normalized alerts
        save_alerts(normalized_alerts, OUTPUT_FILE)
        print(f"Saved {len(normalized_alerts)} normalized alerts to {OUTPUT_FILE}")
        
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()