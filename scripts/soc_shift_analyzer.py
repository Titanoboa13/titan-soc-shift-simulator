import csv
import os

INPUT_FILE = "../logs/soc_alert_queue.csv"
OUTPUT_DIR = "../output"

ESCALATED_FILE = os.path.join(OUTPUT_DIR, "escalated_alerts.txt")
SHIFT_REPORT_FILE = os.path.join(OUTPUT_DIR, "shift_report.txt")


def classify_alert(alert):
    process = alert["process"].lower()
    parent = alert["parent_process"].lower()
    command = alert["command"].lower()
    severity = alert["severity"].lower()

    # Benign patterns
    if (
        severity == "low"
        and process == "powershell.exe"
        and parent in ["explorer.exe", "taskeng.exe"]
        and "encodedcommand" not in command
    ):
        return "Benign"

    # Monitor patterns
    if severity == "medium":
        return "Monitor"

    # Escalation patterns
    if "encodedcommand" in command:
        return "Escalate"

    # Incident patterns
    if process in ["mshta.exe"] and "http" in command:
        return "Incident"

    return "Monitor"


def analyze_alert(alert):
    category = classify_alert(alert)

    analysis = {
        "alert_id": alert["alert_id"],
        "category": category,
        "summary": ""
    }

    if category == "Benign":
        analysis["summary"] = (
            "Activity consistent with expected user or system behavior. "
            "No indicators of malicious intent observed."
        )

    elif category == "Monitor":
        analysis["summary"] = (
            "Suspicious characteristics observed. "
            "Requires monitoring for additional indicators."
        )

    elif category == "Escalate":
        analysis["summary"] = (
            "High-risk behavior detected. "
            "Escalation to Tier-2 required for deeper investigation."
        )

    elif category == "Incident":
        analysis["summary"] = (
            "Confirmed malicious behavior detected. "
            "Immediate incident response actions required."
        )

    return analysis


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    escalated_alerts = []
    shift_summary = {
        "Benign": 0,
        "Monitor": 0,
        "Escalate": 0,
        "Incident": 0
    }

    with open(INPUT_FILE, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)

        for alert in reader:
            result = analyze_alert(alert)
            shift_summary[result["category"]] += 1

            if result["category"] in ["Escalate", "Incident"]:
                escalated_alerts.append(result)

    with open(ESCALATED_FILE, "w", encoding="utf-8") as f:
        for alert in escalated_alerts:
            f.write(f"{alert['alert_id']} - {alert['category']}\n")
            f.write(f"{alert['summary']}\n\n")

    with open(SHIFT_REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("SOC Shift Summary Report\n")
        f.write("========================\n\n")
        for k, v in shift_summary.items():
            f.write(f"{k}: {v}\n")

    print("SOC shift analysis completed.")


if __name__ == "__main__":
    main()
