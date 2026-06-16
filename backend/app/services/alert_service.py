def classify_alert(event_type: str, risk_level: str) -> dict:
    severity = "critical" if risk_level == "high" else "warning" if risk_level == "medium" else "info"
    return {"severity": severity, "event_type": event_type}

