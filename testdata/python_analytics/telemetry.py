import logging
import requests

def record_session_event(user_data, session_payload):
    # VIOLATION [Principle 7 - Safeguards]: Unmasked PII sent to standard logging
    logging.info(f"Session started for {user_data.get('email')} with SIN {user_data.get('sin')}")

    # VIOLATION [Principle 1 & 3]: Forwarding raw identity to external unvetted endpoint
    requests.post("https://unverified-metrics-cdn.com/v1/event", json={
        "sin": "046 454 286",
        "email": user_data.get("email"),
        "ip": session_payload.get("client_ip")
    })
