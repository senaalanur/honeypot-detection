#!/usr/bin/env python3
import json
import requests
import os
from email_alerts import send_email_alert  # Import the alert function

# Load API key from environment variable
HUGGINGFACE_API_KEY = os.getenv("HUGGINGFACE_API_KEY")
if not HUGGINGFACE_API_KEY:
    raise ValueError("Missing Hugging Face API Key. Set it using 'export HUGGINGFACE_API_KEY=<your_key>'")

def analyze_attack(log_data):
    # Attempt to extract the "message" field from the JSON log
    try:
        parsed = json.loads(log_data)
        # Use the "message" field if it exists, otherwise use the whole log
        text_to_summarize = parsed.get("message", log_data) if isinstance(parsed, dict) else log_data
    except json.JSONDecodeError:
        text_to_summarize = log_data

    # Truncate the text to a maximum length (e.g., 1024 characters)
    max_length = 1024
    if len(text_to_summarize) > max_length:
        text_to_summarize = text_to_summarize[:max_length]

    # Use the summarization model from Hugging Face
    url = "https://api-inference.huggingface.co/models/facebook/bart-large-cnn"
    headers = {"Authorization": f"Bearer {HUGGINGFACE_API_KEY}"}
    payload = {"inputs": text_to_summarize}

    response = requests.post(url, headers=headers, json=payload)
    if response.status_code == 200:
        try:
            result = response.json()
            print("Debug: Raw summarization response:")
            print(result)
            if isinstance(result, list) and "summary_text" in result[0]:
                return result[0]["summary_text"]
            else:
                return "Unexpected response format: " + json.dumps(result)
        except (IndexError, KeyError) as e:
            return "Error processing response: " + str(e)
    else:
        return f"Error: {response.status_code} - {response.text}"

def get_latest_attack():
    # Query Elasticsearch for any index that starts with "cowrie-logs"
    es_url = "http://localhost:9200/cowrie-logs-*/_search"
    try:
        response = requests.get(es_url, json={"size": 1})
        if response.status_code != 200:
            return f"Error fetching attack log: {response.status_code} - {response.text}"
        logs = response.json()
        hits = logs.get("hits", {}).get("hits", [])
        if not hits:
            return "No logs found. Is Cowrie running and logging data?"
        attack_log = hits[0].get("_source", {})
        return json.dumps(attack_log, indent=4)
    except requests.RequestException as e:
        return f"Error connecting to Elasticsearch: {str(e)}"

if __name__ == "__main__":
    latest_attack = get_latest_attack()
    print("Latest Attack Log:")
    print(latest_attack)
    analysis_result = analyze_attack(latest_attack)
    print("\nAnalysis:")
    print(analysis_result)

    # Example condition: if no logs are found, send an email alert.
    if "No logs found" in latest_attack:
        alert_message = (
            f"Alert: No logs found in Elasticsearch!\n"
            f"Latest log output:\n{latest_attack}\n"
            f"Analysis:\n{analysis_result}"
        )
        send_email_alert(alert_message)
        print("Alert email has been sent!")
