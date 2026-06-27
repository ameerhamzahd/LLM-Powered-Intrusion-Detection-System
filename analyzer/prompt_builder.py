"""Formats extracted flow features into a prompt for the local LLM, and
defines the exact JSON schema we expect back.
"""

import json

SYSTEM_INSTRUCTIONS = """You are a network intrusion detection analyst.
You will be given statistics for one network flow. Classify it and explain why.

Respond with ONLY a JSON object in this exact shape, no other text:
{
  "classification": "Benign" | "Suspicious" | "Attack",
  "confidence": <number between 0 and 1>,
  "explanation": "<one or two plain-English sentences>"
}

Guidance:
- "Benign": normal traffic patterns, established connections, expected ports.
- "Suspicious": unusual but not clearly malicious (e.g. uncommon port, mild anomaly).
- "Attack": strong signs of scanning, flooding, or exploitation
  (e.g. many SYNs with no matching ACKs, abnormal packet rate, known bad ports).
"""


def build_prompt(features: dict) -> str:
    flow_json = json.dumps(features, indent=2)
    return f"{SYSTEM_INSTRUCTIONS}\nFlow data:\n{flow_json}\n"