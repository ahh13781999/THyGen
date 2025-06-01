import json
import requests

# Fetch MITRE ATT&CK Enterprise JSON data
url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
response = requests.get(url)
data = response.json()

# Extract technique-to-tactic mappings
mapping = {}
for entry in data["objects"]:
    if entry["type"] == "attack-pattern" and "external_references" in entry:
        # Extract technique ID (e.g., T1003)
        tech_id = next(
            (ref["external_id"] for ref in entry["external_references"] if ref["source_name"] == "mitre-attack"),
            None
        )
        if tech_id:
            # Extract tactics (e.g., "Credential Access")
            tactics = [phase["phase_name"] for phase in entry.get("kill_chain_phases", [])]
            if tactics:
                mapping[tech_id] = tactics[0]  # Use primary tactic

# Save to JSON
with open("mitre_mapping.json", "w") as f:
    json.dump(mapping, f, indent=2)