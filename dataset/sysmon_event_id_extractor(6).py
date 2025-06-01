import json

# Load your dataset (assuming it's a JSON file with a list of objects)
with open("sysmon_sentences_enriched.json", "r") as f:
    data = json.load(f)

# Use a set to store unique EventIDs
unique_event_ids = set()

for entry in data:
    event_id = entry.get("metadata", {}).get("EventID")
    if event_id:
        unique_event_ids.add(event_id)

# Write the unique EventIDs to a file
with open("event_ids.txt", "w") as out_file:
    for event_id in sorted(unique_event_ids):
        out_file.write(f"{event_id}\n")
