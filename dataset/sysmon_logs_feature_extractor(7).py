import os
import re
import json
import sys
import xml.etree.ElementTree as ET
from typing import Dict, List

def parse_xml_event(entry: str, label: str) -> Dict[str, str]:
    """Parse a single Sysmon XML event and extract all specified fields"""
    try:
        event = ET.fromstring(entry)
    except ET.ParseError:
        return {}

    # Handle namespaces
    ns = {}
    if event.tag.startswith("{"):
        ns_uri = event.tag.split("}")[0][1:]
        ns = {"ns": ns_uri}
        prefix = "ns:"
    else:
        prefix = ""

    features = {"label": label}

    # System section - get EventID
    system = event.find(f"./{prefix}System", ns)
    if system is not None:
        # EventID
        event_id = system.find(f"{prefix}EventID", ns)
        if event_id is not None and event_id.text:
            features["EventID"] = event_id.text.strip()

        # Execution ProcessID
        execution = system.find(f"{prefix}Execution", ns)
        if execution is not None:
            features["ProcessId"] = execution.attrib.get("ProcessID")

    # EventData section - extract all specified fields
    event_data = event.find(f"./{prefix}EventData", ns)
    if event_data is not None:
        # List of all fields we want to extract
        target_fields = {
            "SourceProcessId", "SourceImage", "Image", "OriginalFileName",
            "ImageLoaded", "TargetProcessId", "TargetImage", "TargetFilename",
            "CallTrace", "EventType", "TargetObject", "SourceIp", "SourcePort",
            "DestinationIp", "DestinationPort", "SourcePortName", 
            "DestinationPortName", "CurrentDirectory", "ParentProcessId",
            "ParentImage", "NewProcessName", "ParentProcessName", "ProcessName"
        }

        for data in event_data.findall(f"{prefix}Data", ns):
            field_name = data.attrib.get("Name")
            if field_name in target_fields:
                value = data.text.strip() if data.text else None
                if value:
                    features[field_name] = value

    return features if len(features) > 1 else {}

def extract_sysmon_features(file_path: str, label: str) -> List[Dict[str, str]]:
    """Extract Sysmon features from a .log or .xml file"""
    features_list = []

    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()

    if "<Event" in content:  # Likely XML content
        entries = content.strip().split("</Event>")
        for entry in entries:
            entry = entry.strip()
            if not entry:
                continue
            entry += "</Event>" if not entry.endswith("</Event>") else ""
            features = parse_xml_event(entry, label)
            if features:
                features_list.append(features)
    else:
        # Fallback to plaintext regex extraction
        for line in content.splitlines():
            if not line.strip():
                continue
            features = {
                "label": label,
                "EventID": None,
                "SourceProcessId": None,
                "ProcessId": None,
                "SourceImage": None,
                "Image": None,
                "OriginalFileName": None,
                "ImageLoaded": None,
                "TargetProcessId": None,
                "TargetImage": None,
                "TargetFilename": None,
                "CallTrace": None,
                "EventType": None,
                "TargetObject": None,
                "SourceIp": None,
                "SourcePort": None,
                "DestinationIp": None,
                "DestinationPort": None,
                "SourcePortName": None,
                "DestinationPortName": None,
                "CurrentDirectory": None,
                "ParentProcessId": None,
                "ParentImage": None,
                "NewProcessName": None,
                "ParentProcessName": None,
                "ProcessName": None
            }

            # Extract EventID
            event_id_match = re.search(r'EventID[=:]["\']?(\d+)', line)
            if event_id_match:
                features["EventID"] = int(event_id_match.group(1))

            # Field patterns
            field_patterns = {
                "SourceProcessId": r'SourceProcessId[=:]["\']?([^"\'\s]+)',
                "ProcessId": r'ProcessId[=:]["\']?([^"\'\s]+)',
                "Image": r'Image[=:]["\']?([^"\']+)',
                "SourceImage": r'SourceImage[=:]["\']?([^"\']+)',
                "OriginalFileName": r'OriginalFileName[=:]["\']?([^"\']+)',
                "ImageLoaded": r'ImageLoaded[=:]["\']?([^"\']+)',
                "TargetProcessId": r'TargetProcessId[=:]["\']?([^"\'\s]+)',
                "TargetImage": r'TargetImage[=:]["\']?([^"\']+)',
                "TargetFilename": r'TargetFilename[=:]["\']?([^"\']+)',
                "CallTrace": r'CallTrace[=:]["\']?([^"\']+)',
                "EventType": r'EventType[=:]["\']?([^"\']+)',
                "TargetObject": r'TargetObject[=:]["\']?([^"\']+)',
                "SourceIp": r'SourceIp[=:]["\']?([^"\'\s,;]+)',
                "SourcePort": r'SourcePort[=:]["\']?(\d+)',
                "DestinationIp": r'DestinationIp[=:]["\']?([^"\'\s,;]+)',
                "DestinationPort": r'DestinationPort[=:]["\']?(\d+)',
                "SourcePortName": r'SourcePortName[=:]["\']?([^"\']+)',
                "DestinationPortName": r'DestinationPortName[=:]["\']?([^"\']+)',
                "CurrentDirectory": r'CurrentDirectory[=:]["\']?([^"\']+)',
                "ParentProcessId": r'ParentProcessId[=:]["\']?([^"\'\s]+)',
                "ParentImage": r'ParentImage[=:]["\']?([^"\']+)',
                "NewProcessName": r'NewProcessName[=:]["\']?([^"\']+)',
                "ParentProcessName": r'ParentProcessName[=:]["\']?([^"\']+)',
                "ProcessName": r'ProcessName[=:]["\']?([^"\']+)'
            }

            for field, pattern in field_patterns.items():
                match = re.search(pattern, line)
                if match:
                    features[field] = match.group(1).strip('"\'')
            
            # Clean up None values
            features = {k: v for k, v in features.items() if v is not None}
            if features:
                features_list.append(features)

    return features_list

def get_label_from_path(file_path: str, input_dir: str) -> str:
    """Extract label from the grandparent folder of 'Sysmon'"""
    rel_path = os.path.relpath(file_path, input_dir)
    path_parts = rel_path.split(os.sep)
    
    try:
        sysmon_index = path_parts.index("Sysmon")
        if sysmon_index > 0:
            return path_parts[sysmon_index - 1]
    except ValueError:
        pass
    return "unknown"

def process_sysmon_logs(input_dir: str, output_file: str):
    """Process all Sysmon logs and write them to JSON"""
    all_events = []

    for root, _, files in os.walk(input_dir):
        if "Sysmon" not in os.path.normpath(root).split(os.sep):
            continue

        for filename in files:
            if filename.lower().endswith((".log", ".xml")):
                file_path = os.path.join(root, filename)
                label = get_label_from_path(file_path, input_dir)
                try:
                    events = extract_sysmon_features(file_path, label)
                    all_events.extend(events)
                    print(f"Processed {len(events)} events from {file_path}")
                except Exception as e:
                    print(f"Error processing {file_path}: {str(e)}", file=sys.stderr)

    # Save to output JSON
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(all_events, f, separators=(',', ':'))
    print(f"\n✅ Successfully saved {len(all_events)} events to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python sysmon_parser.py <input_directory> <output_file.json>", file=sys.stderr)
        sys.exit(1)

    input_dir = sys.argv[1]
    output_file = sys.argv[2]
    process_sysmon_logs(input_dir, output_file)
