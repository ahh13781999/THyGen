import ipaddress
import json
import os
from pathlib import Path
import re
from typing import Dict, List

# Sysmon EventID to Description Mapping
EVENT_ID_MEANINGS = {
    # --- Sysmon Events (Core) ---
    1: "process creation",
    2: "file creation time changed",
    3: "network connection",
    4: "Sysmon service state change",
    5: "process terminated",
    6: "driver loaded",
    7: "image loaded",
    8: "create remote thread",
    9: "raw access read",
    10: "process access",
    11: "file created",
    12: "registry object added or deleted",
    13: "registry value set",
    14: "registry object renamed",
    15: "file stream created",
    16: "Sysmon config state changed",
    17: "pipe created",
    18: "pipe connected",
    19: "WMI event filter activity",
    20: "WMI consumer activity",
    21: "WMI consumer filter binding",
    22: "DNS query",
    23: "file delete",
    24: "clipboard change",
    25: "process tampering",
    26: "file delete detected",
    27: "file block executable",
    255: "Sysmon error",

    # --- Windows Security Events ---
    4624: "Successful logon",
    4625: "failed logon",
    4627: "account lockout",
    4634: "logoff",
    4648: "logon with explicit credentials",
    4657: "registry value modified",
    4662: "object access attempt",
    4672: "Admin privilege assigned",
    4688: "new process created",
    4698: "scheduled task created",
    4702: "scheduled task modified",
    4719: "system audit policy changed",
    4720: "user account created",
    4768: "Kerberos TGT request",
    4769: "Kerberos service ticket requested",
    4776: "NTLM authentication attempt",
    5140: "network share accessed",
    1102: "security log cleared",

    # --- System/Application Logs ---
    1000: "application crash",
    1001: "Windows error reporting",
    1002: "application hang",
    1003: "system error",
    1006: "driver load failure",
    1007: "windows defender scan completed",
    1040: "DNS client events",
    1074: "system shutdown initiated",
    6005: "event log started",
    6006: "event log stopped",
    7036: "service state change",
    7045: "new service installed",

    # --- PowerShell & Scripting ---
    400: "PowerShell session started",
    403: "PowerShell session Terminated",
    4100: "PowerShell script block logging",
    4103: "PowerShell script block logging",
    4104: "PowerShell script block logging",
    4105: "PowerShell remoting session started",
    4106: "PowerShell remoting session stopped",

    # --- Windows Defender & Antivirus ---
    5001: "windows defender threat detected",
    5007: "windows defender configuration changed",
    5010: "windows defender scan started",
    5012: "windows defender threat action taken",

    # --- Active Directory (AD) ---
    4726: "user account deleted",
    4732: "Group membership changed",
    4738: "user account changed",
    4740: "locked Out user account",
    4767: "AD user account unlocked",

    # --- Special Cases (Grouped Ranges) ---
    # PowerShell (4000-4106)
    **{id: "PowerShell logging" for id in range(4000, 4099)},

    # Windows Defender (5000-5012)
    **{id: "windows defender event" for id in range(5000, 5013)},

    # Firewall (5150-5169)
    **{id: "windows firewall event" for id in range(5150, 5170)},

    # Certificate Services (10000-10099)
    **{id: "certificate services event" for id in range(10000, 10100)},

    # Third-party/App-Specific (20000+)
    **{id: "third-party application event" for id in range(20000, 30000)},
}


def get_event_description(event_id: str) -> str:
    """Get human-readable description for EventID"""
    try:
        return EVENT_ID_MEANINGS.get(int(event_id), f"Event ID {event_id}")
    except ValueError:
        return f"Event ID {event_id}"


def extract_filename(filepath: str) -> str:
    """
    Extracts the filename from a full file path, handling all edge cases.

    Args:
        filepath: The full path to the file (Windows or Unix format)

    Returns:
        The filename with extension, or empty string if invalid path

   """
    try:
        # Using pathlib for cross-platform compatibility
        path_obj = Path(filepath)

        # Handle cases like "file.txt" (no path) and "C:\file.txt" (with path)
        if path_obj.name:  # Standard file case
            return path_obj.name
        elif path_obj.parent and str(path_obj).endswith(os.sep):
            # Handle directory paths ending with separator
            return ''
        else:
            # Fallback for edge cases
            return os.path.basename(filepath) or ''
    except (TypeError, AttributeError):
        return ''


def clean_sysmon_value(value: str) -> str | None:
    if value is None or value.strip() == "" or value.strip() == "-":
        return None
    return value.strip().replace(",", "")

def clean_and_validate_ip(address: str) -> str | None:
    if not address or address.strip() in ("", "-"):
        return None
    
    cleaned_ip = address.strip()  # Remove leading/trailing whitespace
    
    try:
        # Try parsing as IPv4 or IPv6
        ip_obj = ipaddress.ip_address(cleaned_ip)
        return str(ip_obj)  # Return standardized format
    except ValueError:
        return None  # Invalid IP

def pascal_to_normal(name: str) -> str:
    """
    Converts a PascalCase (or CamelCase) string into a spaced lowercase string.
    """
    # Insert spaces before capital letters (except the first letter)
    spaced = re.sub(r'(?<!^)(?=[A-Z])', ' ', name)
    # Convert to lowercase and strip extra whitespace
    return spaced.lower().strip()


def has_sufficient_features(features: Dict[str, str]) -> bool:
    """Check if event has at least 4 non-label features"""
    return len([v for k, v in features.items() if v and k != "label"]) >= 4


def calltrace_to_csv(calltrace, label=None):
    if not calltrace or calltrace.strip() == "":
        return "Empty CallTrace" + (f" (Label: {label})" if label else "")

    # Extract and normalize module names (case-insensitive, no paths/extensions)
    entries = []
    for entry in calltrace.split('|'):
        module = entry.split('\\')[-1].split('+')[0]  # Get 'module.dll'
        # Get 'module' (no extension)
        module = module.split('.')[0].lower()
        entries.append(module)

    if not entries:
        return "Empty CallTrace" + (f" (Label: {label})" if label else "")

    # Group consecutive modules and count repetitions
    grouped = []
    current_module = entries[0]
    count = 1
    for module in entries[1:]:
        if module == current_module:
            count += 1
        else:
            grouped.append((current_module, count))
            current_module = module
            count = 1
    grouped.append((current_module, count))

    # Build natural language description
    parts = []
    for i, (module, count) in enumerate(grouped):
        if i == 0:
            parts.append(f"started in {module}")
        elif i == len(grouped) - 1:
            parts.append(f"ended in {module}")
        else:
            if count == 1:
                parts.append(f"called {module}")
            else:
                parts.append(f"called {module} {count} times")

    # Combine into Comma Separated Values
    line = "process " + ", ".join(parts) + "."

    # Append label if provided
    if label:
        line += f" (Label: {label})"

    return line


def feature_to_csv(features: Dict[str, str]) -> str:
    """Convert features to human-readable Comma Sepatated Values with EventID meanings"""
    if not has_sufficient_features(features):
        return None  # Skip events with insufficient features

    sections = []

    # 1. Event Type and Process
    event_desc = get_event_description(features.get("EventID", ""))
    if (event_desc):
        sections.append(f"event_type='{event_desc}'")

    proc_info = []
    if "ProcessId" in features:
        proc_info.append(f"pid='{features['ProcessId']}'")
        
    if "ProcessName" in features or "NewProcessName" in features:
        process_name = features.get(
            "NewProcessName") or features.get("ProcessName")
        process_name_1 = extract_filename(process_name)
        process_name_1_filtered = clean_sysmon_value(process_name_1)
        proc_info.append(f"process='{process_name_1_filtered}'")
    elif "Image" in features or "TargetImage" in features:
        process_name = features.get("Image") or features.get("TargetImage")
        process_name_2 = extract_filename(process_name)
        process_name_2_filtered = clean_sysmon_value(process_name_2)
        proc_info.append(f"process='{process_name_2_filtered}'")


    if proc_info:
        sections.append(', '.join(proc_info))
    else:
        sections.append(event_desc)

    # 2. Parent Process
    if "SourceProcessId" in features or "SourceImage" in features or "ParentProcessId" in features or "ParentImage" in features:
        parent_info = []
        if "SourceProcessId" in features or "ParentProcessId" in features:
            parent_id = features.get(
                "SourceProcessId") or features.get("ParentProcessId")
            parent_info.append(f"ppid='{parent_id}'")
        if "SourceImage" in features or "ParentImage" in features:
            parent_name = features.get(
                "SourceImage") or features.get("ParentImage")
            parent_process = extract_filename(parent_name)
            parent_process_filtered = clean_sysmon_value(parent_process)
            parent_info.append(f"parent_process='{parent_process_filtered}'")
        sections.append(', '.join(parent_info))

    # 3. File Path Information
    if "ImageLoaded" in features or "TargetObject" in features or "CurrentDirectory" in features:
        file_path = []
        if "ImageLoaded" in features or "CurrentDirectory" in features:
            file_location = features.get(
                "ImageLoaded") or features.get("CurrentDirectory")
            file_location_filtered = clean_sysmon_value(file_location)
            file_path.append(f"process_directory='{file_location_filtered}'")
        if "TargetObject" in features:
            registry_path_filtered = clean_sysmon_value(features['TargetObject'])
            file_path.append(
                f"registry_path='{registry_path_filtered}'")
        if file_path:
            sections.append(", ".join(file_path))

    # 4. Network Activity
    if all(f in features for f in ["SourceIp", "DestinationIp"]):
        source_ip_filtered = clean_and_validate_ip(features['SourceIp'])
        net_str = f"source_ip='{source_ip_filtered}'"
        if "SourcePort" in features:
            net_str += f", source_port='{features['SourcePort']}'"
            if "SourcePortName" in features:
                source_port_name = clean_sysmon_value(
                    features['SourcePortName'])
                if(source_port_name):
                   net_str += f", source_port_name='{source_port_name}'"
        dest_ip_filtered = clean_and_validate_ip(features['DestinationIp'])
        net_str += f", destination_ip='{dest_ip_filtered}'"
        if "DestinationPort" in features:
            net_str += f", destination_port='{features['DestinationPort']}'"
            if "DestinationPortName" in features:
                dest_port_name = clean_sysmon_value(
                    features['DestinationPortName'])
                if(dest_port_name):
                  net_str += f", destination_port_name='{dest_port_name}'"
        sections.append(net_str)

    # 5. Original File Name
    if "OriginalFileName" in features or "TargetFilename" in features:
        unfiltered_file_name = features.get(
            "OriginalFileName") or features.get("TargetFilename")
        filtered_file_name = clean_sysmon_value(unfiltered_file_name)
        if (filtered_file_name):
            file_name = "file_name="
            file_name += f"'{filtered_file_name}'"
            sections.append(file_name)

    # 6. Technical Details
    tech = []
    '''
    if "CallTrace" in features:
        call_trace = calltrace_to_csv(features['CallTrace'])
        tech.append(f"call_trace='{call_trace}'")
    '''
    if "EventType" in features:
        event_type = pascal_to_normal(features['EventType'])
        event_type_filtered = clean_sysmon_value(event_type)
        tech.append(f"operation_type='{event_type_filtered}'")
    if tech:
        sections.append(", ".join(tech))

    # 7. Classification
    if "label" in features:
        sections.append(f"mitre_tactic='{features['label']}'")

    # Construct Final Line
    line = ", ".join(s for s in sections if s)

    # Clean up grammar
    line = line.replace("..", ".").replace(",.", ".")
    return line


def generate_csvs(input_file: str, output_file: str):
    """Generate human-readable csv from Sysmon events"""
    with open(input_file, 'r', encoding='utf-8') as f:
        events = json.load(f)

    results = []  # for json output

    with open(output_file, 'w', encoding='utf-8') as f:
        for event in events:
            line = feature_to_csv(event)
            if line:
                f.write(line + '\n')
                results.append({
                    "text": line,
                    "metadata": event,
                    "length": len(line),
                    "event_type": get_event_description(event.get("EventID", "")),
                    "feature_count": len([v for k, v in event.items() if v and k != "label"])
                })
    with open("results.json", 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    print(f"Generated {len(results)} enhanced csv with EventID meanings")


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python script.py <input_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    try:
        generate_csvs(input_file, output_file)
        print(f"Successfully created {output_file}")
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)
