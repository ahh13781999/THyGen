import os
import xml.etree.ElementTree as ET
from collections import defaultdict
import json
import re

def analyze_sysmon_logs(root_directory):
    # Initialize data structures
    data_name_frequency = defaultdict(int)
    event_id_frequency = defaultdict(int)
    total_events = 0
    files_processed = 0
    sysmon_folders_found = 0

    # Walk through the directory structure
    for root, dirs, files in os.walk(root_directory):
        if os.path.basename(root).lower() == 'sysmon':
            sysmon_folders_found += 1
            print(f"Found Sysmon folder: {root}")
            
            for file in files:
                if file.lower().endswith(('.log', '.json')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                            # Handle both Windows and Linux Sysmon formats
                            events = []
                            pattern = re.compile(r'<Event[^>]*>.*?</Event>', re.DOTALL)
                            events_xml = pattern.findall(content)
                            
                            for event_xml in events_xml:
                                try:
                                    # Clean XML and handle namespaces
                                    event_xml_clean = event_xml.replace('UserId=', 'UserID=')  # Normalize attribute
                                    
                                    # Parse the event
                                    event = ET.fromstring(event_xml_clean)
                                    total_events += 1
                                    
                                    # Get EventID (handle both Windows and Linux formats)
                                    event_id = event.find('.//EventID')
                                    if event_id is None:
                                        event_id = event.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventID')
                                    if event_id is not None and event_id.text:
                                        event_id_text = event_id.text.strip()
                                        event_id_frequency[event_id_text] += 1
                                    
                                    # Count all Data Name attributes (handle both formats)
                                    event_data = event.find('.//EventData')
                                    if event_data is None:
                                        event_data = event.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventData')
                                    
                                    if event_data is not None:
                                        for data in event_data.findall('.//Data'):
                                            if 'Name' in data.attrib:
                                                data_name_frequency[data.attrib['Name']] += 1
                                            # Also check with namespace
                                            elif '{http://schemas.microsoft.com/win/2004/08/events/event}Name' in data.attrib:
                                                data_name_frequency[data.attrib['{http://schemas.microsoft.com/win/2004/08/events/event}Name']] += 1
                                except ET.ParseError as e:
                                    print(f"    Error parsing event in {file}: {e}")
                        
                        files_processed += 1
                        print(f"  Processed: {file} ({len(events_xml)} events)")
                    except Exception as e:
                        print(f"  Error processing {file}: {e}")

    # Prepare results
    results = {
        'sysmon_folders_found': sysmon_folders_found,
        'files_processed': files_processed,
        'total_events_processed': total_events,
        'data_name_frequency': dict(sorted(data_name_frequency.items(), key=lambda item: item[1], reverse=True)),
        'event_id_frequency': dict(sorted(event_id_frequency.items(), key=lambda item: item[1], reverse=True))
    }
    
    return results

def save_results(results, output_file='sysmon_analysis.json'):
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"\nResults saved to {output_file}")

def print_frequency_table(title, frequency_dict):
    print(f"\n{title}:")
    print("-" * 50)
    print("{:<30} {:<10}".format("Item", "Count"))
    print("-" * 50)
    for key, count in frequency_dict.items():
        print("{:<30} {:<10}".format(key, count))
    print("-" * 50)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python analyze_sysmon.py <root_directory> [output_file]")
        sys.exit(1)
    
    root_dir = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'sysmon_analysis.json'
    
    print(f"Searching for Sysmon folders in {root_dir}...")
    results = analyze_sysmon_logs(root_dir)
    save_results(results, output_file)
    
    # Print detailed reports
    print("\n=== Analysis Summary ===")
    print(f"Sysmon folders found: {results['sysmon_folders_found']}")
    print(f"Files processed: {results['files_processed']}")
    print(f"Total events analyzed: {results['total_events_processed']}")
    
    print_frequency_table("Data Name Frequency", results['data_name_frequency'])
    print_frequency_table("Event ID Frequency", results['event_id_frequency'])