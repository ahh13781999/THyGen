import os
import json
import argparse
import re
import logging
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def clean_value(value: str) -> str:
    """Clean and sanitize values by removing problematic characters"""
    if not isinstance(value, str):
        value = str(value)
    
    # Remove problematic characters that could break the output format
    value = value.replace('"', '').replace("'", "").replace(",", "")
    return value.strip()

def is_valid_ip(ip_str: str) -> bool:
    """Validate IPv4 address format"""
    if not ip_str:
        return False
        
    pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return re.match(pattern, ip_str) is not None

def get_label(file_path: str) -> str:
    """Get the grandparent folder name as label"""
    try:
        path_parts = os.path.normpath(file_path).split(os.sep)
        if len(path_parts) >= 3:
            return path_parts[-3]
    except Exception as e:
        logger.error(f"Error extracting label from {file_path}: {str(e)}")
    return "unknown"

def extract_fields(log_entry: Dict, file_path: str) -> Optional[Tuple[str, Dict]]:
    """Extract fields based on event_type - processes dns, http, fileinfo events"""
    event_type = log_entry.get('event_type', '').lower()
    
    # Skip unsupported event types
    if event_type not in {'dns', 'http', 'fileinfo'}:
        return None
    
    label = get_label(file_path)
    
    # Initialize all fields with empty strings
    fields = {
        'queried_domain': '',
        'resolved_ip': '',
        'source_ip': '',
        'source_port': '',
        'destination_ip': '',
        'destination_port': '',
        'http_method': '',
        'url_path': '',
        'response_code': '',
        'host_domain': '',
        'redirect_location': '',
        'mitre_tactic': label
    }

    try:
        if event_type == 'dns':
            dns_data = log_entry.get('dns', {})
            fields['queried_domain'] = dns_data.get('rrname', '')
            
            # Handle multiple answers
            answers = dns_data.get('answers', [])
            if answers:
                first_answer = answers[0]
                rdata = first_answer.get('rdata', '')
                # Only use if it's an IP address
                if is_valid_ip(rdata):
                    fields['resolved_ip'] = rdata
        else:
            # Handle http/fileinfo events
            http_data = log_entry.get('http', {})
            fields['source_ip'] = log_entry.get('src_ip', '')
            fields['source_port'] = str(log_entry.get('src_port', ''))
            fields['destination_ip'] = log_entry.get('dest_ip', '')
            fields['destination_port'] = str(log_entry.get('dest_port', ''))
            fields['http_method'] = http_data.get('http_method', '')
            fields['url_path'] = http_data.get('url', '')
            fields['response_code'] = str(http_data.get('status', ''))
            fields['host_domain'] = http_data.get('hostname', '')
            fields['redirect_location'] = http_data.get('redirect', '')
    except Exception as e:
        logger.error(f"Error extracting fields: {str(e)}")
        return None
    
    # Return both event type and fields
    return (event_type, fields)

def process_suricata_log(file_path: str) -> List[Tuple[str, Dict]]:
    """Process a single Suricata log file"""
    events = []
    line_number = 0
    
    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line_number += 1
                line = line.strip()
                if not line:
                    continue
                    
                try:
                    log_entry = json.loads(line)
                    result = extract_fields(log_entry, file_path)
                    if result:
                        events.append(result)
                except json.JSONDecodeError:
                    logger.warning(f"JSON decode error at line {line_number} in {file_path}")
                except Exception as e:
                    logger.error(f"Error processing line {line_number} in {file_path}: {str(e)}")
    except Exception as e:
        logger.error(f"Error opening {file_path}: {str(e)}")
    
    return events

def find_and_process_suricata_logs(input_dir: str) -> Tuple[List[Tuple[str, Dict]], int, int]:
    """Recursively find and process all Suricata flow logs"""
    all_events = []
    processed_files = 0
    skipped_files = 0
    
    try:
        for root, _, files in os.walk(input_dir):
            if 'Suricata_Flow' not in root.split(os.sep):
                continue
                
            for file in files:
                if not file.lower().endswith(('.json', '.log')):
                    skipped_files += 1
                    continue
                    
                file_path = os.path.join(root, file)
                try:
                    logger.info(f"Processing {file_path}")
                    file_events = process_suricata_log(file_path)
                    all_events.extend(file_events)
                    processed_files += 1
                except Exception as e:
                    logger.error(f"Error processing {file_path}: {str(e)}")
    except Exception as e:
        logger.error(f"Error walking directory {input_dir}: {str(e)}")
    
    logger.info(f"Processed {processed_files} files, skipped {skipped_files} non-log files")
    return all_events, processed_files, skipped_files

def write_events_to_file(events: List[Dict], output_path: str, field_order: List[str]) -> Dict:
    """Write events to file in key-value format and return statistics"""
    stats = defaultdict(int)
    output_dir = os.path.dirname(output_path) or '.'
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            for event in events:
                # Create key-value pairs for each field
                kv_pairs = []
                valid_pairs = 0
                
                for field in field_order:
                    value = event.get(field, '')
                    
                    # Skip invalid IPs
                    if field.endswith('_ip') and value and not is_valid_ip(value):
                        continue
                        
                    # Clean and validate
                    cleaned_value = clean_value(value)
                    if not cleaned_value:
                        continue
                    
                    kv_pairs.append(f'{field}="{cleaned_value}"')
                    valid_pairs += 1
                
                # Only write if we have at least 3 valid key-value pairs
                if valid_pairs >= 3:
                    # Join all key-value pairs with comma separator
                    line = ', '.join(kv_pairs)
                    f.write(line + '\n')
                    stats['events_written'] += 1
                else:
                    stats['events_skipped_insufficient_fields'] += 1
        
        logger.info(f"Successfully wrote {stats['events_written']} events to {output_path}")
        if stats['events_skipped_insufficient_fields']:
            logger.info(f"Skipped {stats['events_skipped_insufficient_fields']} events with insufficient fields")
    except Exception as e:
        logger.error(f"Error writing to {output_path}: {str(e)}")
    
    return stats

def main():
    parser = argparse.ArgumentParser(description='Process Suricata flow logs')
    parser.add_argument('-i', '--input', required=True, help='Input directory containing Suricata_Flow folders')
    parser.add_argument('-o', '--output', required=True, help='Output base path for files (without extension)')
    
    args = parser.parse_args()

    # Process all logs
    events, processed_files, skipped_files = find_and_process_suricata_logs(args.input)
    
    if not events:
        logger.warning("No events found or processed.")
        return
    
    # Define the field order
    field_order = [
        'queried_domain',
        'resolved_ip',
        'source_ip',
        'source_port',
        'destination_ip',
        'destination_port',
        'http_method',
        'url_path',
        'response_code',
        'host_domain',
        'redirect_location',
        'mitre_tactic'
    ]
    
    # Separate events by type
    dns_events = []
    http_events = []
    
    for event_type, event_fields in events:
        if event_type == 'dns':
            dns_events.append(event_fields)
        else:  # http or fileinfo
            http_events.append(event_fields)
    
    # Write DNS events to separate file
    dns_stats = {}
    if dns_events:
        dns_output = args.output + '_dns.txt'
        dns_stats = write_events_to_file(dns_events, dns_output, field_order)
    else:
        logger.warning("No DNS events found")
    
    # Write HTTP events to separate file
    http_stats = {}
    if http_events:
        http_output = args.output + '_http.txt'
        http_stats = write_events_to_file(http_events, http_output, field_order)
    else:
        logger.warning("No HTTP events found")
    
    # Final summary
    logger.info("\n=== Processing Summary ===")
    logger.info(f"Files processed: {processed_files}")
    logger.info(f"Files skipped: {skipped_files}")
    logger.info(f"Total events processed: {len(events)}")
    logger.info(f"DNS events: {len(dns_events)}")
    logger.info(f"HTTP events: {len(http_events)}")
    
    # Calculate total events written
    total_written = 0
    total_skipped = 0
    
    if dns_stats:
        dns_written = dns_stats.get('events_written', 0)
        dns_skipped = dns_stats.get('events_skipped_insufficient_fields', 0)
        logger.info(f"DNS events written: {dns_written}")
        logger.info(f"DNS events skipped (insufficient fields): {dns_skipped}")
        total_written += dns_written
        total_skipped += dns_skipped
    
    if http_stats:
        http_written = http_stats.get('events_written', 0)
        http_skipped = http_stats.get('events_skipped_insufficient_fields', 0)
        logger.info(f"HTTP events written: {http_written}")
        logger.info(f"HTTP events skipped (insufficient fields): {http_skipped}")
        total_written += http_written
        total_skipped += http_skipped
    
    logger.info(f"Total events written: {total_written}")
    logger.info(f"Total events skipped (insufficient fields): {total_skipped}")
    logger.info(f"Total events filtered: {len(events) - total_written - total_skipped}")

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logger.exception("Unhandled exception in main program")