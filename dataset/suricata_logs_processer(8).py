import csv
import sys
import re
from pathlib import Path

# Field categorization
DNS_KEYS = {'queried_domain', 'resolved_ip'}
HTTP_KEYS = {
    'http_method', 'source_ip', 'source_port', 'destination_ip',
    'destination_port', 'url_path', 'post_data', 'response_code',
    'host_domain', 'referrer', 'redirect_location', 'object_access_type',
    'object_name'
}

def clean_value(value):
    """Remove all quotes and commas from values"""
    if not isinstance(value, str):
        value = str(value)
    # Remove all quotes and commas
    value = value.replace('"', '').replace("'", "").replace(",", "")
    # Remove leading/trailing whitespace
    return value.strip()

def is_valid_ip(ip_str):
    """Validate IPv4 address format"""
    pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return re.match(pattern, ip_str) is not None

def pascal_to_snake(name):
    """Convert PascalCase to snake_case with acronym handling"""
    if not name:
        return ''
    name = re.sub(r'(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])', '_', name)
    return name.lower()

def process_row(row):
    components = {}
    
    for key in row:
        if key in (None, 'Timestamp'):
            continue
            
        value = clean_value(row[key])
        if not value:
            continue
            
        if key == 'Label':
            components['mitre_tactic'] = value
            continue
            
        snake_key = pascal_to_snake(key)
        
        # Validate resolved_ip format
        if snake_key == 'resolved_ip' and not is_valid_ip(value):
            continue
            
        components[snake_key] = value
    
    # Check minimum non-label fields
    non_label = [k for k in components if k != 'mitre_tactic']
    if len(non_label) < 2:
        return None
    
    # Determine categories
    has_dns = any(k in DNS_KEYS for k in non_label)
    has_http = any(k in HTTP_KEYS for k in non_label)
    
    # Format output with all values in single quotes
    formatted = []
    for k, v in components.items():
        formatted.append(f"{k}='{v}'")
    
    return {'formatted': formatted, 'dns': has_dns, 'http': has_http}

def main():
    input_source = sys.argv[1] if len(sys.argv) > 1 else sys.stdin
    
    with open('dns.csv', 'w') as dns_file, open('http.csv', 'w') as http_file:
        # Input handling
        if isinstance(input_source, str):
            with open(input_source, 'r') as f_in:
                reader = csv.DictReader(f_in)
                for row in reader:
                    result = process_row(row)
                    if result:
                        line = ', '.join(result['formatted'])
                        if result['dns']:
                            dns_file.write(f"{line}\n")
                        if result['http']:
                            http_file.write(f"{line}\n")
        else:
            # Read from stdin
            reader = csv.DictReader(sys.stdin)
            for row in reader:
                result = process_row(row)
                if result:
                    line = ', '.join(result['formatted'])
                    if result['dns']:
                        dns_file.write(f"{line}\n")
                    if result['http']:
                        http_file.write(f"{line}\n")

    print("Processing complete. Output saved to:")
    print("- dns.csv (DNS-related events)")
    print("- http.csv (HTTP-related events)")

if __name__ == "__main__":
    main()