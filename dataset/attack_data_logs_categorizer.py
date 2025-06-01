import os
import re
import shutil
from pathlib import Path

# Filename patterns (case-insensitive)
FILENAME_PATTERNS = {
    "M365_Security": [r"o365", r"m365", r"security_compliance"],
    "Windows_Security": [r"winevent"],
    "Exchange_Transport": [r"exchange", r"transportrule", r"mailflow"],
    "Sysmon": [r"sysmon"],
    "AWS_CloudTrail": [r"aws", r"cloudtrail"],
    "Azure_AD": [r"azure", r"azuread", r"aad"],
    "Splunk_Audit": [r"splunk", r"audittrail"],
    "EDR": [r"edr", r"endpoint", r"process_termination"],
    "ZNK": [r"znk", r"zeek", r"bro", r"conn\.log"],
    "PaloAlto": [r"palo", r"pan"],
    "Okta": [r"okta", r"iam", r"mfa_log"],
    "Google_Workspace": [r"google", r"gws"],
    "CrowdStrike": [r"crowdstrike", r"falcon", r"processrollup"],
    "Web_Server_Access_Log": [r"kubernetes", r"nginx", r"apache"],
    "Network_Traffic": [
        r"(stream.*dns|dns.*stream)", 
        r"(stream.*http|http.*stream)",
    ],
    "CI_CD": [r"circle_ci"],
    "Suricata_Flow": [r"suricata", r"flowlog", r"eve\.json"],
    "SIEM_Entity": [r"ssa"],
    "Splunk_ESCU": [r"esc[u-]", r"splunk_alert", r"post_exploitation"],
    "Windows_DC_Test": [
        r"attack-range-windows-domain-controller",  
        r"win-dc-.*\.json",  
        r"attackrange\.local",  
    ],
    "MFA_PingID": [r"pingid", r"mfa_auth", r"auth_fail"],
    "Splunk_SVD": [
        r"svd",
        r"svd-\d{4}-\d{3}\.log",
        r"splunk_validated",
        r"_svd_log",
    ],
    "Windows_SIP": [
        r"sip_inventory",  
        r"sip_\w+\.log",  
        r"windows_integrity_log",
    ],
    "IIS_Backdoor_Activity": [
        r"pwsh_installediismodules", 
        r"iis_.*backdoor",  
        r"webshell_install",  
    ],
    "Magento_Access": [
        r"magento_access",  
        r"magento.*\.log",  
        r"static_requests",
    ],
    "AttackSim_DNS": [
        r"attack_data.*dns", 
        r"phishnet.*\.json", 
        r"stream_dns_log",  
    ],
    "Java_AppServer": [
        r"server\.log",  
        r"appserver_debug",
        r"hibernate_.*log",  
    ],
}

# Content patterns (checked if filename doesn't match)
CONTENT_PATTERNS = {
    "M365_Security": [
        r'"Workload":\s*"SecurityComplianceCenter"',
        r'"Source":\s*"Office 365 Security & Compliance"',
    ],
    "Windows_Security": [
        r"LogName=(Security|Microsoft-Windows-PowerShell|System)",
        r"SourceName=Microsoft Windows security auditing\.",
        r"EventCode=\d+",
    ],
    "Exchange_Transport": [
        r'"Workload":\s*"Exchange"',
        r'"Operation":\s*"Set-TransportRule"',
        r'"DeleteMessage":\s*"True"',
    ],
    "EDR": [
        r'"type":\s*"endpoint\.event\.procend"',
        r'"event_origin":\s*"EDR"',
        r"certutil\s+-urlcache",
        r'process_path":\s*".*\\powershell\.exe"',
    ],
    "ZNK": [
        r'"ts":\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',
        r'"id\.orig_h":\s*"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"',
        r'"proto":\s*"(tcp|udp|icmp)"',
    ],
    "PaloAlto": [
        r"^\d+ <\d+>1 \d{4}-\d{2}-\d{2}T",
        r",THREAT,url,",
        r",vsys\d+,Trust,Untrust,",
    ],
    "AWS_CloudTrail": [r'"eventSource":\s*"s3\.amazonaws\.com"', r"AwsApiCall"],
    "Azure_AD": [
        r'"Workload":\s*"AzureActiveDirectory"',
        r"AzureActiveDirectoryEventType",
    ],
    "Okta": [
        r'"eventType":\s*"user\.mfa\.factor\.',
        r'"legacyEventType":\s*"core\.user\.factor\.',
        r'debugData":\s*{.*"requestUri":\s*"/api/v1/',
    ],
    "Google_Workspace": [
        r'"kind":\s*"admin#reports#activity"',
        r'"applicationName":\s*"login"',
        r'"event":\s*{.*"type":\s*"login"',
    ],
    "CrowdStrike": [
        r'"event_simpleName":\s*"ProcessRollup',
        r'"aid":\s*"[a-f0-9]{32}"',
        r'"cid":\s*"[a-f0-9]{32}"',
    ],
    "Web_Server_Access": [
        r'\d+\.\d+\.\d+\.\d+\s+-\s+-\s+\[.*\]\s+"(GET|POST|PUT|DELETE)',
        r'HTTP/\d\.\d"\s+\d{3}\s+\d+',
        r'"Mozilla/.*"\s+\d+\s+\d+\.\d{3}',
        r"\.\./\.\./\.\./",  # Path traversal
        r"(etc/passwd|win.ini|\.env)",
        r"(\bunion\b\s+select|sleep\(\d+\))",  # SQLi
    ],
    "Network_Traffic": [
        r'"sum\(bytes\)":\s*\d+',
        r'"app":\s*"(ssl|http|dns)"',
        r'"initial_rtt":\s*\d+',
    ],
    "CI_CD": [
        r'"build_url":\s*"https?://circleci\.com',
        r'"workflows":\s*{.*"job_name":',
        r'"reponame":\s*".+?",\s*"build_num":',
    ],
    "Suricata_Flow": [
        r'"flow_id":\s*\d{16,}',  # 16+ digit flow IDs
        r'"event_type":\s*"flow"',
        r"\\Device\\NPF_{[A-F0-9-]+}",  # Windows NPcap interface
        r'"pkts_toserver":\s*\d+.*"pkts_toclient":\s*\d+',
    ],
    "SIEM_Entity": [
        r'"_tenant":\s*".+?"',
        r'"_datamodels":\s*\[.*\]',
        r"(src|dest)_ip_(id|primary_artifact|scope)",
    ],
    "Splunk_ESCU": [
        r'search_name="ESCU - .* - Rule"',
        r'analyticstories=".*"',
        r'annotations.*mitre_attack":\s*\[".+?"\]',
    ],
    "Windows_DC_Test": [
        r'"Hostname":\s*".*attackrange\.local"',
        r'"SourceName":\s*"Microsoft-Windows-Sysmon"',
        r'"EventID":\s*10',  # Process Access event
    ],
    "Splunk_SVD": [
        r"DEBUG.*REST_Calls.*app=Splunk_TA_",
        r"TcpChannelThread.*server/control",
        r"custom=\w+_polite",  # Graceful operations
    ],
    "Windows_SIP": [
        r"Microsoft\\Cryptography\\OID",  # SIP-managed registry branch
        r'FuncName":\s*"WVTAsn1',  # Trust verification functions
        r'Dll":\s*".*\.DLL"',  # Protected system DLLs
    ],
    "IIS_Backdoor_Activity": [
        r'name=".*[bB]ackdo',  # Catch typos (backdo1/backdo0r/etc)
        r'image=".*\\temp\\',  # Temp folder DLLs
        r'ElementTagName="add".*globalModules',  # Module injection pattern
    ],
    "Magento_Access": [
        r"/static/version\d+/frontend/Magento/",  # Versioned static content
        r"Magento_\w+/js/",  # Module JS files
        r'HTTP/2\.0"\s+200\s+\d+',  # Successful HTTP/2 responses
    ],
    "AttackSim_DNS": [
        r'query":\s*".*phishnet\.attackrange\.local"',
        r'stream:dns".*AAAA"',
        r'transport":\s*"udp".*reply_code":\s*"No Error"',
    ],
    "Java_AppServer": [
        r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} DEBUG",  # Java log format
        r"\[http-\d+\]",  # HTTP thread markers
        r"HQL:\s*from\s+\w+",  # Hibernate queries
    ],
}


def detect_log_type(file_path, content):
    """Detect log type with prioritized filename checks"""
    filename = Path(file_path).name.lower()

    # 1. Check for XML structure (strict Sysmon check) => Since they constit the majorit of logs
    if re.match(r"^\s*<Event[^>]*>", content):
        return "Sysmon"

    # 2. First check filename patterns (Azure gets priority)
    for category, patterns in FILENAME_PATTERNS.items():
        if any(re.search(pattern, filename) for pattern in patterns):
            return category

    # 3. Check content patterns
    for category, patterns in CONTENT_PATTERNS.items():
        if any(re.search(pattern, content) for pattern in patterns):
            return category

    return "Other"


def organize_logs(source_dir):
    """Organize files without creating empty folders"""
    category_counts = {category: 0 for category in FILENAME_PATTERNS.keys()}
    category_counts.update({"Sysmon": 0, "Other": 0})

    # First pass: detect all log types
    files = []
    for file in os.listdir(source_dir):
        file_path = Path(source_dir) / file
        if file_path.is_file() and not file_path.name.startswith("."):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(4096)
                    log_type = detect_log_type(file_path, content)
                    files.append((file_path, log_type))
                    category_counts[log_type] += 1
            except Exception as e:
                print(f"Error processing {file}: {str(e)}")

    # Create folders only for categories with files
    for category, count in category_counts.items():
        if count > 0:
            (Path(source_dir) / category).mkdir(exist_ok=True)

    # Second pass: move files
    for file_path, log_type in files:
        dest_dir = Path(source_dir) / log_type
        try:
            shutil.move(str(file_path), str(dest_dir / file_path.name))
            print(f"Moved {file_path.name} to {log_type}/")
        except Exception as e:
            print(f"Failed to move {file_path.name}: {str(e)}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python script.py </path/to/logs>")
        sys.exit(1)

    source_dir = sys.argv[1]
    if not Path(source_dir).exists():
        print(f"Error: Directory {source_dir} not found")
        sys.exit(1)

    organize_logs(source_dir)
    print("Log organization completed!")
