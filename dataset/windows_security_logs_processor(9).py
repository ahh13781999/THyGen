import os
import re
import sys
from collections import defaultdict

# Windows Security Event Mapping Dictionary
WINDOWS_SECURITY_EVENT_MAPPING = {
    # Account Logon Events
    "4624": "windows-successful-logon",
    "4625": "windows-failed-logon",
    "4648": "windows-explicit-credentials-logon",
    "4672": "windows-special-privileges-assigned",
    "4778": "windows-session-reconnected",
    "4779": "windows-session-disconnected",

    # Account Management
    "4720": "windows-user-account-created",
    "4722": "windows-user-account-enabled",
    "4725": "windows-user-account-disabled",
    "4726": "windows-user-account-deleted",
    "4738": "windows-user-account-changed",
    "4740": "windows-user-account-locked-out",
    "4767": "windows-user-account-unlocked",

    # Process Events
    "4688": "windows-process-creation",
    "4689": "windows-process-exit",
    "4697": "windows-service-installed",

    # Object Access
    "4656": "windows-object-access-attempt",
    "4663": "windows-object-access",
    "4670": "windows-object-permissions-changed",

    # Policy Change
    "4719": "windows-system-audit-policy-changed",
    "4739": "windows-domain-policy-changed",
    "4864": "windows-namespace-collision",

    # Privilege Use
    "4673": "windows-privileged-service-called",
    "4674": "windows-privileged-object-operation",

    # Detailed Tracking
    "4690": "windows-object-deleted",
    "4691": "windows-indirect-object-access",

    # System Events
    "4616": "windows-system-time-changed",
    "4621": "windows-administrator-recovered-system",

    # Log Clear Events
    "1102": "windows-log-cleared",

    # Firewall Events
    "2004": "windows-firewall-rule-added",
    "2005": "windows-firewall-rule-modified",
    "2006": "windows-firewall-rule-deleted",

    # RDP Events
    "21": "windows-remote-desktop-session-success",
    "22": "windows-remote-desktop-session-failed",
    "23": "windows-remote-desktop-session-disconnect",
    "24": "windows-remote-desktop-session-reconnect",

    # PowerShell Events
    "400": "windows-powershell-operation-start",
    "403": "windows-powershell-operation-stop",
    "600": "windows-powershell-provider-start",
    "800": "windows-powershell-pipeline-detail",

    # AppLocker Events
    "8002": "windows-applocker-executable-blocked",
    "8003": "windows-applocker-script-blocked",
    "8004": "windows-applocker-installer-blocked",
    "8006": "windows-applocker-dll-blocked",

    # Windows Defender Events
    "5001": "windows-defender-threat-detected",
    "5004": "windows-defender-config-changed",
    "5007": "windows-defender-config-changed",
    "5010": "windows-defender-signature-updated",
    "5012": "windows-defender-scan-completed",

    # Certificate Services
    "4870": "windows-certificate-services-started",
    "4871": "windows-certificate-services-stopped",
    "4872": "windows-certificate-services-backup",
    "4873": "windows-certificate-services-restored",

    # Special Logon
    "4964": "windows-special-group-assigned",

    # Kerberos Events
    "4768": "windows-kerberos-ticket-request",
    "4769": "windows-kerberos-service-ticket-request",
    "4770": "windows-kerberos-service-ticket-renewed",
    "4771": "windows-kerberos-preauthentication-failed",

    # NTLM Events
    "4776": "windows-ntlm-authentication",
    "4777": "windows-ntlm-session-security",

    # Logon/Logoff
    "4634": "windows-account-logoff",
    "4647": "windows-user-initiated-logoff",
    
    # Expanded Account Logon Events
    "4768": "windows-kerberos-ticket-request",
    "4772": "windows-kerberos-ticket-request-failed",
    "4773": "windows-kerberos-service-ticket-renewed",
    "4774": "windows-kerberos-account-mapped",
    "4775": "windows-domain-controller-failed-validation",
    "4964": "windows-special-group-assigned",
    "5379": "windows-credential-manager-access",
    "5382": "windows-user-device-claims-changed",

    # Expanded Account Management
    "4728": "windows-group-member-added",
    "4729": "windows-group-member-removed",
    "4732": "windows-local-group-member-added",
    "4733": "windows-local-group-member-removed",
    "4756": "windows-universal-group-member-added",
    "4757": "windows-universal-group-member-removed",
    "4765": "windows-sid-history-added",
    "4766": "windows-sid-history-add-failed",

    # Expanded Process Events
    "4698": "windows-scheduled-task-created",
    "4699": "windows-scheduled-task-deleted",
    "4700": "windows-scheduled-task-enabled",
    "4701": "windows-scheduled-task-disabled",
    "4702": "windows-scheduled-task-updated",
    "4687": "windows-process-creation-with-commandline",

    # Expanded Object Access
    "4657": "windows-registry-value-modified",
    "4658": "windows-object-handle-closed",
    "4660": "windows-object-deleted",
    "5140": "windows-network-share-accessed",
    "5142": "windows-network-share-added",
    "5143": "windows-network-share-modified",
    "5144": "windows-network-share-deleted",
    "5168": "windows-share-permission-changed",

    # Expanded Policy Change
    "4704": "windows-user-rights-assigned",
    "4705": "windows-audit-policy-updated",
    "4713": "windows-kerberos-policy-changed",
    "4715": "windows-object-access-audit-policy",
    "4716": "windows-trust-validation-changed",
    "4717": "windows-system-security-access-granted",
    "4718": "windows-system-audit-policy-updated",
    "4737": "windows-global-object-modified",
    "4865": "windows-namespace-collision-detected",
    "4866": "windows-namespace-collision-resolved",
    "4867": "windows-namespace-collision-error",

    # Expanded Detailed Tracking
    "4692": "windows-data-backup-attempt",
    "4693": "windows-data-restore-attempt",
    "4696": "windows-primary-token-assigned",
    "5058": "windows-key-file-operation",
    "5059": "windows-key-migration",

    # Expanded System Events
    "4608": "windows-system-startup",
    "4609": "windows-system-shutdown",
    "4610": "windows-authentication-package-loaded",
    "4611": "windows-trusted-logon-process-registered",
    "4612": "windows-internal-resource-allocated",
    "4614": "windows-notification-package-loaded",
    "4615": "windows-lsa-secret-manipulated",
    "4618": "windows-monitored-security-event-pattern",
    "4622": "windows-security-package-loaded",
    "4694": "windows-protected-data-accessed",
    "4695": "windows-unprotected-data-accessed",
    "5058": "windows-cryptographic-key-operation",
    "5059": "windows-cryptographic-key-migration",
    "5062": "windows-cryptography-operation",

    # Expanded Firewall Events
    "2007": "windows-firewall-rule-setting-changed",
    "2008": "windows-firewall-inbound-blocked",
    "2009": "windows-firewall-rule-modified",
    "2010": "windows-firewall-rule-removed",

    # Expanded RDP Events
    "25": "windows-remote-desktop-auto-reconnect",
    "39": "windows-remote-desktop-protocol-error",
    "40": "windows-remote-desktop-session-timeout",
    "1149": "windows-remote-desktop-auth-failed",

    # Expanded PowerShell Events
    "4103": "windows-powershell-module-log",
    "4104": "windows-powershell-script-block-log",
    "53504": "windows-powershell-transcription-start",
    "53505": "windows-powershell-transcription-stop",

    # Expanded AppLocker Events
    "8007": "windows-applocker-packaged-app-blocked",
    "8020": "windows-applocker-policy-changed",

    # Expanded Windows Defender Events
    "1006": "windows-defender-scan-started",
    "1007": "windows-defender-scan-completed",
    "1008": "windows-defender-signature-updated",
    "1015": "windows-defender-realtime-enabled",
    "1016": "windows-defender-realtime-disabled",
    "1116": "windows-defender-malware-detected",
    "1117": "windows-defender-detection-created",
    "1118": "windows-defender-remediation-complete",

    # Expanded Certificate Services
    "4874": "windows-certificate-authority-config-changed",
    "4875": "windows-certificate-manager-changed",
    "4876": "windows-certificate-service-backup",
    "4877": "windows-certificate-service-restore",
    "4880": "windows-certificate-template-loaded",
    "4885": "windows-certificate-audit-filter-changed",

    # Security Mitigations
    "4649": "windows-replay-attack-detected",
    "4703": "windows-token-right-adjusted",
    "4706": "windows-new-trust-created",
    "4707": "windows-trust-removed",
    "4714": "windows-encrypted-data-recovery-policy",
    "4902": "windows-per-user-audit-policy",
    "4907": "windows-audit-policy-changed",
    "4911": "windows-resource-attribute-changed",
    "4960": "windows-lsa-policy-changed",
    "4963": "windows-crypto-policy-changed",

    # Scheduled Task Events
    "106": "windows-task-registered",
    "140": "windows-task-updated",
    "141": "windows-task-deleted",
    "200": "windows-task-executed",
    "201": "windows-task-completed",
    "202": "windows-task-failed",

    # Group Policy Events
    "5136": "windows-group-policy-applied",
    "5137": "windows-group-policy-modified",
    "5141": "windows-group-policy-deleted",

    # BitLocker Events
    "8222": "windows-bitlocker-encryption-start",
    "8224": "windows-bitlocker-encryption-resume",
    "8228": "windows-bitlocker-encryption-complete",
    "8229": "windows-bitlocker-encryption-failed",
    "8230": "windows-bitlocker-encryption-paused",
    "8251": "windows-bitlocker-recovery-key-backed-up",
    "8450": "windows-bitlocker-pin-changed",
    "8454": "windows-bitlocker-protector-added",
    "8455": "windows-bitlocker-protector-removed",
    "8460": "windows-bitlocker-encryption-method-changed",

    # Hyper-V Events
    "18450": "windows-hyperv-vm-created",
    "18451": "windows-hyperv-vm-deleted",
    "18452": "windows-hyperv-vm-started",
    "18453": "windows-hyperv-vm-stopped",
    "18454": "windows-hyperv-config-changed",
    "18455": "windows-hyperv-snapshot-created",
    "18456": "windows-hyperv-snapshot-deleted",
    "18457": "windows-hyperv-snapshot-applied",

    # DNS Server Events
    "150": "windows-dns-query-received",
    "160": "windows-dns-response-sent",
    "404": "windows-dns-error-occurred",
    "550": "windows-dns-zone-updated",
    "551": "windows-dns-dynamic-update",

    # Component Servicing
    "6145": "windows-component-servicing-operation",

    # Network Policy Server
    "6273": "windows-network-policy-server-access",
    "6278": "windows-quarantine-user",
    "6279": "windows-user-quarantined",
    "6280": "windows-user-exempted",
    "6281": "windows-quarantine-transition",
    "6282": "windows-quarantine-timer-expired",

    # BranchCache
    "6400": "windows-branchcache-activity",
    "6401": "windows-branchcache-content-blocked",
    "6402": "windows-branchcache-hash-generated",
    "6403": "windows-branchcache-content-retrieved",
    "6404": "windows-branchcache-hosted-cache",
    "6405": "windows-branchcache-client-config",
    "6406": "windows-branchcache-server-config",
    
    # System/Application Events
    "1": "windows-system-time-change",
    "2": "windows-print-operation",
    "3": "windows-system-unexpected-shutdown",
    "4": "windows-system-startup-time",
    "6": "windows-driver-loaded",
    "12": "windows-registry-recovery",
    "13": "windows-registry-restored",
    "14": "windows-ntfs-corruption",
    "15": "windows-disk-full",
    "16": "windows-application-error",
    "18": "windows-cluster-resource-offline",
    "20": "windows-update-error",
    "27": "windows-application-crash",
    "29": "windows-firewall-packet-drop",
    "31": "windows-disk-write-error",
    "32": "windows-driver-installation",
    "35": "windows-tcpip-config-change",
    "37": "windows-usb-device-error",
    "50": "windows-file-system-corruption",
    "55": "windows-file-system-error",
    "98": "windows-disk-quota-exceeded",
    "100": "windows-firewall-connection-blocked",
    "102": "windows-dns-resolution",
    "104": "windows-user-logoff",
    "107": "windows-system-sleep",
    "108": "windows-system-resume",
    "109": "windows-kernel-error",
    "110": "windows-user-profile-unload",
    "111": "windows-user-profile-load",
    "129": "windows-disk-read-error",
    "134": "windows-wlan-connection",
    "139": "windows-disk-io-error",
    "143": "windows-volume-mounted",
    "144": "windows-volume-dismounted",
    "153": "windows-disk-timeout",
    "172": "windows-certificate-validation-failed",
    "226": "windows-firewall-rule-added",
    "316": "windows-certificate-autoenrollment-failed",
    "329": "windows-scheduled-task-registered",
    "330": "windows-scheduled-task-executed",
    "603": "windows-backup-operation",
    "808": "windows-hyperv-vm-config-change",
    "809": "windows-hyperv-vm-state-change",
    "1014": "windows-dns-resolution-failed",
    "1024": "windows-application-hang",
    "1026": "windows-net-runtime-error",
    "1028": "windows-dhcp-ip-conflict",
    "1029": "windows-disk-resource-exhausted",
    "1056": "windows-service-control-manager-error",
    "1058": "windows-service-start-failed",
    "1067": "windows-service-unexpected-stop",
    "1072": "windows-logon-explicit-credentials",
    "1074": "windows-system-shutdown-initiated",
    "1100": "windows-eventlog-service-stop",
    "1105": "windows-audit-log-cleared",
    "1129": "windows-rpc-server-unavailable",
    "1281": "windows-app-package-activated",
    "1282": "windows-app-package-terminated",
    "1500": "windows-process-start",
    "1501": "windows-process-end",
    "1502": "windows-module-loaded",
    "3260": "windows-certificate-enrollment",
    "4096": "windows-powershell-command-start",
    "4100": "windows-powershell-module-load",
    "4101": "windows-powershell-script-execution",
    "4105": "windows-powershell-command-detail",
    "4106": "windows-powershell-script-block",
    "4200": "windows-network-isolation",
    "4201": "windows-network-isolation-release",
    "4202": "windows-network-isolation-error",
    "4662": "windows-object-operation",
    
    # Account Management
    "4724": "windows-user-password-reset",
    "4727": "windows-global-group-created",
    "4731": "windows-domain-policy-modified",
    "4735": "windows-domain-policy-changed",
    "4741": "windows-computer-account-created",
    "4742": "windows-computer-account-deleted",
    "4754": "windows-security-group-type-changed",
    "4755": "windows-universal-group-created",
    "4781": "windows-account-name-changed",
    
    # Security Events
    "4794": "windows-directory-service-backup",
    "4798": "windows-group-policy-processing",
    "4799": "windows-resource-attribute-changed",
    "4826": "windows-boot-configuration-changed",
    "4904": "windows-security-policy-updated",
    "4905": "windows-audit-policy-rule-changed",
    
    # Network/Firewall
    "5024": "windows-firewall-service-start",
    "5033": "windows-firewall-rule-applied",
    "5061": "windows-cryptographic-operation",
    "5145": "windows-network-share-access",
    "5154": "windows-firewall-packet-block",
    "5156": "windows-firewall-connection-allow",
    "5157": "windows-firewall-connection-block",
    "5158": "windows-firewall-bind-allow",
    
    # System Events
    "5516": "windows-user-initiated-logoff",
    "5719": "windows-ip-address-conflict",
    "5774": "windows-kerberos-pre-auth-failed",
    "5823": "windows-cluster-node-status",
    "6005": "windows-eventlog-service-start",
    "6006": "windows-eventlog-service-stop",
    "6009": "windows-os-version-boot",
    "6011": "windows-system-unexpected-shutdown",
    "6013": "windows-system-uptime",
    "6038": "windows-volume-shadow-copy",
    
    # Service Events
    "7000": "windows-service-start-failure",
    "7001": "windows-service-dependency-failure",
    "7002": "windows-service-disabled",
    "7009": "windows-service-timeout",
    "7023": "windows-service-terminated-error",
    "7026": "windows-boot-drivers",
    "7031": "windows-service-crash",
    "7034": "windows-service-unexpected-stop",
    "7036": "windows-service-state-change",
    "7038": "windows-service-config-change",
    "7040": "windows-service-start-type-changed",
    "7045": "windows-service-installed",
    
    # RPC/DCOM
    "8193": "windows-rpc-server-start",
    "8194": "windows-rpc-server-register",
    "8195": "windows-rpc-server-listen",
    "8196": "windows-rpc-endpoint-register",
    "8197": "windows-rpc-endpoint-unregister",
    "10005": "windows-dcom-server-start-failed",
    "10010": "windows-dcom-access-denied",
    "10016": "windows-dcom-permission-error",
    
    # Advanced Networking
    "10111": "windows-scheduled-task-status",
    "10148": "windows-firewall-packet-drop",
    "10149": "windows-firewall-connection-block",
    "10154": "windows-http-request-failed",
    
    # Certificate/TPM
    "12039": "windows-certificate-revocation-check-failed",
    "16937": "windows-tpm-error",
    "16962": "windows-kerberos-kdc-failure",
    "16977": "windows-tpm-attestation",
    "32784": "windows-certificate-trust-failed",
    "36886": "windows-tls-handshake-failed",
    
    # PowerShell/WinRM
    "40961": "windows-powershell-engine-start",
    "40962": "windows-powershell-engine-stop",
    "51046": "windows-winrm-access-denied",
    "51047": "windows-winrm-config-error",
    
    # Security Features
    "50036": "windows-credential-guard-policy",
    "50037": "windows-lsa-protection-enabled",
    
        # Windows Hello/Biometrics
    "14531": "windows-hello-biometric-added",
    "14533": "windows-hello-biometric-removed",
    
    # Credential Migration
    "15007": "windows-credential-migration-attempt",
    "15008": "windows-credential-migration-result",
    
    # Key Credential Operations
    "15301": "windows-key-credential-operation",
    
    # Active Directory Certificate Services (AD CS)
    "16401": "windows-adcs-certificate-enrolled",
    "16403": "windows-adcs-certificate-revoked",
    "16413": "windows-adcs-certificate-template-modified",
    
    # Certificate Validation/Issuance
    "16647": "windows-certificate-validation-failure",
    "16648": "windows-certificate-issuance-failure",
    
    # Active Directory Federation Services (AD FS)
    "20001": "windows-adfs-token-validation-failed",
    "20003": "windows-adfs-saml-assertion-invalid",
    
    # Windows Defender
    "5008": "windows-defender-controlled-folder-access",
    
    # Advanced Security Events
    "16401": "windows-certificate-autoenrollment-failed",
    "16403": "windows-certificate-enrollment-agent-restricted",
    "16413": "windows-smartcard-certificate-renewal"
}

# Track unmapped event codes
UNMAPPED_EVENT_CODES = set()

# Enhanced regex patterns with multiple possible field names
REGEX_PATTERNS = {
    'timestamp': re.compile(r'^\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2} [AP]M$', re.I),
    'event_code': re.compile(r'(?:EventCode|Event ID)\s*[:=]\s*(\d+)', re.I),
    'event_type': re.compile(r'TaskCategory\s*[:=]\s*([^\n]+)', re.I),
    
    # Process fields
    'pid': re.compile(r'(?:Process ID|New Process ID)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)', re.I),
    'process': re.compile(r'(?:New Process Name|Process Name)\s*[:=]\s*([^\n]+)', re.I),
    
    # Network fields
    'source_ip': re.compile(r'(?:Source Address|Source Network Address|Network Source Address)\s*[:=]\s*([^\n]+)', re.I),
    'source_port': re.compile(r'(?:Source Port|Network Source Port)\s*[:=]\s*(\d+)', re.I),
    'destination_ip': re.compile(r'(?:Destination Address|Destination Network Address|Network Destination Address)\s*[:=]\s*([^\n]+)', re.I),
    'destination_port': re.compile(r'(?:Destination Port|Network Destination Port)\s*[:=]\s*(\d+)', re.I),
    
    # Parent process fields
    'parent_process': re.compile(r'(?:Creator Process Name|Parent Process Name)\s*[:=]\s*([^\n]+)', re.I),
    'ppid': re.compile(r'(?:Creator Process ID|Parent Process ID)\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)', re.I),
    
    # Path fields
    'process_directory': re.compile(r'(?:File Path|Path|Image Path)\s*[:=]\s*([^\n]+)', re.I),
    'file_name': re.compile(r'(?:Application Name)\s*[:=]\s*([^\n]+)', re.I),
}

def hex_to_dec(value):
    """Convert hex string to decimal integer string"""
    try:
        if isinstance(value, str) and value.lower().startswith('0x'):
            return str(int(value, 16))
        return str(int(value))
    except (ValueError, TypeError):
        return value

def is_valid_value(value):
    """Check if value is meaningful (not empty, not just hyphens/spaces)"""
    if not value:
        return False
    value = str(value).strip()
    refined_value = clean_value(value)
    return bool(refined_value and refined_value not in ('-', 'N/A', 'NULL', '(null)'))

def validate_directory_path(path):
    """
    Validate if a path appears to be a legitimate filesystem directory path
    Returns True for valid-looking paths, False for suspicious patterns
    """
    if not path or not isinstance(path, str):
        return False
    
    # Common suspicious patterns
    suspicious_patterns = [
        r'^\$[a-zA-Z_:]',  # Environment variables like $env:TMP
        r'^%.+%$',         # Windows env variables like %TEMP%
        r'^[^a-zA-Z]:',    # Doesn't start with drive letter (Windows)
        r'^[^/\\]',        # Doesn't start with slash/backslash (Unix/Windows)
        r'\s{2,}',         # Multiple spaces
        r'[<>|]',          # Suspicious characters
        r'\.\.',           # Parent directory references
        r'//+|\\\\+'       # Multiple consecutive slashes
    ]
    
    # Check for suspicious patterns
    for pattern in suspicious_patterns:
        if re.search(pattern, path, re.IGNORECASE):
            return False
    
    # Basic path structure validation
    if re.match(r'^([a-zA-Z]:|\\\\|/)', path):  # Windows drive or UNC, or Unix root
        return True
    
    return False

def clean_value(value, is_path=False):
    """Clean and normalize extracted values with optional path validation and comma removal"""
    if not value:
        return ''
    
    # Convert to string and strip outer whitespace
    value = str(value).strip()
    
    # Remove all types of quotations (both single, double, and smart quotes)
    value = re.sub(r'^[\'\"\u2018\u2019\u201c\u201d]|[\'\"\u2018\u2019\u201c\u201d]$', '', value)
    
    # Remove internal escaped quotes
    value = value.replace('\\"', '').replace("\\'", '')
    
    # Remove commas from the value
    value = value.replace(',', '')
    
    # Normalize whitespace and remove control characters
    value = re.sub(r'\s+', ' ', value)
    value = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value)
    
    # Additional path validation if requested
    if is_path and not validate_directory_path(value):
        return ''
    
    return value

def extract_filename(full_path):
    """Extract just the filename from a full path"""
    if not full_path:
        return ''
    
    # Normalize path separators and get basename
    normalized_path = full_path.replace('\\', '/')
    return os.path.basename(normalized_path)

def get_mitre_tactic(file_path):
    """Extract MITRE tactic from directory structure"""
    try:
        parts = os.path.normpath(file_path).split(os.sep)
        ws_index = parts.index('Windows_Security')
        return parts[ws_index-1] if ws_index > 0 else "unknown"
    except (ValueError, IndexError):
        return "unknown"

def map_event_code(event_code):
    """Map numeric event codes to human-readable names and track unmapped codes"""
    event_code = str(event_code)
    if event_code in WINDOWS_SECURITY_EVENT_MAPPING:
        return WINDOWS_SECURITY_EVENT_MAPPING[event_code]
    else:
        UNMAPPED_EVENT_CODES.add(event_code)
        return f"windows-event-{event_code}"

def print_unmapped_event_codes():
    """Print all encountered event codes that weren't in the mapping"""
    if UNMAPPED_EVENT_CODES:
        print("\nUnmapped Event Codes Encountered:", file=sys.stderr)
        for code in sorted(UNMAPPED_EVENT_CODES, key=int):
            print(f"- {code}", file=sys.stderr)
    else:
        print("\nAll event codes were mapped successfully", file=sys.stderr)
        
def process_log_file(file_path):
    """Process log file and yield parsed entries"""
    current_entry = []
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if REGEX_PATTERNS['timestamp'].match(line):
                if current_entry:
                    yield current_entry
                current_entry = [line]
            else:
                current_entry.append(line)
    
    if current_entry:
        yield current_entry

def extract_fields(log_entry, current_filename):
    """Extract all fields using enhanced multi-pattern regex"""
    entry_text = '\n'.join(log_entry)
    fields = {}
    
    # Extract Event Type
    if match := REGEX_PATTERNS['event_type'].search(entry_text):
        fields['event_type'] = match.group(1)
    
    # PID with hex conversion
    if match := REGEX_PATTERNS['pid'].search(entry_text):
        fields['pid'] = hex_to_dec(match.group(1))
    
    # Process Name 
    if match := REGEX_PATTERNS['process'].search(entry_text):
        app_name = match.group(1)
        extract_name = extract_filename(app_name)
        fields['process'] = extract_name
    
    # Parent process info with hex conversion
    if match := REGEX_PATTERNS['ppid'].search(entry_text):
        fields['ppid'] = hex_to_dec(match.group(1))
    
    # Parent Process Name 
    if match := REGEX_PATTERNS['parent_process'].search(entry_text):
        app_name = match.group(1)
        extract_name = extract_filename(app_name)
        fields['parent_process'] = extract_name
    
    # Process Directory
    if match := REGEX_PATTERNS['process_directory'].search(entry_text):
        path = validate_directory_path(match.group(1))
        fields['process_directory'] = path
    
    # Network information
    if match := REGEX_PATTERNS['source_ip'].search(entry_text):
        source_ip = match.group(1)
        if source_ip not in ('-', '::', '0.0.0.0', '::1'):
            fields['source_ip'] = source_ip
    
    if match := REGEX_PATTERNS['source_port'].search(entry_text):
        fields['source_port'] = match.group(1)
    
    if match := REGEX_PATTERNS['destination_ip'].search(entry_text):
        dest_ip = match.group(1)
        if dest_ip not in ('-', '::', '0.0.0.0', '::1'):
            fields['destination_ip'] = dest_ip
    
    if match := REGEX_PATTERNS['destination_port'].search(entry_text):
        fields['destination_port'] = match.group(1)
    
    # File path if separate from application name
    if match := REGEX_PATTERNS['file_name'].search(entry_text):
        file = validate_directory_path(match.group(1))
        fields['file_name'] = file
        
    # Operation Type
    if match := REGEX_PATTERNS['event_code'].search(entry_text):
        fields['operation_type'] = map_event_code(match.group(1))
    
    # Add the current processing filename
    # fields['processing_file'] = os.path.basename(current_filename)
    
    # Filter for only valid values and require at least 4 fields
    valid_fields = {k: v for k, v in fields.items() if is_valid_value(v)}
    return valid_fields if len(valid_fields) >= 3 else None


def format_output(fields):
    """Format the output string with only valid fields"""
    return ", ".join([f"{k}='{v}'" for k, v in fields.items()])

def main(root_dir):
    """Main processing function"""
    stats = defaultdict(int)
    files_processed = 0
    entries_processed = 0
    entries_skipped = 0
    
    for root, dirs, files in os.walk(root_dir):
        if os.path.basename(root) == 'Windows_Security':
            for file in files:
                if file.lower().endswith('.log'):
                    file_path = os.path.join(root, file)
                    mitre_tactic = get_mitre_tactic(file_path)
                    stats[mitre_tactic] += 1
                    files_processed += 1
                    
                    try:
                        for entry in process_log_file(file_path):
                            fields = extract_fields(entry, file_path)
                            if fields is not None:  # Only process if we got valid fields
                                fields['mitre_tactic'] = mitre_tactic  # Now safe to add
                                output = format_output(fields)
                                if output:
                                    print(output)
                                    entries_processed += 1
                                else:
                                    entries_skipped += 1
                            else:
                                entries_skipped += 1
                    except Exception as e:
                        print(f"Error processing {file_path}: {str(e)}", file=sys.stderr)
   
    # Print statistics
    print("\nProcessing Statistics:", file=sys.stderr)
    for tactic, count in sorted(stats.items()):
        print(f"- {tactic}: {count} files", file=sys.stderr)
    print(f"Total files processed: {sum(stats.values())}", file=sys.stderr)

    print_unmapped_event_codes()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python process-ws.py <root_directory>", file=sys.stderr)
        sys.exit(1)
    
    print("Starting log processing...", file=sys.stderr)
    main(sys.argv[1])
    print("Processing completed.", file=sys.stderr)