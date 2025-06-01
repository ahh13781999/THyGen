import pandas as pd
import os
import torch
import numpy as np
from transformers import AutoModelForCausalLM, AutoTokenizer
from sklearn.utils import resample
import warnings
from tqdm import tqdm
from collections import OrderedDict

# Suppress warnings
warnings.filterwarnings('ignore')

# ----------------------------
# Configuration
# ----------------------------
MODEL_NAME = "segolilylabs/Lily-Cybersecurity-7B-v0.2"
MAX_UNDERSAMPLE_RATIO = 1.2
MIN_OVERSAMPLE_RATIO = 0.4
MINORITY_THRESHOLD = 0.02
DUPLICATION_FACTOR = 2
LLM_TARGET_MULTIPLIER = 3
LLM_GENERATION_RETRIES = 3
BATCH_SIZE = 4

# Field configuration (in original dataset order)
ALLOWED_FIELDS = OrderedDict([
    ('log_type', None),
    ('event_type', None),
    ('pid', None),
    ('process', None),
    ('ppid', None),
    ('parent_process', None),
    ('process_directory', None),
    ('registry_path', None),
    ('source_ip', None),
    ('source_port', None),
    ('source_port_name', None),
    ('destination_ip', None),
    ('destination_port', None),
    ('destination_port_name', None),
    ('file_name', None),
    ('operation_type', None),
    ('queried_domain', None),
    ('resolved_ip', None),
    ('http_method', None),
    ('url_path', None),
    ('response_code', None),
    ('host_domain', None),
    ('redirect_location', None)
])

VALID_PROCESSES = {'explorer.exe', 'svchost.exe', 'powershell.exe', 'lsass.exe',
                  'wmiprvse.exe', 'services.exe', 'wininit.exe', 'spoolsv.exe',
                  'chrome.exe', 'firefox.exe', 'iexplore.exe', 'msedge.exe',
                  'winlogon.exe', 'csrss.exe', 'smss.exe', 'taskhost.exe'}

COMMON_PORTS = {80, 443, 3389, 5985, 22, 53, 445, 636, 8080, 8443}
PRIVATE_IP_PREFIXES = ('10.', '192.168.', '172.16.')

# ----------------------------
# Cybersecurity LLM Integration
# ----------------------------
class CyberLLMGenerator:
    def __init__(self):
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.tokenizer = AutoTokenizer.from_pretrained(
            MODEL_NAME,
            trust_remote_code=True
        )
        self.model = AutoModelForCausalLM.from_pretrained(
            MODEL_NAME,
            torch_dtype=torch.bfloat16,
            device_map="auto",
            trust_remote_code=True
        ).eval()
        torch.cuda.empty_cache()

    def generate_cyber_samples(self, cls, needed_samples):
        prompt = self._build_cybersecurity_prompt(cls)
        generated = []
        
        for _ in range(LLM_GENERATION_RETRIES):
            inputs = self.tokenizer(
                prompt,
                return_tensors="pt",
                max_length=1024,
                truncation=True
            ).to(self.device)
            
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=128,
                temperature=0.7,
                top_p=0.9,
                num_return_sequences=BATCH_SIZE,
                do_sample=True
            )
            
            decoded = self.tokenizer.batch_decode(outputs, skip_special_tokens=True)
            generated.extend(decoded)
            
            if len(generated) >= needed_samples:
                break
        
        return generated[:needed_samples]

    def _build_cybersecurity_prompt(self, tactic):
        fields_list = ", ".join(ALLOWED_FIELDS.keys())
        return f"""Generate realistic cybersecurity log entries for MITRE {tactic} tactic using ONLY these fields in EXACTLY this order:
{fields_list}

Choose ONE log type per sample from these formats:

1. DNS Log (must include queried_domain, resolved_ip, source_port=53):
{self._format_example('dns', ['queried_domain', 'resolved_ip', 'source_ip'])}

2. HTTP Log (must include http_method, url_path, response_code):
{self._format_example('http', ['http_method', 'url_path', 'source_ip'])}

3. Process Log (must include pid, process, parent_process):
{self._format_example('process', ['pid', 'process', 'parent_process'])}

4. Network Log (must include source_port, destination_port, operation_type):
{self._format_example('network', ['source_ip', 'destination_ip', 'operation_type'])}

STRICT RULES:
1. Maintain EXACT field order: {fields_list}
2. Only use private IPs: 10.x.x.x, 192.168.x.x, 172.16.x.x
3. Valid processes: {', '.join(sorted(VALID_PROCESSES))}
4. Common ports: {', '.join(map(str, sorted(COMMON_PORTS)))}
5. Omit unused fields (don't set to null/empty)
6. Never include malware/exploit terms

Generate 3 samples following EXACTLY this format:
"""

    def _format_example(self, log_type, highlight_fields):
        example = OrderedDict(ALLOWED_FIELDS)
        example['log_type'] = log_type
        example['event_type'] = f"{log_type}_event"
        
        # Set example values for highlighted fields
        for field in highlight_fields:
            if field == 'queried_domain':
                example[field] = 'example.com'
            elif field == 'resolved_ip':
                example[field] = '10.2.3.4'
            elif field == 'source_ip':
                example[field] = '192.168.1.100'
            elif field == 'http_method':
                example[field] = 'GET'
            elif field == 'url_path':
                example[field] = '/api/v1/test'
            elif field == 'pid':
                example[field] = '1234'
            elif field in ('process', 'parent_process'):
                example[field] = 'explorer.exe'
            elif field == 'operation_type':
                example[field] = 'outbound'
        
        # Convert to string representation
        return ", ".join(f"{k}='{v}'" if v is not None else f"{k}=None" 
                       for k, v in example.items() if v is not None)

# ----------------------------
# Data Processing
# ----------------------------
def parse_line(line):
    features = OrderedDict(ALLOWED_FIELDS)
    label = None
    
    pairs = [p.strip() for p in line.split(", ") if "=" in p]
    for pair in pairs:
        try:
            key, value = pair.split("=", 1)
            key = key.strip("'\"")
            value = value.strip("'\"")
            if key == 'mitre_tactic':
                label = value
            elif key in features:
                features[key] = value
        except:
            continue
            
    return features, label

def validate_cyber_sample(features, label):
    # Check field order and existence
    if list(features.keys()) != list(ALLOWED_FIELDS.keys()):
        return False
    
    # Check required fields based on log_type
    log_type = features.get('log_type')
    required_fields = {
        'dns': ['queried_domain', 'resolved_ip', 'source_port'],
        'http': ['http_method', 'url_path', 'response_code'],
        'process': ['pid', 'process', 'parent_process'],
        'network': ['source_port', 'destination_port', 'operation_type']
    }
    
    if log_type not in required_fields:
        return False
    
    if not all(features.get(field) for field in required_fields[log_type]):
        return False
    
    # Common validation
    return all([
        features.get('process', '') in VALID_PROCESSES,
        features.get('parent_process', '') in VALID_PROCESSES,
        features.get('source_ip', '').startswith(PRIVATE_IP_PREFIXES),
        str(features.get('source_port', '0')) in map(str, COMMON_PORTS),
        label is not None,
        not is_noisy_data(features)
    ])

def is_noisy_data(features):
    noise_indicators = [
        'RANDOM', 'EXAMPLE', 'TEST', 'DUMMY',
        'malware', 'exploit', 'hack', 'attack',
        'virus', 'ransomware', 'backdoor'
    ]
    return any(
        any(indicator.lower() in str(v).lower() for indicator in noise_indicators)
        or len(str(v)) > 128
        for v in features.values()
    )

# ----------------------------
# Enhanced Resampling Logic
# ----------------------------
def dynamic_resample(fold_dir):
    try:
        # Load original data to preserve field order
        features_df = pd.read_csv(f"{fold_dir}/train_features.csv")
        labels_df = pd.read_csv(f"{fold_dir}/train_labels.csv")
        original_columns = features_df.columns.tolist() + ['mitre_tactic']
        df = pd.concat([features_df, labels_df], axis=1)
    except Exception as e:
        print(f"Failed to load data: {str(e)}")
        return

    print_class_distribution(df, "BEFORE RESAMPLING")
    
    total_samples = len(df)
    class_counts = df['mitre_tactic'].value_counts()
    llm_gen = CyberLLMGenerator()
    
    resampled_data = []
    
    for cls, count in tqdm(class_counts.items(), desc="Resampling classes"):
        cls_samples = df[df['mitre_tactic'] == cls]
        class_percentage = count / total_samples
        
        if class_percentage < MINORITY_THRESHOLD:
            # Step 1: Duplicate existing samples
            duplicated = pd.concat([cls_samples] * DUPLICATION_FACTOR)
            new_count = len(duplicated)
            
            # Step 2: Calculate LLM generation target
            llm_target = max(
                (count * LLM_TARGET_MULTIPLIER) - new_count,
                int(total_samples * MINORITY_THRESHOLD) - new_count
            )
            
            # Generate synthetic samples if needed
            if llm_target > 0:
                valid_samples = []
                attempts = 0
                while len(valid_samples) < llm_target and attempts < LLM_GENERATION_RETRIES * 2:
                    generated = llm_gen.generate_cyber_samples(cls, BATCH_SIZE)
                    for line in generated:
                        features, label = parse_line(line)
                        if validate_cyber_sample(features, label):
                            # Convert to DataFrame row with correct order
                            row = {**features, 'mitre_tactic': label}
                            valid_samples.append(row)
                            if len(valid_samples) >= llm_target:
                                break
                    attempts += 1
                
                # Create DataFrame with original column order
                if valid_samples:
                    valid_df = pd.DataFrame(valid_samples)[original_columns]
                    duplicated = pd.concat([duplicated, valid_df])
            
            resampled_data.append(duplicated)
            
        elif class_percentage > (MINORITY_THRESHOLD * 3):
            target = int(count * 0.6)  # Reduce majority classes by 40%
            resampled_data.append(cls_samples.sample(n=target, random_state=42))
        else:
            resampled_data.append(cls_samples)

    # Combine all while preserving original column order
    final_df = pd.concat(resampled_data, ignore_index=True)
    final_df = final_df[original_columns]  # Enforce original column ordering
    final_df = final_df.sample(frac=1).reset_index(drop=True)  # Shuffle
    
    save_resampled_data(final_df, fold_dir)
    print_class_distribution(final_df, "AFTER RESAMPLING")

# ----------------------------
# Helper Functions
# ----------------------------
def save_resampled_data(df, fold_dir):
    # Split features and labels while preserving order
    feature_columns = [col for col in df.columns if col != 'mitre_tactic']
    df[feature_columns].to_csv(
        f"{fold_dir}/resampled_train_features.csv", index=False)
    df['mitre_tactic'].to_csv(
        f"{fold_dir}/resampled_train_labels.csv", index=False)

def print_class_distribution(df, title):
    counts = df['mitre_tactic'].value_counts()
    total = len(df)
    print(f"\n{title}:")
    print("-" * 60)
    print(f"{'Tactic':<25} {'Count':<10} {'Percentage':<10} {'Imbalance Ratio':<15}")
    for cls, count in counts.items():
        print(f"{cls:<25} {count:<10} {(count/total*100):<10.2f}% {count/counts.min():<15.1f}x")

# ----------------------------
# Execution
# ----------------------------
if __name__ == "__main__":
    base_dir = "/content/drive/MyDrive/folds"
    for fold in range(1, 6):
        fold_dir = f"{base_dir}/fold_{fold}"
        if os.path.exists(fold_dir):
            print(f"\n{'='*60}")
            print(f"PROCESSING FOLD {fold}")
            dynamic_resample(fold_dir)