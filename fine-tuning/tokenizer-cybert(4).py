import os
import re
import json
import pandas as pd
import torch
from transformers import AutoTokenizer
from tqdm import tqdm

# ----------------------------
# Configuration
# ----------------------------
TOKENIZER_NAME = "SynamicTechnologies/CYBERT"
MAX_LENGTH = 128
BASE_DIR = "/content/drive/MyDrive/"

# Security Patterns (compiled once for efficiency)
PATTERNS = [
    (re.compile(r'(?i)\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?'), 'UUID'),
    (re.compile(r'(?i)\b[0-9a-f]{32,}\b'), 'HASH'),
    (re.compile(r'(?i)\b[0-9a-f]{16,31}\b'), 'HEX'),
    (re.compile(r'(?i)\b0x[0-9a-f]+\b'), 'HEX')
]

# Fields requiring pattern replacement
MASK_FIELDS = {'process_directory', 'registry_path', 'file_name', 'queried_domain', 'host_domain', 'redirect_location', 'url_path' }

# Label Mapping (single source of truth)
LABEL_MAPPING = {
    'reconnaissance': 0,
    'resource-development': 1,
    'initial-access': 2,
    'execution': 3,
    'persistence': 4,
    'privilege-escalation': 5,
    'defense-evasion': 6,
    'credential-access': 7,
    'discovery': 8,
    'lateral-movement': 9,
    'collection': 10,
    'command-and-control': 11,
    'exfiltration': 12,
    'impact': 13
}

# ----------------------------
# Core Processing Functions
# ----------------------------
def sanitize_value(value):
    if pd.isnull(value):
        return ''
    if not isinstance(value, str):
        value = str(value)
    for pattern, replacement in PATTERNS:
        value = pattern.sub(replacement, value)
    return value

def process_features(df):
    """Handle NaN without breaking integer columns"""
    processed = df.copy()
    
    # Fill NaN only for non-integer columns
    for col in processed.columns:
        if not pd.api.types.is_integer_dtype(processed[col]):
            processed[col] = processed[col].fillna('')
    
    # Apply security masking
    for field in MASK_FIELDS:
        if field in processed.columns:
            processed[field] = processed[field].astype(str).apply(sanitize_value)
    
    return processed

def serialize_row(row):
    """Safer serialization with type checks"""
    fields = [
        'log_type', 'event_type', 'pid', 'process', 'ppid', 'parent_process',
        'process_directory', 'registry_path', 'source_ip', 'source_port',
        'source_port_name', 'destination_ip', 'destination_port',
        'destination_port_name', 'file_name', 'operation_type',
        'queried_domain', 'resolved_ip', 'http_method', 'url_path', 'response_code',
        'host_domain', 'redirect_location'
    ]
    
    parts = []
    for k in fields:
        if k in row and pd.notnull(row[k]):
            value = row[k]
            # Handle integer formatting
            if k in ['pid', 'ppid', 'source_port', 'destination_port', 'response_code']:
                value = int(float(value)) if str(value).replace('.', '', 1).isdigit() else value
            # Skip empty strings
            if isinstance(value, str) and value.strip() == '':
                continue
            parts.append(f"{k}='{value}'")
    return ", ".join(parts)

# ----------------------------
# Tokenization Pipeline
# ----------------------------
def print_tokenization_example(text, tokenizer):
    tokens = tokenizer.tokenize(text)
    token_ids = tokenizer.encode(text, add_special_tokens=True)
    print("\n--- Tokenization Example ---")
    print(f"Original: {text}")
    print(f"Tokens: {tokens}")
    print(f"Decoded: {tokenizer.decode(token_ids)}\n")

def tokenize_dataset(features, labels, tokenizer, desc=""):
    """Full tokenization workflow"""
    invalid_labels = set(labels['mitre_tactic']) - set(LABEL_MAPPING.keys())
    if invalid_labels:
        raise ValueError(f"Unmapped labels detected: {invalid_labels}")
    
    label_ids = [LABEL_MAPPING[label] for label in labels['mitre_tactic']]
    processed_features = process_features(features)
    
    # Print example before batch processing
    example_row = processed_features.iloc[0]
    example_text = serialize_row(example_row)
    print_tokenization_example(example_text, tokenizer)
    
    texts = [serialize_row(row) for _, row in tqdm(
        processed_features.iterrows(),
        desc=f"Serializing {desc}",
        unit=" samples"
    )]
    
    encodings = tokenizer(
        texts,
        max_length=MAX_LENGTH,
        padding='max_length',
        truncation=True,
        return_tensors='pt'
    )
    
    return {
        **encodings,
        'labels': torch.tensor(label_ids),
    }

# ----------------------------
# Main Execution
# ----------------------------
def main():
    # Define dtypes for integer columns
    dtype_mapping = {
        'pid': pd.Int64Dtype(),
        'ppid': pd.Int64Dtype(),
        'source_port': pd.Int64Dtype(),
        'destination_port': pd.Int64Dtype(),
        'response_code': pd.Int64Dtype()
    }
     
    tokenizer = AutoTokenizer.from_pretrained(TOKENIZER_NAME, do_lower_case=True)
    os.makedirs(f"{BASE_DIR}/tokenized-cybert", exist_ok=True)

    with open(f"{BASE_DIR}/tokenized-cybert/label_mapping.json", "w") as f:
      json.dump(LABEL_MAPPING, f)
    
    try:
        # Process test set
        test_features = pd.read_csv(
            f"{BASE_DIR}/test/test_features.csv",
            dtype=dtype_mapping
        )
        test_labels = pd.read_csv(f"{BASE_DIR}/test/test_labels.csv")
        test_data = tokenize_dataset(test_features, test_labels, tokenizer, "test set")
        torch.save(test_data, f"{BASE_DIR}/tokenized-cybert/test.pt")
        
        # Process all folds
        for fold in tqdm(range(1, 6), desc="Processing folds"):
            fold_dir = f"{BASE_DIR}/folds/fold_{fold}"
            
            # Train data
            train_features = pd.read_csv(
                f"{fold_dir}/resampled_train_features.csv",
                dtype=dtype_mapping
            )
            train_labels = pd.read_csv(f"{fold_dir}/resampled_train_labels.csv")
            train_data = tokenize_dataset(train_features, train_labels, tokenizer, f"fold {fold} train")
            torch.save(train_data, f"{BASE_DIR}/tokenized-cybert/fold_{fold}_train.pt")
            
            # Validation data
            val_features = pd.read_csv(
                f"{fold_dir}/val_features.csv",
                dtype=dtype_mapping
            )
            val_labels = pd.read_csv(f"{fold_dir}/val_labels.csv")
            val_data = tokenize_dataset(val_features, val_labels, tokenizer, f"fold {fold} val")
            torch.save(val_data, f"{BASE_DIR}/tokenized-cybert/fold_{fold}_val.pt")
            
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return

if __name__ == "__main__":
    main()
    print(f"\nTokenization complete. Output saved to: {BASE_DIR}/tokenized-cybert/")
    print(f"Label mapping:\n{json.dumps(LABEL_MAPPING, indent=2)}")