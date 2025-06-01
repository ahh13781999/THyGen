import pandas as pd
from pathlib import Path
from sklearn.model_selection import StratifiedKFold, train_test_split
import json

PREDEFINED_LABELS = [
    'reconnaissance', 'resource-development', 'initial-access', 'execution',
    'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
    'discovery', 'lateral-movement', 'collection', 'command-and-control',
    'exfiltration', 'impact'
]

# Create label mappings
label2id = {label: idx for idx, label in enumerate(PREDEFINED_LABELS)}
id2label = {idx: label for label, idx in label2id.items()}

# Save mapping
with open("label_mapping.json", "w") as f:
    json.dump({"label2id": label2id, "id2label": id2label}, f)

def parse_line(line):
    """Parse a line into features and label with fixed column order."""
    feature_order = [
        'log_type', 'event_type', 'pid', 'process', 'ppid', 'parent_process',
        'process_directory', 'registry_path', 'source_ip', 'source_port',
        'source_port_name', 'destination_ip', 'destination_port',
        'destination_port_name', 'file_name', 'operation_type',
        'queried_domain', 'resolved_ip', 'http_method', 'url_path', 'response_code',
        'host_domain', 'redirect_location'
    ]
    
    features = {key: None for key in feature_order}  # Using regular dict
    label = None
    
    pairs = [pair.strip() for pair in line.split(", ")]
    
    for pair in pairs:
        if "=" not in pair:
            continue
        key, value = pair.split("=", 1)
        key = key.strip().strip("'")
        value = value.strip().strip("'")
        
        if key == "mitre_tactic":
            label = value
        elif key in features:
            features[key] = value
            
    return features, label

def load_data(file_path):
    """Load and parse dataset with enforced column order."""
    data = []
    with open(file_path, "r", encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            features, label = parse_line(line)
            features["mitre_tactic"] = label
            data.append(features)
    
    # Explicit column order to ensure consistency
    columns = list(parse_line("")[0].keys()) + ["mitre_tactic"]
    return pd.DataFrame(data, columns=columns)

# ----------------------------
# Stratified K-Fold Split
# ----------------------------
if __name__ == "__main__":
    # 1. Load data
    df = load_data("dataset.csv")
    
    # 2. Shuffle the dataset three times with different seeds
    for i, seed in enumerate([42, 43, 44]):
        df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
    
    # 3. Split features and labels
    X = df.drop("mitre_tactic", axis=1)
    y = df["mitre_tactic"]
    
    # 4. Create test set
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    
    # 5. Prepare directory structure
    base_dir = Path(".")
    (base_dir / "test").mkdir(exist_ok=True)
    for fold in range(1, 6):
        (base_dir / "folds" / f"fold_{fold}").mkdir(parents=True, exist_ok=True)
    
    # 6. Save test set
    X_test.to_csv(base_dir / "test" / "test_features.csv", index=False)
    y_test.to_csv(base_dir / "test" / "test_labels.csv", index=False)
    
    # 7. Generate K-Fold splits
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    for fold, (train_idx, val_idx) in enumerate(skf.split(X_train_val, y_train_val), start=1):
        fold_dir = base_dir / "folds" / f"fold_{fold}"
        X_train_fold, y_train_fold = X_train_val.iloc[train_idx], y_train_val.iloc[train_idx]
        X_val_fold, y_val_fold = X_train_val.iloc[val_idx], y_train_val.iloc[val_idx]
        
        X_train_fold.to_csv(fold_dir / "train_features.csv", index=False)
        y_train_fold.to_csv(fold_dir / "train_labels.csv", index=False)
        X_val_fold.to_csv(fold_dir / "val_features.csv", index=False)
        y_val_fold.to_csv(fold_dir / "val_labels.csv", index=False)
    
    # Print summary
    print(f"Generated 5 stratified folds + test set")
    print(f"Final dataset structure:")
    print(f"- Test set: {len(X_test)} samples")
    print(f"- Train/val per fold: ~{len(X_train_fold)}/~{len(X_val_fold)} samples")