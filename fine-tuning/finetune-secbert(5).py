import torch
import numpy as np
from transformers import (
    AutoConfig,
    AutoModelForSequenceClassification,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
    EvalPrediction
)
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    matthews_corrcoef,
    confusion_matrix,
    precision_recall_fscore_support,
    classification_report
)
from torch import nn
from torch.utils.data import Dataset
import os
import json
from tqdm import tqdm
from collections import Counter
import matplotlib.pyplot as plt
import seaborn as sns

os.environ["WANDB_DISABLED"] = "1"  # Disables W&B completely
os.environ["TOKENIZERS_PARALLELISM"] = "false"  # Prevents potential hangs

# Configuration
MODEL_NAME = "jackaduma/SecBERT"
MAX_LENGTH = 128
BATCH_SIZE = 64
LEARNING_RATE = 5e-5
NUM_EPOCHS = 3
NUM_FOLDS = 5
USE_FOCAL_LOSS = True
FOCAL_GAMMA = 2.0
MINORITY_THRESHOLD = 0.3
MINORITY_CLASS_THRESHOLD = 0.055
MINORITY_LR_MULTIPLIER = 1.5

# Paths
TOKENIZED_DATA_DIR = "/content/drive/MyDrive/tokenized-secrobert"
BASE_OUTPUT_DIR = "/content/drive/MyDrive/secrobert-model_output"
CHECKPOINT_DIR = "/content/drive/MyDrive/secrobert-checkpoints"

os.makedirs(BASE_OUTPUT_DIR, exist_ok=True)
os.makedirs(CHECKPOINT_DIR, exist_ok=True)

class CustomTrainer(Trainer):
    def __init__(self, minority_class_ids=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.minority_class_ids = minority_class_ids

    def compute_loss(self, model, inputs, return_outputs=False, **kwargs):
        labels = inputs.pop("labels")
        outputs = model(**inputs)
        logits = outputs.logits
        
        loss_fct = nn.CrossEntropyLoss(reduction='none')
        ce_loss = loss_fct(logits.view(-1, model.config.num_labels), labels.view(-1))
        
        if USE_FOCAL_LOSS:
            pt = torch.exp(-ce_loss)
            if self.minority_class_ids:
                minority_mask = torch.isin(labels, torch.tensor(self.minority_class_ids, device=labels.device))
                gamma = torch.where(minority_mask, FOCAL_GAMMA * 2, FOCAL_GAMMA)
            else:
                gamma = FOCAL_GAMMA
            loss = ((1 - pt) ** gamma * ce_loss).mean()
        else:
            loss = ce_loss.mean()
        
        return (loss, outputs) if return_outputs else loss

    def predict_with_threshold(self, dataset, minority_class_ids=None, minority_threshold=MINORITY_THRESHOLD):
        predictions = self.predict(dataset)
        logits = predictions.predictions
        probs = torch.softmax(torch.tensor(logits), dim=-1).numpy()
        
        adjusted_preds = np.zeros(probs.shape[0], dtype=int)
        for i in range(probs.shape[0]):
            sample_probs = probs[i]
            mask = np.zeros_like(sample_probs, dtype=bool)
            for class_idx in range(len(sample_probs)):
                if minority_class_ids and class_idx in minority_class_ids:
                    threshold = minority_threshold
                else:
                    threshold = 0.5
                if sample_probs[class_idx] >= threshold:
                    mask[class_idx] = True
            candidates = np.where(mask)[0]
            if len(candidates) > 0:
                adjusted_preds[i] = candidates[np.argmax(sample_probs[candidates])]
            else:
                adjusted_preds[i] = np.argmax(sample_probs)
        
        return EvalPrediction(predictions=adjusted_preds, label_ids=predictions.label_ids)

class LogsDataset(Dataset):
    def __init__(self, encodings, labels):
        self.input_ids = encodings['input_ids']
        self.attention_mask = encodings['attention_mask']
        self.labels = labels if isinstance(labels, torch.Tensor) else torch.tensor(labels)
        
    def __len__(self):
        return len(self.labels)
    
    def __getitem__(self, idx):
        return {
            'input_ids': self.input_ids[idx],
            'attention_mask': self.attention_mask[idx],
            'labels': self.labels[idx]
        }

def load_label_mapping():
    with open(os.path.join(TOKENIZED_DATA_DIR, "label_mapping.json"), "r") as f:
        return json.load(f)

def get_class_distribution():
    all_labels = []
    data_path = os.path.join(TOKENIZED_DATA_DIR, "fold_1_train.pt")
    data = torch.load(data_path)
    all_labels.extend(data['labels'].tolist())
    
    class_counts = Counter(all_labels)
    label_mapping = load_label_mapping()
    
    for cls_id in label_mapping.values():
        if cls_id not in class_counts:
            class_counts[cls_id] = 0
            
    return class_counts

def compute_metrics(p: EvalPrediction, label_mapping):
    if len(p.predictions.shape) == 1:
        preds = p.predictions
    else:
        preds = np.argmax(p.predictions, axis=1)
    labels = p.label_ids
    
    accuracy = accuracy_score(labels, preds)
    macro_f1 = f1_score(labels, preds, average='macro')
    weighted_f1 = f1_score(labels, preds, average='weighted')
    mcc = matthews_corrcoef(labels, preds)
    
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, preds, average=None, zero_division=0
    )
    
    cm = confusion_matrix(labels, preds)
    clf_report = classification_report(
        labels, preds,
        target_names=list(label_mapping.keys()),
        output_dict=True
    )
    
    return {
        'accuracy': accuracy,
        'macro_f1': macro_f1,
        'weighted_f1': weighted_f1,
        'mcc': mcc,
        'per_class': {
            'precision': precision.tolist(),
            'recall': recall.tolist(),
            'f1': f1.tolist()
        },
        'confusion_matrix': cm.tolist(),
        'classification_report': clf_report
    }

def plot_confusion_matrix(cm, class_names, output_dir):
    plt.figure(figsize=(12, 10))
    sns.heatmap(cm, annot=True, fmt='d',
                xticklabels=class_names,
                yticklabels=class_names,
                cmap='Blues')
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.savefig(os.path.join(output_dir, 'confusion_matrix.png'))
    plt.close()

def train_and_evaluate_fold(fold_num, label_mapping, minority_class_ids):
    fold_dir = os.path.join(BASE_OUTPUT_DIR, f"fold_{fold_num}")
    os.makedirs(fold_dir, exist_ok=True)
    
    train_data = torch.load(os.path.join(TOKENIZED_DATA_DIR, f"fold_{fold_num}_train.pt"))
    val_data = torch.load(os.path.join(TOKENIZED_DATA_DIR, f"fold_{fold_num}_val.pt"))
    
    train_dataset = LogsDataset(
        {'input_ids': train_data['input_ids'],
         'attention_mask': train_data['attention_mask']},
        train_data['labels']
    )
    val_dataset = LogsDataset(
        {'input_ids': val_data['input_ids'],
         'attention_mask': val_data['attention_mask']},
        val_data['labels']
    )
    
    config = AutoConfig.from_pretrained(
        MODEL_NAME,
        num_labels=len(label_mapping),
        id2label={v: k for k, v in label_mapping.items()},
        label2id=label_mapping
    )
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, config=config)
    
    training_args = TrainingArguments(
        output_dir=fold_dir,
        eval_strategy="epoch",
        save_strategy="epoch",
        learning_rate=LEARNING_RATE,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        num_train_epochs=NUM_EPOCHS,
        weight_decay=0.01,
        warmup_ratio=0.1,
        load_best_model_at_end=True,
        metric_for_best_model="macro_f1",
        greater_is_better=True,
        logging_dir=os.path.join(fold_dir, 'logs'),
        logging_steps=100,
        save_total_limit=2,
        report_to="none",
        gradient_accumulation_steps=2,
        disable_tqdm=True,
        max_grad_norm=1.0,
        fp16=True,
        dataloader_num_workers=2,
        dataloader_pin_memory=True,
    )
    
    trainer = CustomTrainer(
        minority_class_ids=minority_class_ids,
        args=training_args,
        model=model,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=lambda p: compute_metrics(p, label_mapping)
    )
    
    print(f"\n{'='*40}")
    print(f"Training Fold {fold_num}/{NUM_FOLDS}")
    trainer.train()
    trainer.save_model(fold_dir)
    
    val_results = trainer.evaluate()
    plot_confusion_matrix(
        np.array(val_results['eval_confusion_matrix']),
        list(label_mapping.keys()),
        fold_dir
    )
    
    with open(os.path.join(fold_dir, 'metrics.json'), 'w') as f:
        json.dump(val_results, f)
    
    return val_results

def evaluate_test_set(fold_num, label_mapping, minority_class_ids):
    fold_dir = os.path.join(BASE_OUTPUT_DIR, f"fold_{fold_num}")
    model = AutoModelForSequenceClassification.from_pretrained(fold_dir)
    test_data = torch.load(os.path.join(TOKENIZED_DATA_DIR, "test.pt"))
    
    test_dataset = LogsDataset(
        {'input_ids': test_data['input_ids'],
         'attention_mask': test_data['attention_mask']},
        test_data['labels']
    )
    
    trainer = CustomTrainer(
        model=model,
        minority_class_ids=minority_class_ids,
        compute_metrics=lambda p: compute_metrics(p, label_mapping)
    )
    
    test_results = trainer.predict_with_threshold(
        test_dataset,
        minority_class_ids=minority_class_ids,
        minority_threshold=MINORITY_THRESHOLD
    )
    test_metrics = compute_metrics(test_results, label_mapping)
    
    with open(os.path.join(fold_dir, 'test_metrics.json'), 'w') as f:
        json.dump(test_metrics, f)
    
    return test_metrics

def main():
    label_mapping = load_label_mapping()
    print("Label Mapping:", label_mapping)
    
    class_counts = get_class_distribution()
    total_samples = sum(class_counts.values())
    minority_class_ids = [
        cls_id for cls_id, count in class_counts.items()
        if (count / total_samples) < MINORITY_CLASS_THRESHOLD
    ]
    
    print("Class Distribution:", class_counts)
    print("Minority Classes (IDs):", minority_class_ids)
    
    fold_results = {}
    for fold_num in tqdm(range(1, NUM_FOLDS+1), desc="Training Folds"):
        try:
            fold_results[f'fold_{fold_num}'] = train_and_evaluate_fold(
                fold_num, label_mapping, minority_class_ids
            )
        except Exception as e:
            print(f"Error in fold {fold_num}: {str(e)}")
            continue
    
    best_fold = max(fold_results.items(), key=lambda x: x[1]['eval_macro_f1'])[0]
    test_results = evaluate_test_set(int(best_fold.split('_')[1]), label_mapping, minority_class_ids)
    
    final_report = {
        'config': {
            'model': MODEL_NAME,
            'batch_size': BATCH_SIZE,
            'learning_rate': LEARNING_RATE,
            'epochs': NUM_EPOCHS,
            'focal_loss': USE_FOCAL_LOSS,
            'minority_threshold': MINORITY_THRESHOLD
        },
        'cross_validation': fold_results,
        'best_fold': best_fold,
        'test_results': test_results
    }
    
    with open(os.path.join(BASE_OUTPUT_DIR, 'final_report.json'), 'w') as f:
        json.dump(final_report, f, indent=2)
    
    print("\nTraining Complete!")
    print(f"Best Fold: {best_fold}")
    print(f"Test Macro F1: {test_results['macro_f1']:.4f}")
    print(f"Test MCC: {test_results['mcc']:.4f}")

if __name__ == "__main__":
    main()