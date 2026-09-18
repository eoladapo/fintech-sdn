#!/usr/bin/env python3
"""
Train Random Forest Classifier for SDN DDoS Detection in FinTech Networks
Features: packet_count, byte_count, duration_sec, packet_rate, byte_rate, bytes_per_packet
Target: label (0 = Benign, 1 = Malicious/DDoS)
"""

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

DATASET_PATH = os.path.expanduser('~/fintech-sdn/data/flow_dataset.csv')
MODEL_DIR = os.path.expanduser('~/fintech-sdn/models')
MODEL_PATH = os.path.join(MODEL_DIR, 'ddos_rf_model.pkl')

os.makedirs(MODEL_DIR, exist_ok=True)

print("[*] Loading flow dataset...")
df = pd.read_csv(DATASET_PATH)

# Clean invalid values
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# Select behavioral features
features = [
    'packet_count', 
    'byte_count', 
    'duration_sec', 
    'packet_rate', 
    'byte_rate', 
    'bytes_per_packet'
]

X = df[features]
y = df['label']

print(f"[*] Total valid samples: {len(df)}")
print(f"    - Benign (0): {(y == 0).sum()}")
print(f"    - DDoS   (1): {(y == 1).sum()}\n")

# Split with stratification to preserve class ratios
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

print("[*] Training Random Forest Classifier...")
clf = RandomForestClassifier(
    n_estimators=100, 
    max_depth=12, 
    random_state=42,
    n_jobs=-1
)
clf.fit(X_train, y_train)

# Model evaluation
y_pred = clf.predict(X_test)
acc = accuracy_score(y_test, y_pred)
conf_matrix = confusion_matrix(y_test, y_pred)

print(f"\n[+] Training Complete!")
print(f"[+] Model Accuracy: {acc * 100:.2f}%\n")
print("Confusion Matrix:")
print(conf_matrix)
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Benign', 'DDoS flood']))

# Save serialized model
joblib.dump(clf, MODEL_PATH)
print(f"\n[+] Saved model binary to: {MODEL_PATH}")