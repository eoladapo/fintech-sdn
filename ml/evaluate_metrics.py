#!/usr/bin/env python3
"""
Performance Evaluation and Metric Plotting for SDN DDoS Mitigation
Generates Confusion Matrix, ROC Curve, and Feature Importance charts.
"""

import os
import joblib
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, roc_curve, auc

DATASET_PATH = os.path.expanduser('~/fintech-sdn/data/flow_dataset.csv')
MODEL_PATH = os.path.expanduser('~/fintech-sdn/models/ddos_rf_model.pkl')
OUTPUT_DIR = os.path.expanduser('~/fintech-sdn/data/plots')

os.makedirs(OUTPUT_DIR, exist_ok=True)

df = pd.read_csv(DATASET_PATH)
df.dropna(inplace=True)

features = ['packet_count', 'byte_count', 'duration_sec', 'packet_rate', 'byte_rate', 'bytes_per_packet']
X = df[features]
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
model = joblib.load(MODEL_PATH)
y_pred = model.predict(X_test)
y_proba = model.predict_proba(X_test)[:, 1]

# 1. Confusion Matrix Plot
fig, ax = plt.subplots(figsize=(6, 5))
cm = confusion_matrix(y_test, y_pred)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=['Benign', 'DDoS Flood'])
disp.plot(cmap=plt.cm.Blues, ax=ax)
plt.title("SDN Flow Classification: Confusion Matrix")
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, 'confusion_matrix.png'), dpi=300)
plt.close()

# 2. ROC Curve Plot
fpr, tpr, _ = roc_curve(y_test, y_proba)
roc_auc = auc(fpr, tpr)

plt.figure(figsize=(6, 5))
plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.3f})')
plt.plot([0, 1], [0, 1], color='navy', lw=1.5, linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver Operating Characteristic (ROC)')
plt.legend(loc="lower right")
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, 'roc_curve.png'), dpi=300)
plt.close()

# 3. Feature Importance Plot
importances = model.feature_importances_
feat_df = pd.DataFrame({'Feature': features, 'Importance': importances}).sort_values('Importance', ascending=True)

plt.figure(figsize=(7, 4))
plt.barh(feat_df['Feature'], feat_df['Importance'], color='#1f77b4')
plt.title('Random Forest Feature Importance Analysis')
plt.xlabel('Gini Importance')
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, 'feature_importance.png'), dpi=300)
plt.close()

print(f"[+] All evaluation plots generated successfully in: {OUTPUT_DIR}")