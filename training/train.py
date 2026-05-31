"""
Main training script for PowerShell malicious script detector
Includes mixed_malicious dataset in training
"""

import os
import sys
import numpy as np
import pandas as pd
import pickle
from pathlib import Path
from sklearn.model_selection import cross_val_score, train_test_split, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix, accuracy_score,
    precision_score, recall_score, f1_score, roc_auc_score, roc_curve
)
import matplotlib.pyplot as plt
import joblib

# Add training to path
sys.path.insert(0, './training')

from data_loader import PowerShellDataLoader
from feature_extractor import PowerShellFeatureExtractor


def plot_metrics(y_true, y_pred, y_pred_proba, output_dir):
    """Plot evaluation metrics"""
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True)
    
    # Confusion Matrix
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(8, 6))
    plt.imshow(cm, cmap='Blues', interpolation='nearest')
    plt.colorbar()
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    for i in range(2):
        for j in range(2):
            plt.text(j, i, str(cm[i, j]), ha='center', va='center', color='white' if cm[i, j] > cm.max()/2 else 'black')
    plt.tight_layout()
    plt.savefig(output_dir / 'confusion_matrix.png', dpi=100)
    print(f"Saved confusion matrix to {output_dir / 'confusion_matrix.png'}")
    plt.close()
    
    # ROC Curve
    fpr, tpr, _ = roc_curve(y_true, y_pred_proba)
    auc_score = roc_auc_score(y_true, y_pred_proba)
    
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, label=f'ROC curve (AUC = {auc_score:.3f})', linewidth=2)
    plt.plot([0, 1], [0, 1], 'k--', label='Random classifier', linewidth=1)
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve')
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_dir / 'roc_curve.png', dpi=100)
    print(f"Saved ROC curve to {output_dir / 'roc_curve.png'}")
    plt.close()


def main():
    print("PowerShell Malicious Script Detector")
    print("="*60)
    print("Training WITH mixed_malicious dataset included")
    print("="*60)
    
    # Paths
    data_dir = Path('./')
    models_dir = Path('./models')
    output_dir = Path('./output')
    
    models_dir.mkdir(exist_ok=True)
    output_dir.mkdir(exist_ok=True)
    
    # Load data
    print("\n[1/5] Loading data...")
    loader = PowerShellDataLoader(data_dir)
    X, y = loader.load_all_data(include_mixed=True)  # Include mixed scripts!
    loader.get_statistics(X, y)
    
    # Extract features
    print("\n[2/5] Extracting features...")
    X_features, feature_names = loader.extract_features(X)
    
    print(f"Number of features: {len(feature_names)}")
    print("Feature names:", feature_names[:5], "...")
    
    # Split data (80% train, 20% test)
    print("\n[3/5] Splitting data (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X_features, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training set: {X_train.shape[0]} samples")
    print(f"Test set: {X_test.shape[0]} samples")
    print(f"Training set - Malicious: {sum(y_train == 1)}, Benign: {sum(y_train == 0)}")
    print(f"Test set - Malicious: {sum(y_test == 1)}, Benign: {sum(y_test == 0)}")
    
    # Feature scaling
    print("\nScaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Save scaler
    joblib.dump(scaler, models_dir / 'scaler.pkl')
    
    # Train model
    print("\n[4/5] Training Random Forest classifier...")
    print("This may take a few minutes...")
    
    rf_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=30,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        verbose=1,
        class_weight='balanced'
    )
    
    rf_model.fit(X_train_scaled, y_train)
    
    # Save model
    joblib.dump(rf_model, models_dir / 'random_forest_model.pkl')
    print(f"Model saved to {models_dir / 'random_forest_model.pkl'}")
    
    # Cross-validation on training data
    print("\n[5/5] Performing cross-validation...")
    cv_scores = cross_val_score(rf_model, X_train_scaled, y_train, cv=5, scoring='accuracy', n_jobs=-1)
    print(f"Cross-validation scores: {cv_scores}")
    print(f"Mean CV accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
    
    # Test predictions
    print("\nEvaluating on test set...")
    y_pred = rf_model.predict(X_test_scaled)
    y_pred_proba = rf_model.predict_proba(X_test_scaled)[:, 1]
    
    # Metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_pred_proba)
    
    print("\n" + "="*60)
    print("TEST SET RESULTS (with mixed_malicious training)")
    print("="*60)
    print(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-Score:  {f1:.4f}")
    print(f"AUC-ROC:   {auc:.4f}")
    print("="*60)
    
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))
    
    # Feature importance
    print("\nTop 10 Most Important Features:")
    feature_importance = pd.DataFrame({
        'feature': feature_names,
        'importance': rf_model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print(feature_importance.head(10).to_string(index=False))
    feature_importance.to_csv(output_dir / 'feature_importance.csv', index=False)
    
    # Save results
    results = {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'auc': auc,
        'cv_scores': cv_scores.tolist(),
        'cv_mean': cv_scores.mean(),
        'cv_std': cv_scores.std(),
    }
    
    with open(output_dir / 'results.txt', 'w') as f:
        f.write("PowerShell Malicious Script Detection Results\n")
        f.write("(Trained WITH mixed_malicious dataset)\n")
        f.write("="*60 + "\n\n")
        f.write(f"Total training samples: {len(X)}\n")
        f.write(f"  - Malicious (pure + mixed): {sum(y == 1)}\n")
        f.write(f"  - Benign: {sum(y == 0)}\n\n")
        f.write(f"Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)\n")
        f.write(f"Precision: {precision:.4f}\n")
        f.write(f"Recall:    {recall:.4f}\n")
        f.write(f"F1-Score:  {f1:.4f}\n")
        f.write(f"AUC-ROC:   {auc:.4f}\n\n")
        f.write(f"Cross-validation accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})\n")
        f.write(f"Cross-validation scores: {cv_scores.tolist()}\n")
        f.write("\nClassification Report:\n")
        f.write(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))
    
    print(f"\nResults saved to {output_dir / 'results.txt'}")
    
    # Plot metrics
    print("\nGenerating visualizations...")
    plot_metrics(y_test, y_pred, y_pred_proba, output_dir)
    
    print("\n✓ Training complete!")
    print(f"Model saved: {models_dir / 'random_forest_model.pkl'}")
    print(f"Results saved: {output_dir}")


if __name__ == '__main__':
    main()
