"""
DDoS Detection Model Training
Trains Random Forest classifier for attack detection
"""

import pandas as pd
import numpy as np
import json
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import pickle
import json
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')

import os

class DDOSDetectionModel:
    """DDoS Detection Model Trainer"""
    
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_names = [
            'pps', 'bps', 'duration', 'tcp_ratio', 'udp_ratio', 'icmp_ratio'
        ]
        self.base_dir = os.path.dirname(os.path.abspath(__file__))

        
    def generate_dataset(self, n_samples=50000):
        """Generate realistic training dataset"""
        np.random.seed(42)
        
        print(f"Generating {n_samples} samples...")
        
        # Normal traffic patterns
        normal_data = {
            'pps': np.random.normal(0.5, 0.2, n_samples//2),
            'bps': np.random.normal(0.2, 0.1, n_samples//2),
            'duration': np.random.normal(0.5, 0.2, n_samples//2),
            'tcp_ratio': np.random.normal(0.8, 0.1, n_samples//2),
            'udp_ratio': np.random.normal(0.1, 0.05, n_samples//2),
            'icmp_ratio': np.random.normal(0.1, 0.05, n_samples//2),
            'label': [0] * (n_samples//2)  # Normal
        }
        
        # Attack traffic patterns
        attack_data = {
            'pps': np.random.normal(8.0, 3.0, n_samples//2),
            'bps': np.random.normal(3.0, 1.5, n_samples//2),
            'duration': np.random.normal(0.1, 0.05, n_samples//2),
            'tcp_ratio': np.random.normal(0.9, 0.05, n_samples//2),
            'udp_ratio': np.random.normal(0.05, 0.02, n_samples//2),
            'icmp_ratio': np.random.normal(0.05, 0.02, n_samples//2),
            'label': [1] * (n_samples//2)  # Attack
        }
        
        # Combine datasets
        normal_df = pd.DataFrame(normal_data)
        attack_df = pd.DataFrame(attack_data)
        df = pd.concat([normal_df, attack_df], ignore_index=True)
        
        # Shuffle
        df = df.sample(frac=1).reset_index(drop=True)
        
        print(f"✅ Generated {len(df)} samples")
        print(f"   Normal: {len(df[df['label']==0])}")
        print(f"   Attack: {len(df[df['label']==1])}")
        return df

    def train_model(self, df):
        """Train Random Forest classifier"""
        print("\n🤖 Training DDoS Detection Model...")
        
        # Prepare features and labels
        X = df[self.feature_names]
        y = df['label']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        
        # Scale features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train Random Forest
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]
        
        print("\n" + "="*60)
        print("MODEL PERFORMANCE METRICS")
        print("="*60)
        
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))
        
        print("\nConfusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        print(cm)
        
        # Cross-validation
        cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=5)
        print(f"\nCross-validation Scores: {cv_scores}")
        print(f"Mean CV Score: {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")
        
        # ROC-AUC
        roc_auc = roc_auc_score(y_test, y_pred_proba)
        print(f"\nROC-AUC Score: {roc_auc:.4f}")
        
        # Feature importance
        importances = self.model.feature_importances_
        print("\nFeature Importance:")
        for name, imp in zip(self.feature_names, importances):
            print(f"  {name}: {imp:.3f}")

        # Save model and scaler
        model_path = os.path.join(self.base_dir, 'model.pkl')
        scaler_path = os.path.join(self.base_dir, 'scaler.pkl')
        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)
        joblib.dump(self.scaler, scaler_path)

        print(f"\n✅ Model saved as '{model_path}'")
        print(f"✅ Scaler saved as '{scaler_path}'")

        # ---- Export real metrics to JSON for the report generator ---- #
        # (Nothing here is hardcoded -- every value below is read directly
        # from the sklearn objects computed above from your actual run.)
        cm_list = cm.tolist()  # [[TN, FP], [FN, TP]]
        tn, fp, fn, tp = cm_list[0][0], cm_list[0][1], cm_list[1][0], cm_list[1][1]
        total = tn + fp + fn + tp
        report_dict = classification_report(y_test, y_pred, target_names=['Normal', 'Attack'], output_dict=True)

        metrics_export = {
            "n_train_samples": int(len(X_train)),
            "n_test_samples": int(len(X_test)),
            "accuracy_percent": round(100 * (tn + tp) / total, 4) if total else None,
            "precision_percent": round(100 * tp / (tp + fp), 4) if (tp + fp) else None,
            "recall_percent": round(100 * tp / (tp + fn), 4) if (tp + fn) else None,
            "roc_auc": round(float(roc_auc), 4),
            "confusion_matrix": {
                "true_normal": tn, "false_positive": fp,
                "false_negative": fn, "true_attack": tp,
            },
            "cross_validation": {
                "scores": [round(float(s), 4) for s in cv_scores],
                "mean": round(float(cv_scores.mean()), 4),
                "std": round(float(cv_scores.std()), 4),
            },
            "feature_importance": {
                name: round(float(imp), 4)
                for name, imp in zip(self.feature_names, importances)
            },
            "hyperparameters": {
                "n_estimators": self.model.n_estimators,
                "max_depth": self.model.max_depth,
                "min_samples_split": self.model.min_samples_split,
                "min_samples_leaf": self.model.min_samples_leaf,
                "random_state": self.model.random_state,
                "class_weight": str(self.model.class_weight),
            },
        }
        metrics_path = os.path.join(self.base_dir, 'model_metrics.json')
        with open(metrics_path, 'w') as f:
            json.dump(metrics_export, f, indent=2)
        print(f"✅ Real metrics exported to '{metrics_path}' (used by generate_results_report.py)")

        # Save real metrics to JSON for the report generator -- every value
        # here comes directly from the sklearn evaluation above, nothing
        # hardcoded.
        tn, fp, fn, tp = cm.ravel()
        model_metrics = {
            'confusion_matrix': {
                'true_negative': int(tn), 'false_positive': int(fp),
                'false_negative': int(fn), 'true_positive': int(tp),
                'n_test_samples': int(len(y_test)),
            },
            'accuracy_percent': round(100.0 * (tn + tp) / len(y_test), 2),
            'precision_percent': round(100.0 * tp / (tp + fp), 2) if (tp + fp) else None,
            'recall_percent': round(100.0 * tp / (tp + fn), 2) if (tp + fn) else None,
            'roc_auc': round(float(roc_auc), 4),
            'cv_scores_mean': round(float(cv_scores.mean()), 4),
            'cv_scores_std': round(float(cv_scores.std()), 4),
            'feature_importance': {name: round(float(imp), 4)
                                    for name, imp in zip(self.feature_names, importances)},
        }
        metrics_path = os.path.join(self.base_dir, 'model_metrics.json')
        with open(metrics_path, 'w') as f:
            json.dump(model_metrics, f, indent=2)
        print(f"✅ Model metrics saved as '{metrics_path}' (used by generate_results_report.py)")

        return self.model, self.scaler, X_test, y_test, y_pred, y_pred_proba

    def plot_results(self, X_test, y_test, y_pred, y_pred_proba):
        """Generate performance plots"""
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        
        # 1. Confusion Matrix
        cm = confusion_matrix(y_test, y_pred)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[0,0],
                   xticklabels=['Normal', 'Attack'],
                   yticklabels=['Normal', 'Attack'])
        axes[0,0].set_title('Confusion Matrix', fontsize=12, weight='bold')
        axes[0,0].set_ylabel('Actual')
        axes[0,0].set_xlabel('Predicted')
        
        # 2. Feature Importance
        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1]
        axes[0,1].barh(range(len(indices)), importances[indices], color='skyblue')
        axes[0,1].set_yticks(range(len(indices)))
        axes[0,1].set_yticklabels([self.feature_names[i] for i in indices])
        axes[0,1].set_xlabel('Importance')
        axes[0,1].set_title('Feature Importance', fontsize=12, weight='bold')
        
        # 3. ROC Curve
        from sklearn.metrics import roc_curve
        fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
        axes[1,0].plot(fpr, tpr, label=f'ROC (AUC = {roc_auc_score(y_test, y_pred_proba):.3f})')
        axes[1,0].plot([0, 1], [0, 1], 'k--')
        axes[1,0].set_xlabel('False Positive Rate')
        axes[1,0].set_ylabel('True Positive Rate')
        axes[1,0].set_title('ROC Curve', fontsize=12, weight='bold')
        axes[1,0].legend()
        axes[1,0].grid(True, alpha=0.3)
        
        # 4. Distribution of probabilities
        axes[1,1].hist(y_pred_proba[y_test==0], bins=50, alpha=0.5, label='Normal', color='green')
        axes[1,1].hist(y_pred_proba[y_test==1], bins=50, alpha=0.5, label='Attack', color='red')
        axes[1,1].set_xlabel('Predicted Probability')
        axes[1,1].set_ylabel('Frequency')
        axes[1,1].set_title('Prediction Confidence Distribution', fontsize=12, weight='bold')
        axes[1,1].legend()
        axes[1,1].grid(True, alpha=0.3)
        
        plt.suptitle('DDoS Detection Model Performance', fontsize=14, weight='bold')
        plt.tight_layout()
        plt.savefig('model_performance.png', dpi=300, bbox_inches='tight')
        plt.show()

    def predict_attack(self, features):
        """Predict if traffic is attack"""
        if self.model is None:
            print("⚠️ Model not loaded!")
            return None
        
        features_scaled = self.scaler.transform([features])
        prediction = self.model.predict(features_scaled)
        probability = self.model.predict_proba(features_scaled)[0][1]
        
        return {
            'is_attack': bool(prediction[0]),
            'confidence': probability
        }

def main():
    """Main training function"""
    print("="*60)
    print("DDoS DETECTION MODEL TRAINING")
    print("="*60)
    
    # Initialize trainer
    trainer = DDOSDetectionModel()
    
    # Generate dataset
    df = trainer.generate_dataset(50000)
    
    # Train model
    model, scaler, X_test, y_test, y_pred, y_pred_proba = trainer.train_model(df)
    
    # Plot results
    trainer.plot_results(X_test, y_test, y_pred, y_pred_proba)
    
    # Test with samples
    print("\n" + "="*60)
    print("SAMPLE PREDICTIONS")
    print("="*60)
    
    # Normal traffic sample
    normal_sample = [500, 2000000, 40, 0.6, 10, 0.05]
    result = trainer.predict_attack(normal_sample)
    print(f"\nNormal Traffic:")
    print(f"  Features: {normal_sample}")
    print(f"  Prediction: {'NORMAL' if not result['is_attack'] else 'ATTACK'}")
    print(f"  Confidence: {result['confidence']:.2%}")
    
    # Attack traffic sample
    attack_sample = [10000, 25000000, 150, 0.95, 2, 0.001]
    result = trainer.predict_attack(attack_sample)
    print(f"\nAttack Traffic:")
    print(f"  Features: {attack_sample}")
    print(f"  Prediction: {'ATTACK' if result['is_attack'] else 'NORMAL'}")
    print(f"  Confidence: {result['confidence']:.2%}")
    
    print("\n✅ Training complete!")

if __name__ == '__main__':
    main()
