#!/usr/bin/env python3
"""
Unified model trainer for Solana security analysis.
Combines features and approaches from both training scripts.
"""

import os
import joblib
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb
import lightgbm as lgb
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import StackingClassifier
from imblearn.pipeline import Pipeline as ImbPipeline
from imblearn.over_sampling import SMOTE
from collections import Counter

# Configuration
DATA_FILE = "solana_dataset_enhanced.csv"
MODEL_DIR = "models"
RANDOM_STATE = 42

class SolanaSecurityModel:
    def __init__(self):
        self.setup_paths()
        self.encoders = {}
        self.models = {}
        
    def setup_paths(self):
        """Setup model and data paths"""
        os.makedirs(MODEL_DIR, exist_ok=True)
        if not os.path.exists(DATA_FILE):
            raise FileNotFoundError(f"Enhanced dataset '{DATA_FILE}' not found. Run process_dataset.py first.")
    
    def create_stacked_model(self):
        """Create a stacked model combining multiple classifiers"""
        # Base models
        xgb_model = xgb.XGBClassifier(
            use_label_encoder=False,
            eval_metric='logloss',
            random_state=RANDOM_STATE
        )
        lgb_model = lgb.LGBMClassifier(random_state=RANDOM_STATE)
        rf_model = RandomForestClassifier(
            n_estimators=200,
            class_weight='balanced',
            random_state=RANDOM_STATE
        )
        
        # Meta classifier
        meta_clf = LogisticRegression(max_iter=1000)
        
        # Stack the models
        return StackingClassifier(
            estimators=[
                ('xgb', xgb_model),
                ('lgb', lgb_model),
                ('rf', rf_model)
            ],
            final_estimator=meta_clf,
            cv=5
        )
    
    def load_and_preprocess_data(self):
        """Load and preprocess the enhanced dataset"""
        print("Loading and preprocessing data...")
        df = pd.read_csv(DATA_FILE)
        
        # Basic features
        basic_features = [
            'ContractType', 'LinesOfCode', 'NumFunctionCalls',
            'NumLoops', 'NumIfs', 'NumUnsafeBlocks', 'NumAnchorMacros',
            'NumPDAs', 'NumCPICalls', 'NumStateAccounts', 'NumTokenAccounts',
            'ComplexityScore', 'SecurityScore'
        ]
        
        # Security pattern features
        security_features = [
            'num_signer_checks', 'num_owner_checks', 'num_pda_checks',
            'num_bump_validations', 'num_account_checks', 'num_cpi_calls',
            'num_program_checks', 'num_require_asserts', 'num_anchor_constraints',
            'num_error_handlers', 'num_custom_errors', 'num_unsafe_blocks',
            'num_mut_refs', 'num_raw_pointers', 'num_transfers', 'num_token_ops'
        ]
        
        # Risk assessment features
        risk_features = [
            'has_proper_validation', 'has_proper_error_handling',
            'is_high_risk', 'is_unsafe', 'Impact', 'Likelihood', 'RiskScore'
        ]
        
        # Combine all features
        feature_cols = basic_features + security_features + risk_features
        
        # Prepare features
        X = df[feature_cols].copy()
        
        # Encode categorical features
        cat_features = ['ContractType']
        for col in cat_features:
            if col in X.columns:
                self.encoders[col] = LabelEncoder()
                X[col] = self.encoders[col].fit_transform(X[col])
                joblib.dump(self.encoders[col], f"{MODEL_DIR}/{col}_encoder.pkl")
        
        # Prepare labels
        self.encoders['vuln'] = LabelEncoder()
        y_vuln = self.encoders['vuln'].fit_transform(df['VulnCategory'])
        joblib.dump(self.encoders['vuln'], f"{MODEL_DIR}/vulnerability_encoder.pkl")
        
        self.encoders['severity'] = LabelEncoder()
        y_sev = self.encoders['severity'].fit_transform(df['Severity'])
        joblib.dump(self.encoders['severity'], f"{MODEL_DIR}/severity_encoder.pkl")
        
        return X, y_vuln, y_sev
    
    def create_preprocessing_pipeline(self, min_samples):
        """Create preprocessing pipeline with optional SMOTE"""
        steps = [('scaler', StandardScaler())]
        
        # Only apply SMOTE if we have enough samples
        if min_samples >= 5:
            steps.append(('smote', SMOTE(random_state=RANDOM_STATE, k_neighbors=min(5, min_samples-1))))
            
        return ImbPipeline(steps)
    
    def train_and_evaluate(self, X, y, model_name, pipeline):
        """Train and evaluate a model"""
        print(f"\nTraining {model_name} model...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
        )
        
        # Create and train model
        model = self.create_stacked_model()
        
        # Process training data
        X_train_scaled = pipeline.named_steps['scaler'].fit_transform(X_train)
        X_test_scaled = pipeline.named_steps['scaler'].transform(X_test)
        
        # Apply SMOTE if available
        if 'smote' in pipeline.named_steps:
            print("Applying SMOTE oversampling...")
            X_train_processed, y_train_processed = pipeline.named_steps['smote'].fit_resample(X_train_scaled, y_train)
        else:
            print("Skipping SMOTE due to small sample size...")
            X_train_processed, y_train_processed = X_train_scaled, y_train
        
        # Train model
        model.fit(X_train_processed, y_train_processed)
        
        # Save model and preprocessor
        joblib.dump(model, f"{MODEL_DIR}/{model_name}_model.pkl")
        joblib.dump(pipeline.named_steps['scaler'], f"{MODEL_DIR}/{model_name}_scaler.pkl")
        
        # Evaluate
        y_pred = model.predict(X_test_scaled)
        print(f"\n{model_name} Classification Report:")
        print(classification_report(y_test, y_pred))
        
        # Print class distribution
        print("\nClass distribution:")
        print(pd.Series(y_train_processed).value_counts())
        
        return model
    
    def train(self):
        """Train vulnerability and severity models"""
        # Load and preprocess data
        X, y_vuln, y_sev = self.load_and_preprocess_data()
        
        # Get min samples per class
        min_vuln_samples = min(Counter(y_vuln).values())
        min_sev_samples = min(Counter(y_sev).values())
        
        print(f"\nMinimum samples per class:")
        print(f"Vulnerability classes: {min_vuln_samples}")
        print(f"Severity classes: {min_sev_samples}")
        
        # Create preprocessing pipelines
        vuln_pipeline = self.create_preprocessing_pipeline(min_vuln_samples)
        sev_pipeline = self.create_preprocessing_pipeline(min_sev_samples)
        
        # Train vulnerability model
        self.models['vulnerability'] = self.train_and_evaluate(X, y_vuln, 'vulnerability', vuln_pipeline)
        
        # Train severity model
        self.models['severity'] = self.train_and_evaluate(X, y_sev, 'severity', sev_pipeline)
        
        print("\n✅ Training complete! Models saved in 'models' directory.")

def main():
    trainer = SolanaSecurityModel()
    trainer.train()

if __name__ == "__main__":
    main()
