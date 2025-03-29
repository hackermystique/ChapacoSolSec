#!/usr/bin/env python3
"""
Unified model trainer for Solana security analysis.
Combines features and approaches from both training scripts.
"""

import os
import joblib
import pandas as pd
import logging
from typing import Tuple, Dict, Any, List
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
from functools import lru_cache

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/model_training.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
DATA_FILE = "solana_dataset_enhanced.csv"
MODEL_DIR = "models"
RANDOM_STATE = 42

class SolanaSecurityModel:
    """A class for training and managing Solana security analysis models."""
    
    def __init__(self):
        """Initialize the SolanaSecurityModel with necessary setup."""
        self.setup_paths()
        self.encoders = {}
        self.models = {}
        
    def setup_paths(self) -> None:
        """Setup model and data paths, creating necessary directories."""
        try:
            os.makedirs(MODEL_DIR, exist_ok=True)
            if not os.path.exists(DATA_FILE):
                raise FileNotFoundError(f"Enhanced dataset '{DATA_FILE}' not found. Run process_dataset.py first.")
            logger.info(f"Successfully set up paths. Model directory: {MODEL_DIR}")
        except Exception as e:
            logger.error(f"Error setting up paths: {str(e)}")
            raise
    
    @lru_cache(maxsize=1)
    def create_stacked_model(self) -> StackingClassifier:
        """
        Create a stacked model combining multiple classifiers.
        
        Returns:
            StackingClassifier: A stacked model combining XGBoost, LightGBM, and Random Forest.
        """
        try:
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
        except Exception as e:
            logger.error(f"Error creating stacked model: {str(e)}")
            raise
    
    def load_and_preprocess_data(self) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
        """
        Load and preprocess the enhanced dataset.
        
        Returns:
            Tuple[pd.DataFrame, pd.Series, pd.Series]: Features and labels for vulnerability and severity.
            
        Raises:
            FileNotFoundError: If the dataset file is not found.
            ValueError: If the dataset is empty or invalid.
        """
        logger.info("Loading and preprocessing data...")
        try:
            df = pd.read_csv(DATA_FILE)
            if df.empty:
                raise ValueError("Dataset is empty")
            
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
                'is_high_risk', 'is_unsafe'
            ]
            
            # Combine all features
            feature_cols = basic_features + security_features + risk_features
            
            # Prepare features
            X = df[basic_features].copy()
            
            # Encode categorical features
            cat_features = ['ContractType']
            for col in cat_features:
                if col in X.columns:
                    self.encoders[col] = LabelEncoder()
                    X[col] = self.encoders[col].fit_transform(X[col])
                    self._save_encoder(col)
            
            # Prepare labels
            self.encoders['vuln'] = LabelEncoder()
            y_vuln = self.encoders['vuln'].fit_transform(df['VulnCategory'])
            self._save_encoder('vuln')
            
            self.encoders['severity'] = LabelEncoder()
            y_sev = self.encoders['severity'].fit_transform(df['Severity'])
            self._save_encoder('severity')
            
            logger.info("Data preprocessing completed successfully")
            return X, y_vuln, y_sev
            
        except Exception as e:
            logger.error(f"Error in data preprocessing: {str(e)}")
            raise
    
    def _save_encoder(self, encoder_name: str) -> None:
        """
        Save an encoder to disk.
        
        Args:
            encoder_name: Name of the encoder to save.
        """
        try:
            encoder_path = f"{MODEL_DIR}/{encoder_name}_encoder.pkl"
            joblib.dump(self.encoders[encoder_name], encoder_path)
            logger.debug(f"Saved encoder {encoder_name} to {encoder_path}")
        except Exception as e:
            logger.error(f"Error saving encoder {encoder_name}: {str(e)}")
            raise
    
    def create_preprocessing_pipeline(self, min_samples: int) -> ImbPipeline:
        """
        Create preprocessing pipeline with optional SMOTE.
        
        Args:
            min_samples: Minimum number of samples required for SMOTE.
            
        Returns:
            ImbPipeline: A pipeline containing scaler and optional SMOTE.
        """
        steps = [('scaler', StandardScaler())]
        
        if min_samples >= 5:
            steps.append(('smote', SMOTE(random_state=RANDOM_STATE, k_neighbors=min(5, min_samples-1))))
            logger.info("Added SMOTE to preprocessing pipeline")
            
        return ImbPipeline(steps)
    
    def train_and_evaluate(self, X: pd.DataFrame, y: pd.Series, model_name: str, pipeline: ImbPipeline) -> Any:
        """
        Train and evaluate a model.
        
        Args:
            X: Feature matrix.
            y: Target labels.
            model_name: Name of the model being trained.
            pipeline: Preprocessing pipeline.
            
        Returns:
            Any: Trained model.
        """
        logger.info(f"Training {model_name} model...")
        try:
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
                logger.info("Applying SMOTE oversampling...")
                X_train_processed, y_train_processed = pipeline.named_steps['smote'].fit_resample(X_train_scaled, y_train)
            else:
                logger.info("Skipping SMOTE due to small sample size...")
                X_train_processed, y_train_processed = X_train_scaled, y_train
            
            # Train model
            model.fit(X_train_processed, y_train_processed)
            
            # Save model and preprocessor
            self._save_model_and_preprocessor(model, pipeline, model_name)
            
            # Evaluate
            y_pred = model.predict(X_test_scaled)
            logger.info(f"\n{model_name} Classification Report:")
            logger.info(classification_report(y_test, y_pred))
            
            # Print class distribution
            logger.info("\nClass distribution:")
            logger.info(pd.Series(y_train_processed).value_counts())
            
            return model
            
        except Exception as e:
            logger.error(f"Error in model training and evaluation: {str(e)}")
            raise
    
    def _save_model_and_preprocessor(self, model: Any, pipeline: ImbPipeline, model_name: str) -> None:
        """
        Save model and preprocessor to disk.
        
        Args:
            model: Trained model to save.
            pipeline: Preprocessing pipeline.
            model_name: Name of the model.
        """
        try:
            model_path = f"{MODEL_DIR}/{model_name}_model.pkl"
            scaler_path = f"{MODEL_DIR}/{model_name}_scaler.pkl"
            
            joblib.dump(model, model_path)
            joblib.dump(pipeline.named_steps['scaler'], scaler_path)
            
            logger.debug(f"Saved model and preprocessor for {model_name}")
        except Exception as e:
            logger.error(f"Error saving model and preprocessor: {str(e)}")
            raise
    
    def train(self) -> None:
        """Train vulnerability and severity models."""
        try:
            # Load and preprocess data
            X, y_vuln, y_sev = self.load_and_preprocess_data()
            
            # Get min samples per class
            min_vuln_samples = min(Counter(y_vuln).values())
            min_sev_samples = min(Counter(y_sev).values())
            
            logger.info(f"\nMinimum samples per class:")
            logger.info(f"Vulnerability classes: {min_vuln_samples}")
            logger.info(f"Severity classes: {min_sev_samples}")
            
            # Create preprocessing pipelines
            vuln_pipeline = self.create_preprocessing_pipeline(min_vuln_samples)
            sev_pipeline = self.create_preprocessing_pipeline(min_sev_samples)
            
            # Train vulnerability model
            self.models['vulnerability'] = self.train_and_evaluate(X, y_vuln, 'vulnerability', vuln_pipeline)
            
            # Train severity model
            self.models['severity'] = self.train_and_evaluate(X, y_sev, 'severity', sev_pipeline)
            
            logger.info("\n✅ Training complete! Models saved in 'models' directory.")
            
        except Exception as e:
            logger.error(f"Error in training process: {str(e)}")
            raise

def main():
    """Main entry point for the model training script."""
    try:
        trainer = SolanaSecurityModel()
        trainer.train()
    except Exception as e:
        logger.error(f"Fatal error in main: {str(e)}")
        raise

if __name__ == "__main__":
    main()
