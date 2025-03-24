#!/usr/bin/env python3
"""
Script to process and enhance the Solana security analysis dataset.
Adds advanced features and improves data quality for better vulnerability detection.
"""

import pandas as pd
import numpy as np
import re
from typing import Dict, List
from dataclasses import dataclass
from pathlib import Path

@dataclass
class VulnerabilityInfo:
    category: str
    owasp_id: str
    severity: str
    impact: float  # 0-10 scale
    likelihood: float  # 0-10 scale

class SolanaDatasetProcessor:
    def __init__(self, input_file: str):
        self.input_file = input_file
        self.df = None
        self.setup_mappings()

    def setup_mappings(self):
        # Enhanced vulnerability mappings with more granular categories
        self.vuln_mapping = {
            # Critical vulnerabilities
            'Missing Signer Check': 'Unauthorized Access',
            'Unchecked Owner': 'Account Spoofing',
            'Unchecked CPI': 'Malicious CPI',
            'Missing System Account Check': 'System Account Abuse',
            'Unauthorized Debit': 'Unauthorized Transfer',
            
            # High severity
            'Missing PDA Check': 'PDA Validation',
            'Account Initialized Check': 'Account Initialization',
            'State Account': 'State Management',
            'Token Account': 'Token Security',
            'Constraint Validation': 'Input Validation',
            
            # Memory/safety issues
            'Arithmetic Overflow': 'Integer Overflow',
            'Integer Overflows and Underflows': 'Integer Overflow',
            'Panic Due to Division by Zero': 'Runtime Safety',
            'UnsafeAnchor1': 'Unsafe Code',
            
            # Concurrency/state
            'Data Race': 'Race Condition',
            'Concurrent State Manipulation': 'Race Condition',
            'Reentrancy': 'Reentrancy',
            
            # Other
            'Serialization': 'Data Integrity',
            'Lack of Error Handling': 'Error Handling',
            'Missing Check for Lamports': 'Resource Management',
            'Safe': 'No Vulnerability'
        }

        # Enhanced OWASP mappings with Solana-specific categories
        self.owasp_info: Dict[str, VulnerabilityInfo] = {
            'Unauthorized Access': VulnerabilityInfo(
                'Access Control', 'SC02', 'Critical', 9.5, 8.0
            ),
            'Account Spoofing': VulnerabilityInfo(
                'Account Safety', 'SC02', 'Critical', 9.0, 7.5
            ),
            'Malicious CPI': VulnerabilityInfo(
                'Program Security', 'SC04', 'Critical', 9.0, 7.0
            ),
            'System Account Abuse': VulnerabilityInfo(
                'Program Security', 'SC02', 'Critical', 9.0, 6.5
            ),
            'Unauthorized Transfer': VulnerabilityInfo(
                'Access Control', 'SC02', 'Critical', 9.5, 8.0
            ),
            'PDA Validation': VulnerabilityInfo(
                'Account Safety', 'SC07', 'High', 8.0, 7.0
            ),
            'Account Initialization': VulnerabilityInfo(
                'Account Safety', 'SC07', 'High', 8.0, 6.5
            ),
            'State Management': VulnerabilityInfo(
                'State Safety', 'SC07', 'High', 8.0, 6.0
            ),
            'Token Security': VulnerabilityInfo(
                'Token Safety', 'SC02', 'High', 8.5, 7.0
            ),
            'Input Validation': VulnerabilityInfo(
                'Validation', 'SC08', 'High', 7.5, 7.0
            ),
            'Integer Overflow': VulnerabilityInfo(
                'Runtime Safety', 'SC01', 'High', 7.5, 6.0
            ),
            'Runtime Safety': VulnerabilityInfo(
                'Runtime Safety', 'SC06', 'Medium', 6.5, 5.0
            ),
            'Unsafe Code': VulnerabilityInfo(
                'Memory Safety', 'SC06', 'High', 8.0, 5.5
            ),
            'Race Condition': VulnerabilityInfo(
                'Concurrency', 'SC09', 'High', 7.5, 5.0
            ),
            'Reentrancy': VulnerabilityInfo(
                'State Safety', 'SC03', 'High', 8.0, 6.0
            ),
            'Data Integrity': VulnerabilityInfo(
                'Data Safety', 'SC08', 'Medium', 6.5, 5.5
            ),
            'Error Handling': VulnerabilityInfo(
                'Program Safety', 'SC05', 'Medium', 6.0, 5.0
            ),
            'Resource Management': VulnerabilityInfo(
                'Resource Safety', 'SC07', 'Medium', 6.5, 5.0
            ),
            'No Vulnerability': VulnerabilityInfo(
                'Secure', 'None', 'None', 0.0, 0.0
            )
        }

    def extract_code_features(self, code: str) -> Dict[str, int]:
        """Extract advanced features from code snippets using improved regex patterns"""
        features = {
            # Signer and authority checks
            'num_signer_checks': len(re.findall(r'(?:is_signer|require(?:_auth|_signer)|verify_signer)\b', code)),
            'num_owner_checks': len(re.findall(r'(?:\.owner\s*==|assert(?:_eq)?!\s*.*?\bowner\b|verify_owner)\b', code)),
            
            # PDA and account validation
            'num_pda_checks': len(re.findall(r'(?:find|create)_program_address(?:_with_seed)?\b', code)),
            'num_bump_validations': len(re.findall(r'(?:assert(?:_eq)?!\s*.*?\bbump\b|verify_bump|seeds\s*=\s*\[.*?bump.*?\])', code)),
            'num_account_checks': len(re.findall(r'(?:assert(?:_eq)?!\s*.*?initialized|Account::try_from|verify_account|check_account)\b', code)),
            
            # CPI and program calls
            'num_cpi_calls': len(re.findall(r'(?:invoke(?:_signed)?|CpiContext::new(?:_with_signer)?|cpi::)\b', code)),
            'num_program_checks': len(re.findall(r'(?:assert(?:_eq)?!\s*.*?program_id|verify_program|check_program_account)\b', code)),
            
            # Validation and constraints
            'num_require_asserts': len(re.findall(r'(?:require!|assert(?:_eq)?!|invariant|ensure)\b', code)),
            'num_anchor_constraints': len(re.findall(r'#\[(?:account|instruction)\]\s*(?:#\[derive.*?\]\s*)*(?:pub\s+)?struct\s+\w+\s*{[^}]*constraint\s*=\s*[^}]+}', code, re.DOTALL)),
            
            # Error handling
            'num_error_handlers': len(re.findall(r'(?:catch|Result|Option|match|if\s+let|try[!]?|map_err|or_else)\b', code)),
            'num_custom_errors': len(re.findall(r'(?:#\[error\]|pub\s+enum\s+Error|ErrorCode|anchor::error::Error)\b', code)),
            
            # Unsafe code and risky patterns
            'num_unsafe_blocks': len(re.findall(r'unsafe\s*{|#\[unsafe_code\]', code)),
            'num_mut_refs': len(re.findall(r'&mut\s+(?:\w+::\w+|\w+)(?:<.*?>)?', code)),
            'num_raw_pointers': len(re.findall(r'\*(?:mut|const)\s+(?:\w+::\w+|\w+)(?:<.*?>)?', code)),
            
            # Financial operations
            'num_transfers': len(re.findall(r'(?:transfer(?:_lamports|_to)?|withdraw|close|drain)\b', code)),
            'num_token_ops': len(re.findall(r'(?:mint_to|burn|freeze|thaw|approve|revoke|set_authority|transfer|close_account)\b', code)),
            
            # Additional Solana-specific patterns
            'num_pda_seeds': len(re.findall(r'seeds\s*=\s*\[.*?\]', code)),
            'num_rent_checks': len(re.findall(r'(?:Rent::get|rent::minimum_balance|exempt_from_rent)\b', code)),
            'num_system_program_checks': len(re.findall(r'(?:system_program|SystemProgram|ID::check)\b', code)),
            'num_token_program_checks': len(re.findall(r'(?:token_program|TokenProgram|spl_token)\b', code))
        }
        
        # Enhanced derived features
        features.update({
            'has_proper_validation': (
                features['num_require_asserts'] > 0 and 
                features['num_account_checks'] > 0 and 
                (features['num_owner_checks'] > 0 or features['num_signer_checks'] > 0)
            ),
            'has_proper_error_handling': (
                features['num_error_handlers'] > 0 and 
                features['num_custom_errors'] > 0 and 
                features['num_require_asserts'] > 0
            ),
            'is_high_risk': (
                features['num_transfers'] > 0 or 
                features['num_token_ops'] > 0 or 
                features['num_cpi_calls'] > 0
            ),
            'is_unsafe': (
                features['num_unsafe_blocks'] > 0 or 
                features['num_raw_pointers'] > 0 or 
                (features['num_mut_refs'] > 2 and features['num_require_asserts'] == 0)
            ),
            'has_proper_pda': (
                features['num_pda_checks'] > 0 and 
                features['num_bump_validations'] > 0 and 
                features['num_pda_seeds'] > 0
            ),
            'has_proper_program_checks': (
                features['num_program_checks'] > 0 and 
                (features['num_system_program_checks'] > 0 or features['num_token_program_checks'] > 0)
            ),
            'has_proper_rent_checks': features['num_rent_checks'] > 0,
            'risk_score': (
                (features['num_transfers'] * 2) + 
                (features['num_token_ops'] * 2) + 
                (features['num_cpi_calls'] * 1.5) + 
                (features['num_unsafe_blocks'] * 3) + 
                (features['num_raw_pointers'] * 2) - 
                (features['num_require_asserts'] * 0.5) - 
                (features['num_owner_checks'] * 0.5) - 
                (features['num_signer_checks'] * 0.5)
            )
        })
        
        return features

    def read_contract_code(self, contract_path: str) -> str:
        """Read contract code from file if available"""
        try:
            with open(contract_path, 'r') as f:
                return f.read()
        except:
            return ""

    def process(self) -> pd.DataFrame:
        """Process and enhance the dataset"""
        print(f"Loading dataset from {self.input_file}...")
        self.df = pd.read_csv(self.input_file)
        
        # Clean data
        self.df.columns = self.df.columns.str.strip()
        self.df = self.df.dropna(subset=['Contract', 'VulnerabilityType'])
        
        # Try to read actual contract code
        print("Reading contract code...")
        self.df['ContractCode'] = self.df['Contract'].apply(self.read_contract_code)
        
        # Map vulnerabilities
        print("Mapping vulnerability categories...")
        self.df['VulnCategory'] = self.df['VulnerabilityType'].replace(self.vuln_mapping)
        
        # Extract OWASP info
        print("Extracting OWASP information...")
        self.df['OWASP_Category'] = self.df['VulnCategory'].apply(lambda x: self.owasp_info.get(x, self.owasp_info['No Vulnerability']).category)
        self.df['OWASP_ID'] = self.df['VulnCategory'].apply(lambda x: self.owasp_info.get(x, self.owasp_info['No Vulnerability']).owasp_id)
        self.df['New_Severity'] = self.df['VulnCategory'].apply(lambda x: self.owasp_info.get(x, self.owasp_info['No Vulnerability']).severity)
        self.df['Impact'] = self.df['VulnCategory'].apply(lambda x: self.owasp_info.get(x, self.owasp_info['No Vulnerability']).impact)
        self.df['Likelihood'] = self.df['VulnCategory'].apply(lambda x: self.owasp_info.get(x, self.owasp_info['No Vulnerability']).likelihood)
        
        # Calculate risk score (CVSS-like)
        self.df['RiskScore'] = round((self.df['Impact'] * self.df['Likelihood']) / 10, 1)
        
        # Extract code features from actual code if available, otherwise use existing metrics
        print("Extracting code features...")
        code_features = self.df.apply(
            lambda row: self.extract_code_features(row['ContractCode']) 
            if row['ContractCode'] else {
                'num_signer_checks': 0,
                'num_owner_checks': 0,
                'num_pda_checks': row['NumPDAs'],
                'num_bump_validations': 0,
                'num_account_checks': 0,
                'num_cpi_calls': row['NumCPICalls'],
                'num_program_checks': 0,
                'num_require_asserts': 0,
                'num_anchor_constraints': row['NumAnchorMacros'],
                'num_error_handlers': 0,
                'num_custom_errors': 0,
                'num_unsafe_blocks': row['NumUnsafeBlocks'],
                'num_mut_refs': 0,
                'num_raw_pointers': 0,
                'num_transfers': 0,
                'num_token_ops': row['NumTokenAccounts'],
                'has_proper_validation': False,
                'has_proper_error_handling': False,
                'is_high_risk': row['NumTokenAccounts'] > 0,
                'is_unsafe': row['NumUnsafeBlocks'] > 0
            },
            axis=1
        )
        code_features_df = pd.DataFrame.from_records(code_features.tolist())
        self.df = pd.concat([self.df, code_features_df], axis=1)
        
        # Add metadata
        self.df['ProcessedTimestamp'] = pd.Timestamp.now()
        self.df['DatasetVersion'] = '2.0.0'
        
        return self.df

    def save(self, output_file: str):
        """Save the processed dataset"""
        if self.df is not None:
            print(f"Saving enhanced dataset to {output_file}...")
            self.df.to_csv(output_file, index=False)
            print("✅ Dataset processing complete!")
            
            # Print statistics
            print("\nDataset Statistics:")
            print(f"Total samples: {len(self.df)}")
            print("\nVulnerability distribution:")
            print(self.df['VulnCategory'].value_counts())
            print("\nSeverity distribution:")
            print(self.df['Severity'].value_counts())
        else:
            print("❌ Error: Dataset not processed yet. Run process() first.")

def main():
    processor = SolanaDatasetProcessor("solana_security_analysis_report_combined.csv")
    processor.process()
    processor.save("solana_dataset_enhanced.csv")

if __name__ == "__main__":
    main()