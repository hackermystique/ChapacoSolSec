import ast
import os
import json
import sys
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass
from functools import lru_cache
import logging
from pathlib import Path
from tree_sitter import Language, Parser
import joblib
from sklearn.base import BaseEstimator
from ast_patterns import SOLANA_AST_PATTERNS
import re
import git
from analysis import setup_tree_sitter
from logger_config import setup_logger

logger = setup_logger('ast_analysis', 'logs/ast_analysis.log')

# Initialize tree-sitter parser
parser = Parser()
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
try:
    # Try to load the Rust language using the build/my-languages.so file
    language_path = os.path.join(CURRENT_DIR, 'build', 'my-languages.so')
    if not os.path.exists(language_path):
        logger.error(f"Language file not found: {language_path}")
        RUST_LANGUAGE = None
    else:
        RUST_LANGUAGE = Language(language_path, 'rust')
        parser.set_language(RUST_LANGUAGE)
        logger.info("Successfully loaded Rust language parser from my-languages.so")
except Exception as e:
    logger.error(f"Failed to load Tree-sitter Rust parser: {e}")
    RUST_LANGUAGE = None

# Load trained model and label encoder
MODEL_DIR = "models"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/ast_analysis.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class AnalysisResult:
    """Represents a single analysis result."""
    issue: str
    severity: str
    category: str
    line: int
    code: str
    context: str
    file_path: str
    required_checks: List[str]
    fix_suggestion: Optional[str] = None
    risk_score: float = 0.0
    model_predictions: Dict[str, Any] = None

class TreeSitterSetup:
    """Handles Tree-sitter initialization and management."""
    
    def __init__(self):
        self.parser = None
        self.rust_language = None
        self.setup_parser()
    
    def setup_parser(self) -> None:
        """Set up the Tree-sitter parser for Rust code analysis."""
        try:
            self.parser, self.rust_language = setup_tree_sitter()
            if not self.parser or not self.rust_language:
                logger.error("Failed to initialize Tree-sitter parser")
                return
            logger.info("Tree-sitter parser initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Tree-sitter parser: {e}")

class ModelManager:
    """Manages machine learning models for vulnerability detection."""
    
    def __init__(self, model_dir: str = "models"):
        self.model_dir = Path(model_dir)
        self.models: Dict[str, BaseEstimator] = {}
        self.scalers: Dict[str, Any] = {}
        self.encoders: Dict[str, Any] = {}
        self.feature_names = [
            'code_length', 'context_length', 'num_tokens',
            'has_require', 'has_assert', 'has_unsafe',
            'has_transfer', 'has_signer_check', 'has_owner_check',
            'has_program_check', 'has_pda_check', 'num_loops',
            'num_conditions'
        ]
        self.load_models()
    
    def load_models(self) -> None:
        """Load all available models, scalers, and encoders from the models directory."""
        try:
            if not self.model_dir.exists():
                logger.error(f"Models directory not found: {self.model_dir}")
                return
                
            logger.info(f"Loading models from {self.model_dir}")
            
            # First, try to load the vulnerability scaler
            vuln_scaler_path = self.model_dir / "vulnerability_scaler.pkl"
            if vuln_scaler_path.exists():
                try:
                    self.scalers['vulnerability_scaler'] = joblib.load(vuln_scaler_path)
                    logger.info("Successfully loaded vulnerability_scaler")
                except Exception as e:
                    logger.error(f"Failed to load vulnerability_scaler: {e}")
            
            # Then load other models and scalers
            for model_path in self.model_dir.glob("*.pkl"):
                model_name = model_path.stem
                try:
                    logger.debug(f"Loading {model_name} from {model_path}")
                    model = joblib.load(model_path)
                    
                    if isinstance(model, BaseEstimator):
                        self.models[model_name] = model
                        logger.info(f"Loaded model: {model_name}")
                    elif hasattr(model, 'transform'):  # Scaler
                        self.scalers[model_name] = model
                        logger.info(f"Loaded scaler: {model_name}")
                    elif hasattr(model, 'classes_'):  # LabelEncoder
                        # Map vuln_encoder to vulnerability_encoder for compatibility
                        if model_name == 'vuln_encoder':
                            self.encoders['vulnerability_encoder'] = model
                            logger.info("Loaded vulnerability encoder (mapped from vuln_encoder)")
                        else:
                            self.encoders[model_name] = model
                            logger.info(f"Loaded encoder: {model_name}")
                except Exception as e:
                    logger.error(f"Failed to load {model_name}: {e}")
                    continue
                    
            logger.info(f"Loaded {len(self.models)} models, {len(self.scalers)} scalers, {len(self.encoders)} encoders")
            
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            raise
    
    def extract_features(self, code: str, context: str) -> List[float]:
        """Extract features from code and context."""
        try:
            # Basic code metrics
            code_length = len(code)
            context_length = len(context)
            num_tokens = len(code.split())
            
            # Security-related features
            has_require = int("require!" in context)
            has_assert = int("assert!" in context)
            has_unsafe = int("unsafe" in context.lower())
            has_transfer = int(any(x in context.lower() for x in ['transfer', 'withdraw', 'close']))
            
            # Pattern-based features
            has_signer_check = int("is_signer" in context)
            has_owner_check = int("owner" in context)
            has_program_check = int("program_id" in context)
            has_pda_check = int("find_program_address" in context)
            
            # Complexity features
            num_loops = len(re.findall(r'\b(for|while|loop)\b', context))
            num_conditions = len(re.findall(r'\b(if|match)\b', context))
            
            # Return exactly 13 features to match the model's expectations
            features = [
                code_length,          # 1
                context_length,       # 2
                num_tokens,          # 3
                has_require,         # 4
                has_assert,          # 5
                has_unsafe,          # 6
                has_transfer,        # 7
                has_signer_check,    # 8
                has_owner_check,     # 9
                has_program_check,   # 10
                has_pda_check,       # 11
                num_loops,           # 12
                num_conditions       # 13
            ]
            
            if len(features) != 13:
                raise ValueError(f"Feature count mismatch: got {len(features)}, expected 13")
                
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            raise
    
    def predict(self, code: str, context: str) -> Dict[str, Any]:
        """Make predictions using all available models."""
        predictions = {}
        
        try:
            # Extract features
            features = self.extract_features(code, context)
            logger.debug(f"Extracted features: {features}")
            
            # Create DataFrame with feature names for LightGBM
            import pandas as pd
            features_df = pd.DataFrame([features], columns=self.feature_names)
            
            # Scale features if scaler exists
            if 'vulnerability_scaler' in self.scalers:
                try:
                    logger.debug("Scaling features with vulnerability_scaler")
                    features_scaled = self.scalers['vulnerability_scaler'].transform(features_df)
                    if 'vulnerability_model' in self.models:
                        logger.debug("Making vulnerability prediction")
                        pred = self.models['vulnerability_model'].predict(features_scaled)[0]
                        if 'vulnerability_encoder' in self.encoders:
                            pred = self.encoders['vulnerability_encoder'].inverse_transform([pred])[0]
                        predictions['vulnerability'] = str(pred)
                        logger.debug(f"Vulnerability prediction: {pred}")
                    else:
                        logger.warning("Vulnerability model not found")
                        predictions['vulnerability'] = 'error: model not found'
                except Exception as e:
                    logger.error(f"Vulnerability prediction failed: {e}")
                    predictions['vulnerability'] = f"error: {str(e)}"
            else:
                logger.warning("Vulnerability scaler not found")
                predictions['vulnerability'] = 'error: scaler not found'
            
            # Predict severity if model exists
            if 'severity_model' in self.models:
                try:
                    if 'severity_scaler' in self.scalers:
                        logger.debug("Scaling features with severity_scaler")
                        features_scaled = self.scalers['severity_scaler'].transform(features_df)
                    else:
                        features_scaled = features_df
                        
                    logger.debug("Making severity prediction")
                    pred = self.models['severity_model'].predict(features_scaled)[0]
                    if 'severity_encoder' in self.encoders:
                        pred = self.encoders['severity_encoder'].inverse_transform([pred])[0]
                    predictions['severity'] = str(pred)
                    logger.debug(f"Severity prediction: {pred}")
                except Exception as e:
                    logger.error(f"Severity prediction failed: {e}")
                    predictions['severity'] = f"error: {str(e)}"
            else:
                logger.warning("Severity model not found")
                predictions['severity'] = 'error: model not found'
            
        except Exception as e:
            logger.error(f"Error in prediction pipeline: {e}")
            predictions = {
                'vulnerability': f"error: {str(e)}",
                'severity': f"error: {str(e)}"
            }
        
        return predictions

class ASTPatternMatcher:
    """Handles pattern matching for vulnerability detection."""
    
    def __init__(self):
        self.patterns = SOLANA_AST_PATTERNS
    
    @staticmethod
    def get_parent_function(node) -> Optional[Any]:
        """Get the parent function node of a given node."""
        current = node
        while current:
            if current.type == 'function_item':
                return current
            current = current.parent
        return None
    
    def has_validation_check(self, node: Any, pattern_type: str = 'generic') -> bool:
        """Check if there's validation logic around the node."""
        parent_fn = self.get_parent_function(node)
        if not parent_fn:
            return False
            
        validation_patterns = {
            'signer': ['is_signer', 'require!(', 'assert!('],
            'owner': ['.owner', 'assert_eq!(*account.owner'],
            'program': ['check_program_id', 'verify_program_id'],
            'pda': ['seeds =', 'bump ='],
            'arithmetic': ['checked_add', 'checked_sub', 'checked_mul', 'checked_div'],
            'generic': ['require!(', 'assert!(', 'validate', 'check_']
        }
        
        patterns = validation_patterns.get(pattern_type, validation_patterns['generic'])
        fn_text = parent_fn.text.decode('utf8')
        return any(pattern in fn_text for pattern in patterns)

class VulnerabilityAnalyzer:
    """Main class for vulnerability analysis."""
    
    def __init__(self):
        self.tree_sitter = TreeSitterSetup()
        self.pattern_matcher = ASTPatternMatcher()
        self.model_manager = ModelManager()
    
    @lru_cache(maxsize=100)
    def analyze_file(self, file_path: str) -> List[AnalysisResult]:
        """Analyze a single file for vulnerabilities."""
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return []
            
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source_code = f.read()
        except UnicodeDecodeError:
            logger.error(f"Failed to read file {file_path}: Invalid encoding")
            return []
        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            return []
            
        return self._analyze_source(source_code, file_path)
    
    def _analyze_source(self, source_code: str, file_path: str) -> List[AnalysisResult]:
        """Analyze source code for vulnerabilities."""
        if self.tree_sitter.rust_language is None:
            logger.error("Tree-sitter parser not initialized")
            return []
            
        try:
            tree = self.tree_sitter.parser.parse(bytes(source_code, "utf8"))
            return self._check_patterns(tree.root_node, source_code, file_path)
        except Exception as e:
            logger.error(f"Failed to parse {file_path}: {e}")
            return []
    
    def _check_patterns(self, node: Any, source_code: str, file_path: str) -> List[AnalysisResult]:
        """Check for vulnerability patterns in the AST."""
        results = []
        
        def process_node(node):
            if not hasattr(node, 'type'):
                return
                
            node_text = node.text.decode('utf8') if hasattr(node, 'text') else ""
            node_type = node.type
            
            for pattern_name, pattern in self.pattern_matcher.patterns.items():
                if node_type == pattern['node_type']:
                    if any(p in node_text for p in pattern['patterns']):
                        if not self.pattern_matcher.has_validation_check(node, pattern_name.split('_')[0]):
                            result = self._create_result(
                                node, pattern, pattern_name, source_code, file_path
                            )
                            results.append(result)
            
            for child in node.children:
                process_node(child)
        
        process_node(node)
        return results
    
    def _create_result(self, node: Any, pattern: Dict, pattern_name: str, source_code: str, file_path: str) -> AnalysisResult:
        """Create an analysis result from a detected vulnerability."""
        try:
            line = node.start_point[0] + 1
        except AttributeError:
            line = 0
            
        code = source_code[node.start_byte:node.end_byte] if hasattr(node, 'start_byte') else ""
        context = source_code[max(0, node.start_byte-100):min(len(source_code), node.end_byte+100)]
        
        # Get model predictions
        try:
            model_predictions = self.model_manager.predict(code, context)
        except Exception as e:
            logger.error(f"Failed to get model predictions: {e}")
            model_predictions = {
                'vulnerability': 'error: prediction failed',
                'severity': 'error: prediction failed'
            }
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(pattern, context)
        
        # Adjust risk score based on model predictions if available
        if 'severity' in model_predictions and not model_predictions['severity'].startswith('error'):
            severity_map = {
                'Critical': 9.0,
                'High': 7.5,
                'Medium': 5.0,
                'Low': 2.5
            }
            model_severity = model_predictions['severity']
            if model_severity in severity_map:
                # Blend the pattern-based and model-based risk scores
                risk_score = (risk_score + severity_map[model_severity]) / 2
        
        return AnalysisResult(
            issue=pattern['description'],
            severity=pattern['severity'],
            category=pattern_name.split('_')[0],
            line=line,
            code=code,
            context=context,
            file_path=file_path,
            required_checks=pattern.get('required_checks', []),
            fix_suggestion=pattern.get('secure_example'),
            risk_score=risk_score,
            model_predictions=model_predictions
        )
    
    def _calculate_risk_score(self, pattern: Dict, context: str) -> float:
        """Calculate risk score based on pattern and context."""
        base_score = {
            'Critical': 9.0,
            'High': 7.5,
            'Medium': 5.0,
            'Low': 2.5
        }.get(pattern['severity'], 5.0)
        
        # Adjust score based on context
        if any(x in context.lower() for x in ['transfer', 'withdraw', 'close']):
            base_score += 0.5
        if 'unsafe' in context.lower():
            base_score += 0.5
        if 'require!' in context.lower() or 'assert!' in context.lower():
            base_score -= 0.3
            
        return min(10.0, max(1.0, base_score))

def run_ast_analysis(project_path: str) -> tuple[Dict[str, List[Dict]], int]:
    """Main entry point for AST analysis.
    
    Args:
        project_path: Path to the project directory to analyze
        
    Returns:
        Tuple containing:
        - Dict mapping file paths to lists of analysis results
        - Number of files analyzed
    """
    if not os.path.exists(project_path):
        logger.error(f"Project directory not found: {project_path}")
        return {}, 0
        
    analyzer = VulnerabilityAnalyzer()
    results = {}
    files_analyzed = 0
    total_issues = 0
    
    try:
        # First check if the directory exists and is a directory
        if not os.path.isdir(project_path):
            logger.error(f"Path is not a directory: {project_path}")
            return {}, 0
            
        # Get all Rust files in the project
        rust_files = []
        for root, _, files in os.walk(project_path):
            for file in files:
                if file.endswith('.rs'):
                    file_path = os.path.join(root, file)
                    if os.path.isfile(file_path):  # Only add if it's actually a file
                        rust_files.append((root, file, file_path))
        
        if not rust_files:
            logger.warning(f"No Rust files found in {project_path}")
            return {}, 0
            
        # Analyze each Rust file
        for root, file, file_path in rust_files:
            try:
                rel_path = os.path.relpath(file_path, project_path)
                file_results = analyzer.analyze_file(file_path)
                
                if file_results:
                    # Convert AnalysisResult objects to dictionaries
                    results[rel_path] = [
                        {
                            'line': result.line,
                            'issue': result.issue,
                            'severity': result.severity,
                            'category': result.category,
                            'code': result.code,
                            'context': result.context,
                            'risk_score': result.risk_score,
                            'fix_suggestion': result.fix_suggestion,
                            'model_predictions': result.model_predictions
                        }
                        for result in file_results
                    ]
                    total_issues += len(file_results)
                    logger.info(f"Found {len(file_results)} issues in {rel_path}")
                
                files_analyzed += 1
                
            except Exception as e:
                logger.error(f"Error analyzing {file_path}: {e}")
                continue
        
        logger.info(f"Analysis complete. Analyzed {files_analyzed} files, found {total_issues} issues.")
        return results, files_analyzed
        
    except Exception as e:
        logger.error(f"Fatal error during analysis: {e}")
        return {}, 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ast_analysis.py <project_path>")
        sys.exit(1)

    project_dir = sys.argv[1]
    if not os.path.exists(project_dir):
        print(f"Error: Project directory '{project_dir}' does not exist")
        sys.exit(1)

    results, files_analyzed = run_ast_analysis(project_dir)
    
    if results:
        # Generate safe filename for the report
        safe_name = project_dir.replace('/', '_')
        base_filename = f"{safe_name}_ast_report"
        output_file = Path("json_reports") / f"{base_filename}.json"
        print(output_file)
        output_file.parent.mkdir(exist_ok=True)
        
        with output_file.open('w') as f:
            json.dump(results, f, indent=2, default=lambda x: x.__dict__)
        
        print("\nAnalysis Summary:")
        print("=" * 50)
        print(f"Files analyzed: {files_analyzed}")
        print(f"Total issues found: {sum(len(issues) for issues in results.values())}")
        print(f"Results saved to: {output_file}")
        
        # Print severity distribution
        severity_counts = {}
        for file_results in results.values():
            for result in file_results:
                severity = result['severity']
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print("\nSeverity Distribution:")
        for severity, count in sorted(severity_counts.items()):
            print(f"{severity}: {count}")
    else:
        print("\nNo issues found in any files")