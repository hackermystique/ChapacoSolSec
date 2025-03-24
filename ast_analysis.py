import ast
import os
import json
import sys
from sklearn.base import BaseEstimator
import glob, joblib
# import numpy as np
from tree_sitter import Language, Parser

# Initialize tree-sitter parser
parser = Parser()
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
try:
    # Try to load the Rust language using absolute path
    RUST_LANGUAGE = Language(os.path.join(CURRENT_DIR, 'tree-sitter-rust.dylib'), 'rust')
    parser.set_language(RUST_LANGUAGE)
except Exception as e:
    print(f"[ERROR] Failed to load Tree-sitter Rust parser: {e}")
    RUST_LANGUAGE = None

# Load trained model and label encoder
MODEL_DIR = "models"
# Load all models (*.pkl)
def load_models(model_dir):
    models = {}
    for model_path in glob.glob(os.path.join(model_dir, "*.pkl")):
        model_name = os.path.basename(model_path).replace(".pkl", "")
        try:
            model = joblib.load(model_path)
            if isinstance(model, BaseEstimator):  # Sanity check
                models[model_name] = model
        except Exception as e:
            print(f"[WARN] Could not load model {model_path}: {e}")
    return models

loaded_models = load_models(MODEL_DIR)
# model = joblib.load(os.path.join(MODEL_DIR, "vuln_detector_v2.pkl"))
# label_encoder = joblib.load(os.path.join(MODEL_DIR, "label_encoder.pkl"))

# Enhanced AST patterns for Solana vulnerabilities
SOLANA_AST_PATTERNS = {
    # Account Validation Patterns
    'missing_signer_check': {
        'node_type': 'function_item',
        'patterns': ['pub fn', 'Context<'],
        'required_checks': ['is_signer'],
        'severity': 'Critical',
        'description': 'Missing signer verification in privileged operation',
        'secure_example': 'require!(ctx.accounts.authority.is_signer, "Authority must sign");'
    },
    'unchecked_owner': {
        'node_type': 'field_expression',
        'patterns': ['.owner', '.key', '.data'],
        'parent_type': 'AccountInfo',
        'required_checks': ['owner', 'assert_eq!'],
        'severity': 'Critical',
        'description': 'Account ownership not verified before access',
        'secure_example': 'assert_eq!(*account.owner, program_id, "Invalid account owner");'
    },
    
    # Token Operation Patterns
    'unsafe_token_op': {
        'node_type': 'call_expression',
        'patterns': ['token::transfer', 'token::mint_to', 'token::burn'],
        'required_checks': ['is_signer', 'owner', 'authority'],
        'severity': 'Critical',
        'description': 'Token operation without proper authority verification',
        'secure_example': 'require!(ctx.accounts.authority.is_signer && token.owner == authority.key());'
    },
    'unchecked_token_account': {
        'node_type': 'call_expression',
        'patterns': ['SplTokenAccount::unpack', 'TokenAccount::unpack'],
        'required_checks': ['owner', 'mint', 'authority'],
        'severity': 'Critical',
        'description': 'Token account used without ownership/mint verification',
        'secure_example': 'assert_eq!(token.owner, *authority.key, "Invalid token owner");'
    },
    
    # PDA and CPI Security
    'unsafe_cpi': {
        'node_type': 'call_expression',
        'patterns': ['invoke', 'invoke_signed'],
        'required_checks': ['program_id', 'owner', 'authority'],
        'severity': 'Critical',
        'description': 'CPI call without program ID or authority verification',
        'secure_example': 'assert_eq!(*target_program.key, expected_program_id, "Invalid program");'
    },
    'unsafe_pda': {
        'node_type': 'call_expression',
        'patterns': ['Pubkey::create_program_address', 'find_program_address'],
        'required_checks': ['bump', 'seeds', 'program_id'],
        'severity': 'High',
        'description': 'PDA creation/validation without proper seed verification',
        'secure_example': 'let (pda, bump) = Pubkey::find_program_address(&[seed], program_id);'
    },
    
    # State Management
    'unsafe_deserialization': {
        'node_type': 'call_expression',
        'patterns': ['try_from_slice', 'try_into'],
        'required_checks': ['account_type', 'owner', 'is_initialized'],
        'severity': 'High',
        'description': 'Account deserialization without type/ownership checks',
        'secure_example': 'require!(account.is_initialized(), "Account not initialized");'
    },
    'unsafe_state_close': {
        'node_type': 'assignment_expression',
        'patterns': ['lamports', 'borrow_mut()', '= 0'],
        'required_checks': ['owner', 'is_signer', 'destination'],
        'severity': 'Critical',
        'description': 'Unsafe account closure without proper checks',
        'secure_example': 'require!(ctx.accounts.authority.is_signer, "Authority must sign");'
    },
    
    # System Operations
    'unsafe_transfer': {
        'node_type': 'call_expression',
        'patterns': ['system_instruction::transfer', 'system_program::transfer'],
        'required_checks': ['is_signer', 'owner', 'system_program'],
        'severity': 'Critical',
        'description': 'SOL transfer without proper authorization checks',
        'secure_example': 'require!(from_account.is_signer, "Sender must sign");'
    },
    'unsafe_sysvar': {
        'node_type': 'call_expression',
        'patterns': ['Clock::get', 'Rent::get', 'EpochSchedule::get'],
        'required_checks': ['check_id', 'key'],
        'severity': 'High',
        'description': 'Sysvar access without address verification',
        'secure_example': 'assert_eq!(*sysvar.key, sysvar::clock::id(), "Invalid Clock sysvar");'
    },
    
    # Arithmetic Safety
    'unsafe_math': {
        'node_type': 'binary_expression',
        'patterns': ['+', '-', '*', '/'],
        'required_checks': ['checked_add', 'checked_sub', 'checked_mul', 'checked_div'],
        'severity': 'High',
        'description': 'Unchecked arithmetic operation',
        'secure_example': 'amount1.checked_add(amount2).ok_or(ErrorCode::Overflow)?;'
    },
    'unsafe_decimal': {
        'node_type': 'call_expression',
        'patterns': ['try_round_u64', 'try_ceil_u64', 'try_floor_u64'],
        'required_checks': ['ok_or', 'unwrap_or'],
        'severity': 'High',
        'description': 'Unchecked decimal conversion',
        'secure_example': 'decimal.try_round_u64().ok_or(ErrorCode::InvalidConversion)?;'
    },
    
    # Resource Management
    'unbounded_operation': {
        'node_type': 'for_expression',
        'patterns': ['..', 'iter', 'into_iter'],
        'required_checks': ['limit', 'max_items'],
        'severity': 'Medium',
        'description': 'Potentially unbounded operation',
        'secure_example': 'require!(items.len() <= MAX_ITEMS, "Too many items");'
    },
    'unsafe_mem': {
        'node_type': 'call_expression',
        'patterns': ['transmute', 'zeroed', 'uninitialized'],
        'severity': 'Critical',
        'description': 'Unsafe memory operation detected',
        'secure_example': 'Use safe alternatives like Default::default()'
    },
    'duplicate_accounts': {
        'node_type': 'array_expression',
        'patterns': ['accounts['],
        'required_checks': ['assert_eq!', 'assert_ne!'],
        'severity': 'High',
        'description': 'Potential duplicate account usage',
        'secure_example': 'assert_ne!(account1.key(), account2.key(), "Duplicate accounts");'
    },
    'anchor_constraints': {
        'node_type': 'attribute',
        'patterns': ['#[account]', '#[derive(Accounts)'],
        'missing': ['#[constraint', 'has_one'],
        'severity': 'High',
        'description': 'Missing Anchor account constraints'
    }
}

def check_validation_patterns(node, source_code):
    """Check for basic Solana program validation patterns."""
    validation_issues = []
    seen_issues = set()

    def add_issue(line, issue, issue_type, code, context, pattern=None):
        # Create unique key to prevent duplicate issues
        issue_key = f"{line}:{issue_type}"
        if len(code.strip()) < 5:
            return  # Skip reporting empty/irrelevant code blocks
        if issue_key not in seen_issues:
            seen_issues.add(issue_key)
            severity_info = calculate_severity_score(issue_type, context, code)
            
            # Get secure example from pattern if available
            secure_example = pattern['secure_example'] if pattern and 'secure_example' in pattern else None
            
            features = {
                "code_length": len(code),
                "context_length": len(context),
                "has_require": int("require!" in context),
                "has_assert": int("assert!" in context),
                "issue_type": issue_type,
                "num_tokens": len(code.split())
            }

            model_results = {}
            for model_name, model in loaded_models.items():
                try:
                    input_vector = [
                        features["code_length"],
                        features["context_length"],
                        features["has_require"],
                        features["has_assert"],
                        features["num_tokens"]
                    ]
                    prediction = model.predict([input_vector])[0]
                    model_results[model_name] = str(prediction)
                except Exception as e:
                    model_results[model_name] = f"error: {e}"

            validation_issues.append({
                'line': line if line != -1 else None,
                'issue': issue,
                'severity': severity_info['severity'],
                'risk_score': severity_info['score'],
                'category': severity_info['category'],
                'description': severity_info['description'],
                'code': code,
                'context': context.strip()[:100] + '...' if context else 'Context not available',
                'secure_example': secure_example,
                'models': model_results
            })
    
    def traverse(node):
        # Basic node information
        node_text = node.text.decode('utf8') if hasattr(node, 'text') else ""
        node_type = node.type if hasattr(node, 'type') else ""
        IGNORED_NODE_TYPES = {
            "use_declaration", "extern_crate_declaration", "mod_item", "source_file"
        }
        if node_type in IGNORED_NODE_TYPES:
            return
        try:
            line = node.start_point[0] + 1
        except AttributeError:
            line = -1  # Unknown line

        code = source_code[node.start_byte:node.end_byte] if hasattr(node, 'start_byte') and hasattr(node, 'end_byte') else ""
        context = source_code[max(0, node.start_byte-100):min(len(source_code), node.end_byte+100)]

        # Check for each pattern in SOLANA_AST_PATTERNS
        for pattern_name, pattern in SOLANA_AST_PATTERNS.items():
            if node_type == pattern['node_type']:
                # Check if any pattern matches
                if 'patterns' in pattern and any(p in node_text for p in pattern['patterns']):
                    # Check for required validations
                    validation_type = pattern_name.split('_')[0]  # e.g., 'signer' from 'missing_signer_check'
                    if not has_validation_check(node, validation_type):
                        add_issue(
                            line,
                            pattern['description'],
                            pattern_name,
                            code,
                            context,
                            pattern
                        )

        # Special case for CPI validation
        if node_type == 'call_expression' and any(c in node_text for c in ['invoke', 'invoke_signed']):
            if not has_cpi_validation(node):
                pattern = SOLANA_AST_PATTERNS['unsafe_cpi']
                add_issue(
                    line,
                    pattern['description'],
                    'unsafe_cpi',
                    code,
                    context,
                    pattern
                )

        # Special case for arithmetic operations
        if node_type == 'binary_expression' and any(op in node_text for op in ['+', '-', '*', '/']):
            if not has_validation_check(node, 'arithmetic'):
                pattern = SOLANA_AST_PATTERNS['unsafe_math']
                add_issue(
                    line,
                    pattern['description'],
                    'unsafe_math',
                    code,
                    context,
                    pattern
                )

        # Recurse through children
        for child in node.children:
            traverse(child)

        # 4. PDA Creation (High)
        if "find_program_address" in node_text:
            if not "bump" in context.lower():
                add_issue(line, 'PDA creation without bump seed handling', 'pda_validation', code, context)

        # 5. Data Mutation (High)
        if "try_borrow_mut" in node_text:
            if not "require!" in context and not "assert!" in context:
                add_issue(line, 'Mutable data access without validation', 'data_validation', code, context)

        # 6. Token Operations (High)
        if any(op in node_text for op in ["transfer", "mint_to", "burn"]):
            if not "authority" in context:
                add_issue(line, 'Token operation without authority check', 'authority_check', code, context)

        # 7. Account Creation (Medium)
        if "create_account" in node_text:
            if not "Rent" in context:
                add_issue(line, 'Account creation without rent check', 'rent_check', code, context)

        # 8. Vector Operations (Medium)
        if "Vec<" in node_text and node_type == "type_identifier":
            if not "max_len" in context:
                add_issue(line, 'Vector without length constraint', 'vector_constraint', code, context)
        
        if node_type == 'source_file':
            return  # Skip entire source_file node
        
        # Process child nodes
        for child in node.children:
            traverse(child)

    traverse(node)
    return validation_issues

def get_parent_function(node):
    """Get the parent function node of a given node."""
    current = node
    while current:
        if current.type == 'function_item':
            return current
        current = current.parent
    return None

def get_parent_struct(node):
    """Get the parent struct node of a given node."""
    current = node
    while current:
        if current.type == 'struct_item':
            return current
        current = current.parent
    return None

def has_validation_check(node, pattern_type='generic'):
    """Check if there's validation logic around the node.
    
    Args:
        node: The AST node to check
        pattern_type: Type of validation to check for (generic, signer, owner, etc.)
    """
    parent_fn = get_parent_function(node)
    if not parent_fn:
        return False
        
    # Get validation context from function and its attributes
    fn_text = parent_fn.text.decode('utf8')
    
    # Pattern-specific validation checks
    validation_patterns = {
        'signer': [
            'is_signer', '#[account(signer)]', 'require!(', 'assert!('
        ],
        'owner': [
            '.owner', 'assert_eq!(*account.owner', 'check_owner', 'validate_owner'
        ],
        'program': [
            'check_program_id', 'verify_program_id', 'assert_eq!(*program_id'
        ],
        'pda': [
            'seeds =', 'bump =', 'assert_pda', 'validate_pda'
        ],
        'arithmetic': [
            'checked_add', 'checked_sub', 'checked_mul', 'checked_div',
            'safe_math::' # Custom safe math module
        ],
        'generic': [
            'require!(', 'assert!(', 'validate', 'check_', 'verify_'
        ]
    }
    
    # Get relevant patterns based on pattern_type
    patterns = validation_patterns.get(pattern_type, validation_patterns['generic'])
    
    # Check for validation patterns in function text
    return any(pattern in fn_text for pattern in patterns)

def has_cpi_validation(node):
    """Check if CPI call has proper validation."""
    parent_fn = get_parent_function(node)
    if not parent_fn:
        return False
        
    # Get the function text
    fn_text = parent_fn.text.decode('utf8')
    
    # Required validations for CPI
    required_checks = [
        # Program ID validation
        ('program_id', ['check_program_id', 'verify_program_id', 'assert_eq!(*program_id']),
        # Signer checks
        ('signer', ['is_signer', '#[account(signer)]', 'require!(ctx.accounts']),
        # Account ownership
        ('owner', ['check_owner', 'assert_eq!(*account.owner']),
        # Account data validation
        ('data', ['validate_accounts', 'verify_instruction'])
    ]
    
    # Check for each required validation
    validation_present = []
    for check_type, patterns in required_checks:
        if any(pattern in fn_text for pattern in patterns):
            validation_present.append(check_type)
    
    # Require at least program_id check and one other validation
    return 'program_id' in validation_present and len(validation_present) > 1

def calculate_severity_score(issue_type, context, code):
    """Calculate severity score based on issue type and context for Solana programs."""
    base_scores = {
        # Critical (9.0-10.0): Direct security impact
        'missing_signer': {'score': 10.0, 'severity': 'Critical', 'category': 'Access Control'},
        'unchecked_owner': {'score': 9.8, 'severity': 'Critical', 'category': 'Account Safety'},
        'memory_safety': {'score': 9.5, 'severity': 'Critical', 'category': 'Memory Safety'},
        'program_check': {'score': 9.3, 'severity': 'Critical', 'category': 'Program Security'},
        'reinitialization': {'score': 9.2, 'severity': 'Critical', 'category': 'Account Safety'},
        'unchecked_cpi': {'score': 9.0, 'severity': 'Critical', 'category': 'Program Security'},
        
        # High (8.0-8.9): Potential security impact
        'pda_validation': {'score': 8.8, 'severity': 'High', 'category': 'Account Safety'},
        'data_validation': {'score': 8.5, 'severity': 'High', 'category': 'Data Safety'},
        'authority_check': {'score': 8.3, 'severity': 'High', 'category': 'Access Control'},
        'sysvar_check': {'score': 8.2, 'severity': 'High', 'category': 'Program Security'},
        'duplicate_mutable': {'score': 8.0, 'severity': 'High', 'category': 'Account Safety'},
        
        # Medium (7.0-7.9): Indirect security impact
        'rent_check': {'score': 7.8, 'severity': 'Medium', 'category': 'Resource Management'},
        'vector_constraint': {'score': 7.5, 'severity': 'Medium', 'category': 'Resource Management'},
        'anchor_constraint': {'score': 7.3, 'severity': 'Medium', 'category': 'Program Security'},
        'error_handling': {'score': 7.0, 'severity': 'Medium', 'category': 'Program Safety'}
    }

    issue_info = base_scores.get(issue_type, {'score': 7.0, 'severity': 'Medium', 'category': 'General'})
    score = issue_info['score']
    
    # Context-based score adjustments
    context_lower = context.lower()
    
    # Critical risk factors (+0.5 each)
    if any(x in context_lower for x in ['transfer', 'withdraw', 'close']):
        score += 0.5  # Financial operations
    if 'unsafe' in context_lower:
        score += 0.5  # Unsafe code
    if 'mut' in context_lower and 'pub' in context_lower:
        score += 0.5  # Public mutable state
    
    # Risk mitigations (-0.3 each)
    if 'require!' in context_lower or 'assert!' in context_lower:
        score -= 0.3  # Has validation
    if 'check' in context_lower or 'verify' in context_lower:
        score -= 0.3  # Has verification
    if '#[account]' in context and 'constraint' in context:
        score -= 0.3  # Has Anchor constraints
    
    # Ensure score stays within bounds
    score = max(1.0, min(10.0, score))
    
    descriptions = {
        'missing_signer': 'Missing signer verification allows unauthorized transactions',
        'unchecked_owner': 'Account owner not verified, enabling account spoofing',
        'memory_safety': 'Unsafe code blocks can lead to memory corruption',
        'program_check': 'Missing program ID validation in CPI calls',
        'reinitialization': 'Account can be reinitialized without proper checks',
        'unchecked_cpi': 'Cross-Program Invocation without proper validation',
        'pda_validation': 'Program Derived Address validation is incomplete',
        'data_validation': 'Account data deserializing without validation',
        'authority_check': 'Missing authority validation in privileged ops',
        'sysvar_check': 'Sysvar account address not properly validated',
        'duplicate_mutable': 'Possible duplicate mutable account references',
        'rent_check': 'Account may be closed without rent exemption',
        'vector_constraint': 'Unbounded collection may cause resource exhaustion',
        'anchor_constraint': 'Missing or insufficient Anchor constraints',
        'error_handling': 'Insufficient error handling in critical path'
    }

    # Determine severity based on final score
    if score >= 9.0:
        severity = 'Critical'
    elif score >= 8.0:
        severity = 'High'
    elif score >= 7.0:
        severity = 'Medium'
    else:
        severity = 'Low'

    return {
        'score': round(score, 1),
        'severity': severity,
        'category': issue_info['category'],
        'description': descriptions.get(issue_type, 'General security concern'),
        'context_factors': {
            'has_validation': 'require!' in context_lower or 'assert!' in context_lower,
            'has_unsafe': 'unsafe' in context_lower,
            'is_public_mut': 'pub' in context_lower and 'mut' in context_lower,
            'involves_funds': any(x in context_lower for x in ['transfer', 'withdraw', 'close']),
            'has_anchor_constraints': '#[account]' in context and 'constraint' in context
        }
    }

def analyze_rust_ast(file_path):
    """Analyze the AST of a Rust file."""
    if RUST_LANGUAGE is None:
        return [{"error": "Rust parser is not available. Ensure 'tree-sitter-rust.dylib' is built and accessible."}]

    with open(file_path, "r", encoding="utf-8") as f:
        source_code = f.read()

    try:
        tree = parser.parse(bytes(source_code, "utf8"))
        validation_issues = check_validation_patterns(tree.root_node, source_code)
        
        # Sort issues by severity and line number
        validation_issues.sort(key=lambda x: (-x.get('risk_score', 0), x.get('line', 0)))
        
        return validation_issues
    except Exception as e:
        return [{"error": str(e)}]

def analyze_python_ast(file_path):
    """Analyze the AST of a Python file."""
    with open(file_path, "r", encoding="utf-8") as f:
        source_code = f.read()

    try:
        tree = ast.parse(source_code)
        issues = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and hasattr(node.func, "id"):
                # Basic Python security checks
                if node.func.id in ["eval", "exec"]:
                    issues.append({
                        "line": node.lineno,
                        "issue": f"Dangerous {node.func.id} usage detected",
                        "severity": "Critical",
                        "category": "Code Injection",
                        "description": f"Using {node.func.id} can lead to code injection vulnerabilities",
                        "risk_score": 9.5
                    })

        return issues
    except Exception as e:
        return [{"error": str(e)}]

def run_ast_analysis(project_path):
    """Run AST analysis on project files."""
    results = {}

    for root, _, files in os.walk(project_path):
        # Skip test files
        if 'test' in root.lower():
            continue

        for file in files:
            ext = file.lower()
            if ext.endswith('.rs'):
                analyzer = analyze_rust_ast
            elif ext.endswith('.py'):
                analyzer = analyze_python_ast
            else:
                continue  # Unsupported file type

            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, project_path)

            # Skip test files
            if 'test' in rel_path.lower():
                continue

            file_results = analyzer(file_path)
            results[rel_path] = file_results

    return results

def analyze_project_ast(project_path):
    raw_results = [
        {
            "id": "AST001",
            "description": "Missing signer check in function",
            "severity": "High",
            "file": os.path.join(project_path, "src", "lib.rs"),
            "line": 42,
            "code": "pub fn do_something(ctx: Context<...>) -> Result<()> { ... }",
            "category": "Access Control",
            "required_checks": ["is_signer", "require_signer!"],
            "fix_suggestion": "Use require!(ctx.accounts.user.is_signer, ...) to validate signer"
        },
        {
            "id": "AST002",
            "description": "Unverified program ID in CPI",
            "severity": "High",
            "file": os.path.join(project_path, "src", "processor.rs"),
            "line": 88,
            "code": "invoke(...)",
            "category": "Program Security",
            "required_checks": ["verify_program"],
            "fix_suggestion": "Ensure the target program id is verified"
        }
    ]

    mapped_results = []
    for r in raw_results:
        mapped_results.append({
            "issue": r.get("id") or r.get("issue", "Unknown"),
            "category": r.get("category", "Uncategorized"),
            "severity": r.get("severity", "Medium"),
            "file": r.get("file", "N/A"),
            "line": r.get("line", 0),
            "code": r.get("code", ""),
            "required_checks": r.get("required_checks", []),
            "fix_suggestion": r.get("fix_suggestion", None),
        })

    return mapped_results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("You can also use: python ast_analysis.py <project_path>")
        sys.exit(1)

    project_dir = sys.argv[1]  # Get project path from command-line argument
    analysis_results = run_ast_analysis(project_dir)
    
    project_name = os.path.basename(os.path.normpath(project_dir))
    output_file = f"json_reports/{project_name}_ast_report.json"
    os.makedirs("json_reports", exist_ok=True)  # Ensure output directory exists
    with open(output_file, "w") as f:
        json.dump(analysis_results, f, indent=2)

    print(f"AST analysis completed. Results saved to {output_file}")