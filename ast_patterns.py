"""
Solana AST patterns for vulnerability detection.
"""

from typing import Dict, Any

SOLANA_AST_PATTERNS: Dict[str, Dict[str, Any]] = {
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

# Severity score mappings
SEVERITY_SCORES = {
    'Critical': {'base': 9.0, 'range': (9.0, 10.0)},
    'High': {'base': 7.5, 'range': (7.0, 8.9)},
    'Medium': {'base': 5.0, 'range': (5.0, 6.9)},
    'Low': {'base': 2.5, 'range': (1.0, 4.9)}
}

# Risk factor adjustments
RISK_FACTORS = {
    'critical': {
        'transfer_ops': 0.5,  # Financial operations
        'unsafe_code': 0.5,   # Unsafe code blocks
        'pub_mut': 0.5,       # Public mutable state
    },
    'mitigations': {
        'validation': -0.3,   # Has validation checks
        'verification': -0.3, # Has verification logic
        'constraints': -0.3,  # Has Anchor constraints
    }
}

# Validation patterns by type
VALIDATION_PATTERNS = {
    'signer': [
        'is_signer',
        '#[account(signer)]',
        'require!(',
        'assert!('
    ],
    'owner': [
        '.owner',
        'assert_eq!(*account.owner',
        'check_owner',
        'validate_owner'
    ],
    'program': [
        'check_program_id',
        'verify_program_id',
        'assert_eq!(*program_id'
    ],
    'pda': [
        'seeds =',
        'bump =',
        'assert_pda',
        'validate_pda'
    ],
    'arithmetic': [
        'checked_add',
        'checked_sub',
        'checked_mul',
        'checked_div',
        'safe_math::'
    ],
    'generic': [
        'require!(',
        'assert!(',
        'validate',
        'check_',
        'verify_'
    ]
}

# Issue descriptions
ISSUE_DESCRIPTIONS = {
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