"""
ChapacoSolSec - Solana Smart Contract Security Analysis Tool

This module provides core functionality for analyzing Solana smart contracts
for security vulnerabilities and best practices. It uses pattern matching
and Security analysis to identify potential issues.
"""

import git
import os
import regex as re
import json
import logging
import pandas as pd
import io
from typing import List, Dict, Pattern, Optional, Union
from collections import Counter
from flask import Response, send_file
from tree_sitter import Language, Parser
import toml
import subprocess
from pathlib import Path
import tempfile
import git
from logger_config import setup_logger

logger = setup_logger('analysis', 'logs/analysis.log')

def setup_tree_sitter():
    """Set up tree-sitter parser for Rust code analysis."""
    try:
        # Get the absolute path of the current directory
        current_dir = os.path.abspath(os.path.dirname(__file__))
        
        # Define paths using absolute paths
        build_dir = os.path.join(current_dir, 'build')
        lib_path = os.path.join(build_dir, 'my-languages.so')
        vendor_path = os.path.join(current_dir, 'vendor', 'tree-sitter-rust')
        
        # Create build directory if it doesn't exist
        os.makedirs(build_dir, exist_ok=True)
        
        # Create vendor directory if it doesn't exist
        os.makedirs(vendor_path, exist_ok=True)
        
        # Clone tree-sitter-rust if it doesn't exist
        if not os.path.exists(os.path.join(vendor_path, 'src')):
            logger.info("Cloning tree-sitter-rust...")
            subprocess.run(['git', 'clone', 'https://github.com/tree-sitter/tree-sitter-rust.git', vendor_path], check=True)
        
        # Build the library if it doesn't exist
        if not os.path.exists(lib_path):
            logger.info("Building tree-sitter library...")
            Language.build_library(lib_path, [vendor_path])
        
        # Initialize the language
        try:
            # Ensure the library exists and is readable
            if not os.path.exists(lib_path):
                raise FileNotFoundError(f"Tree-sitter library not found at {lib_path}")
            
            # Initialize language with the library path
            rust_language = Language(lib_path, 'rust')
            if not rust_language:
                raise RuntimeError("Failed to create language object")
                
            # Create and configure parser
            parser = Parser()
            parser.set_language(rust_language)
            
            logger.info("Tree-sitter parser initialized successfully")
            return parser, rust_language
            
        except Exception as e:
            logger.error(f"Failed to initialize language: {str(e)}")
            return None, None
        
    except Exception as e:
        logger.error(f"Failed to initialize tree-sitter: {str(e)}")
        return None, None

def convert_to_markdown(data: List[Dict], base_filename: str) -> Union[Response, tuple[str, int]]:
    """Convert analysis results to a formatted Markdown document.

    Args:
        data: List of analysis results, each a dictionary of findings
        base_filename: Base name for the output file

    Returns:
        Flask Response object with Markdown content or error tuple
    """
    if not data:
        return "No data to export", 400
        
    output = io.StringIO()
    output.write(f"# Security Analysis Report: {base_filename}\n\n")
    output.write("## Overview\n")
    output.write(f"Total Issues Found: {len(data)}\n\n")
    
    # Group issues by severity
    severity_groups = {}
    for item in data:
        severity = item.get('severity', 'Unknown')
        if severity not in severity_groups:
            severity_groups[severity] = []
        severity_groups[severity].append(item)
    
    # Write issues grouped by severity
    for severity in ['Critical', 'High', 'Medium', 'Low', 'Unknown']:
        if severity in severity_groups:
            output.write(f"## {severity} Severity Issues\n")
            for item in severity_groups[severity]:
                output.write(f"### {item.get('id', 'Unknown ID')}\n")
                for key, value in item.items():
                    if key != 'id':
                        output.write(f"**{key.capitalize()}**: `{value}`\n")
                output.write("\n---\n\n")

    output.seek(0)
    return Response(
        output,
        mimetype="text/markdown",
        headers={
            "Content-Disposition": f"attachment;filename={base_filename}.md"
        }
    )

def convert_to_csv(data, base_filename):
    import csv
    output = io.StringIO()
    if not data:
        return "No data to export", 400

    keys = data[0].keys()
    writer = csv.DictWriter(output, fieldnames=keys)
    writer.writeheader()
    for row in data:
        writer.writerow(row)

    output.seek(0)
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={base_filename}.csv"}
    )

def convert_to_txt(data, base_filename):
    output = io.StringIO()
    if not data:
        return "No data to export", 400
    for idx, item in enumerate(data, 1):
        output.write(f"Issue {idx}:\n")
        for key, value in item.items():
            output.write(f"{key.capitalize()}: {value}\n")
        output.write("\n" + "-"*40 + "\n\n")

    output.seek(0)
    return Response(
        output,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment;filename={base_filename}.txt"}
    )

def convert_to_html(data, base_filename):
    output = io.StringIO()
    if not data:
        return "No data to export", 400
    output.write(f"<!DOCTYPE html><html><head><meta charset='UTF-8'><title>{base_filename}</title></head><body>")
    output.write(f"<h1>Security Analysis Report: {base_filename}</h1>")

    for idx, item in enumerate(data, 1):
        output.write(f"<h2>Issue {idx}</h2><ul>")
        for key, value in item.items():
            output.write(f"<li><strong>{key.capitalize()}</strong>: <code>{value}</code></li>")
        output.write("</ul><hr>")

    output.write("</body></html>")
    output.seek(0)

    return Response(
        output,
        mimetype="text/html",
        headers={"Content-Disposition": f"attachment;filename={base_filename}.html"}
    )

# Logging configuration
logging.basicConfig(level=logging.INFO)

# Load tree-sitter Rust parser
LIB_PATH = 'build/my-languages.so'
if not os.path.exists(LIB_PATH):
    Language.build_library(LIB_PATH, ['vendor/tree-sitter-rust'])
RUST_LANGUAGE = Language(LIB_PATH, 'rust')

# Solana vulnerability patterns
SOLANA_PATTERNS = {
    # Account validation patterns
    'missing_signer': r'#\[derive\(Accounts\)\][^}]*pub struct \w+[^}]*?(?:authority|signer|admin|owner):\s*(?:AccountInfo|Account|UncheckedAccount)[^}]*\}(?!.*(?:Signer|#\[signer\]))',
    'account_validation': r'#\[derive\(Accounts\)\][^}]*pub struct \w+[^}]*?\w+:\s*AccountInfo[^}]*\}(?!.*Account<|.*#\[account\])',
    # Existing patterns
    'cpi': r'\binvoke\(\s*&?ctx\s*,\s*(?!&ID|&program_id).*?\)',
    'account_init': r'\btry_from_slice\s*\((?!.*is_initialized|.*initialized).*?\)',
    'token_transfer': r'\btoken::transfer\s*\((?!.*verify|.*check).*?\)',
    'sol_transfer': r'\bsystem_instruction::transfer\s*\((?!.*owner|.*authority).*?\)',
    'pda': r'\bPubkey::find_program_address\s*\([^)]*\)(?!.*validate|.*check)',
    'account_mut': r'\b(?:ctx\.accounts|accounts\[\d+\])\.data\.borrow_mut\(\)(?!.*authority)',
    'arithmetic': r'\b(u64|u128)\s*[+\-*/]\s*\w+(?!.*checked)',
    'sysvar': r'\bsysvar::clock::Clock::get\((?!.*slot)'
}

# Compile regex patterns
SOLANA_REGEX: Dict[str, Pattern] = {k: re.compile(v) for k, v in SOLANA_PATTERNS.items()}

# Main vulnerability detection patterns
VULNERABILITY_PATTERNS = {
    "Solana": [
        {"id": "SOL001", "severity": "Critical", "regex": SOLANA_REGEX["missing_signer"], "description": "Missing signer verification in account validation - Authority account is not verified as a signer"},
        {"id": "SOL002", "severity": "Critical", "regex": SOLANA_REGEX["account_validation"], "description": "Insufficient account validation - Using raw AccountInfo without proper Account constraints"},
        {"id": "RUST002", "severity": "Medium", "regex": re.compile(r"(?<!expect\()\.unwrap\(\)(?!\s*//)"), "description": "Unwrap used without error handling."},
        {"id": "VULN040b", "severity": "High", "regex": re.compile(r"invoke\(\s*&?ctx,.*?\)"), "description": "Unverified target program ID in CPI (Raw Solana Rust)."},
        {"id": "VULN014", "severity": "High", "regex": re.compile(r"token::transfer\(&ctx,\s*amount\)"), "description": "Token transfer without signature verification may allow unauthorized transactions."},
        {"id": "VULN008", "severity": "High", "regex": re.compile(r"invoke_signed\("), "description": "Unchecked CPI with program-derived addresses (PDAs) could allow unauthorized transactions."},
        {"id": "VULN011", "severity": "Medium", "regex": re.compile(r"for\s+\w+\s+in\s+0\s*\.\.\s*(\d{5,}|MAX)"), "description": "Potential excessive looping causing high compute unit consumption."},
        {"id": "RUST008", "severity": "High", "regex": re.compile(r"std::fs::File::open\(.+?\)\.(unwrap|expect)\(\s*(\".*?\"|\'.*?\')?\)"), "description": "File handling with unwrap can cause runtime panics."},
        {"id": "RUST010", "severity": "High", "regex": re.compile(r"std::net::TcpListener::bind\(.+?\)\.unwrap\(\)"), "description": "TCP binding with unwrap (potential crash)."},
        {"id": "VULN012", "severity": "Medium", "regex": re.compile(r"std::iter::repeat"), "description": "Use of `std::iter::repeat` can lead to excessive compute unit usage."},
        {"id": "VULN002", "severity": "High", "regex": re.compile(r"try_from_slice\(&ctx.accounts.\w+.data.borrow\(\)\?\)"), "description": "Unchecked Account Deserialization."},
        {"id": "VULN013", "severity": "High", "regex": re.compile(r"vec!\[\w+\]\.resize\("), "description": "Resizing large vectors may lead to excessive memory allocation."},
        {"id": "VULN009", "severity": "High", "regex": re.compile(r"system_instruction::transfer\("), "description": "Direct SOL transfer without ownership verification."},
        {"id": "VULN006", "severity": "High", "regex": re.compile(r"sysvar::clock::Clock::get\("), "description": "Direct clock sysvar access can enable replay attacks."},
        {"id": "VULN010", "severity": "High", "regex": re.compile(r"account_info\.try_borrow_mut_data\(\)"), "description": "Unchecked mutable borrow of account data."},
        {"id": "VULN007", "severity": "High", "regex": re.compile(r"invoke\("), "description": "Unchecked CPI call, which may execute unintended external programs."},
        {"id": "VULN005", "severity": "High", "regex": re.compile(r"Pubkey::find_program_address\([^\)]*\)(?!.*expected)"), "description": "Potential misuse of PDA without verification."},
        {"id": "VULN004", "severity": "High", "regex": re.compile(r"Pubkey::create_program_address\("), "description": "Manually creating PDA without validation."},
        {"id": "RUST012", "severity": "High", "regex": re.compile(r"\.get_unchecked\("), "description": "Unchecked array indexing can cause out-of-bounds errors."},
        {"id": "VULN024b", "severity": "High", "regex": re.compile(r"Pubkey::create_program_address\(&\["),},
        {"id": "RUST009", "severity": "High", "regex": re.compile(r"std::process::Command"), "description": "Use of system command execution (security risk)."},
        {"id": "RUST004", "severity": "High", "regex": re.compile(r"mem::transmute"), "description": "Use of mem::transmute can lead to undefined behavior."},
        {"id": "RUST003", "severity": "High", "regex": re.compile(r"mem::uninitialized\(\)|mem::zeroed\(\)"), "description": "Use of uninitialized memory."},
        {"id": "RUST005", "severity": "Medium", "regex": re.compile(r"\bunwrap\(\)(?!\s*//)"), "description": "Unhandled error (unwrap)."},
        {"id": "VULN093", "severity": "Medium", "regex": re.compile(r"panic!\("), "description": "Overuse of Panics for Control Flow"},
        {"id": "VULN003", "severity": "High", "regex": re.compile(r"invoke\(\[.*?\], &[.*?]\)"), "description": "CPI to Unauthorized Programs."},
        {"id": "VULN001", "severity": "High", "regex": re.compile(r"next_account_info\s*\("), "description": "Potential Missing signer verification."},
        {"id": "RUST019", "severity": "High", "regex": re.compile(r"(?<!\w\s)\*\s*\w+(?!\s*\*)"), "description": "Unsafe pointer dereferencing"},
        {"id": "RUST017", "severity": "High", "regex": re.compile(r"str::as_ptr"), "description": "Direct string pointer access can cause memory issues"},
        {"id": "VULN086", "severity": "High", "regex": re.compile(r"if\s+!\s*\w+\.is_signer"), "description": "Signer verification missing, allowing unauthorized transactions."},
        {"id": "VULN222", "severity": "Critical", "regex": re.compile(r"try_from_slice\s*\("), "description": "Account reinitialized without checking if it's already initialized."},
        {"id": "VULN223", "severity": "Critical", "regex": re.compile(r"(try_from_slice\s*\(|\b\w+::try_from_slice\s*\()", re.DOTALL), "description": "Account reinitialized without checking if it's already initialized."},
    ],
    "Intermediate": [
        {"id": "RUST006", "severity": "High", "regex": re.compile(r"rand::thread_rng\(\)"), "description": "Use of insecure random generator."},
        {"id": "RUST013", "severity": "Low", "regex": re.compile(r"\sas\s(u8|u16|u32|u64|u128|usize)"), "description": "Unchecked integer cast"},
        {"id": "VULN015", "severity": "Medium", "regex": re.compile(r"ctx.accounts.transfer_ctx\(\).with_signer\(&\[\w+\]\)"), "description": "Improper PDA signer verification, leading to unauthorized fund transfers."},
        {"id": "VULN111", "severity": "High", "regex": re.compile(r"sysvar::clock::Clock::get\("), "description": "Direct access to the clock sysvar can enable replay attacks."},
        {"id": "VULN019b", "severity": "High", "regex": re.compile(r"accounts\[\d+\]\.owner\s*!=\s*&\s*Pubkey::default\(\)"), "description": "Missing owner field verification in raw Solana Rust."},
        {"id": "VULN031b", "severity": "High", "regex": re.compile(r"(u64|u128)\s*\.\s*(checked_add|checked_sub|checked_mul|checked_div)\s*\(\s*\w+"), "description": "Unchecked integer subtraction may cause underflow (Raw Solana Rust)."},
        {"id": "VULN019a", "severity": "High", "regex": re.compile(r"ctx.accounts\.\w+\.owner\s*!=\s*&\s*Pubkey::default\(\)"), "description": "Missing owner field verification in Anchor."},
        {"id": "VULN030b", "severity": "High", "regex": re.compile(r"\w+\s*\+\s*\w+(?!.*checked_add)"), "description": "Unchecked integer addition may cause overflow (Raw Solana Rust)."},
        {"id": "VULN108", "severity": "Medium", "regex": re.compile(r"for\s+\w+\s+in\s+0\s*\.\.\s*\d{5,}"), "description": "Potential excessive looping consuming high compute units."},
        {"id": "VULN030a", "severity": "High", "regex": re.compile(r"\w+\s*\+\s*\w+(?!.*checked_add)"), "description": "Unchecked integer addition may cause overflow (Anchor)."},
        {"id": "VULN024a", "severity": "High", "regex": re.compile(r"Pubkey::create_program_address\(&\["), "description": "Improper validation of PDA bump seeds (Anchor)."},
        {"id": "VULN040a", "severity": "High", "regex": re.compile(r"solana_program::program::invoke\("), "description": "Unverified target program ID in CPI (Anchor)."},
        {"id": "VULN109", "severity": "High", "regex": re.compile(r"unsafe\s*\{"), "description": "Unsafe code block detected, which may lead to memory corruption."},
        {"id": "VULN090", "severity": "High", "regex": re.compile(r"invoke\([^\)]*\)\s*;(?!\s*if)"), "description": "Unchecked return value from CPI call"},
        {"id": "VULN072", "severity": "Medium", "regex": re.compile(r"if\s+account\.owner\s*!=\s*&\s*Pubkey::default\(\)"), "description": "Potential missing owner check, enabling unauthorized account modifications."},
    ],
    "Advanced": [
        {"id": "VULN078", "severity": "High", "regex": re.compile(r"solana_program::sysvar::instructions::load_current_index\("), "description": "Sysvar instruction index is accessed without checking authenticity, leading to possible instruction reordering attacks."},
        {"id": "VULN078a", "severity": "High", "regex": re.compile(r"solana_program::sysvar::instructions::load_current_index\(\s*&accs\.\w+\.try_borrow_mut_data\(\)?\s*\)"), "description": "Unsafe instruction index access with mutable borrow in Anchor, potential for instruction reordering attacks."},
        {"id": "VULN078b", "severity": "High", "regex": re.compile(r"solana_program::sysvar::instructions::load_current_index\(\s*&accounts\[\d+\]\.try_borrow_mut_data\(\)?\s*\)"), "description": "Unsafe instruction index access with mutable borrow in Raw Solana Rust, potential for instruction reordering attacks."},
        {"id": "VULN049", "severity": "Critical", "regex": re.compile(r"Vec::with_capacity\s*\(\s*\d{6,}\s*\)"), "description": "Potential memory exhaustion via large allocation"},
        {"id": "VULN101", "severity": "High", "regex": re.compile(r"Box::new\(\[0;\s*\d{6,}\]\)"), "description": "Potential excessive heap allocation."},
        {"id": "VULN105b", "severity": "High", "regex": re.compile(r"try_from_slice\(&accounts\[\d+\]\.data\.borrow\(\)\?\)"), "description": "Deserializing accounts without validation can lead to unintended account modifications (Raw Solana Rust)."},
        {"id": "VULN105a", "severity": "High", "regex": re.compile(r"try_from_slice\(&ctx.accounts.\w+\.data\.borrow\(\)\?\)"), "description": "Deserializing accounts without validation can lead to unintended account modifications (Anchor)."},
        {"id": "VULN100a", "severity": "High", "regex": re.compile(r"pub\s+fn\s+\w+\s*\(ctx:\s*Context<\w+>\)\s*->\s*ProgramResult\s*\{"), "description": "Signer check is missing, which could allow unauthorized transactions in Anchor programs."},
        {"id": "VULN016a", "severity": "High", "regex": re.compile(r"(SplTokenAccount|spl_token(::state)?::Account)::unpack\(&ctx\.accounts\.\w+\.data\.borrow(_mut)?\(\)\)"), "description": "Account Data Matching - Anchor"},
        {"id": "VULN016b", "severity": "High", "regex": re.compile(r"SplTokenAccount::unpack\(&ctx\.accounts\.\w+\.data\.borrow\(\)\)"), "description": "Owner Checks - Anchor"},
        {"id": "VULN018b", "severity": "High", "regex": re.compile(r"SplTokenAccount::unpack\(&accounts\[\d+\]\.data\.borrow\(\)\)"), "description": "Missing verification of token ownership or mint authority in SPL Token accounts (Raw Solana Rust)."},
        {"id": "VULN018a", "severity": "High", "regex": re.compile(r"SplTokenAccount::unpack\(&ctx\.accounts\.\w+\.data\.borrow\(\)\)"), "description": "Missing verification of token ownership or mint authority in SPL Token accounts (Anchor)."},
        {"id": "VULN050a", "severity": "High", "regex": re.compile(r"\*\*ctx.accounts.account.to_account_info\(\).lamports.borrow_mut\(\) = 0;"), "description": "Improper closing of accounts may leave them vulnerable to misuse (Anchor)."},
        {"id": "VULN051", "severity": "High", "regex": re.compile(r"while\s*\(\s*true\s*\)"), "description": "Infinite loop detected"},
        {"id": "VULN017a", "severity": "High", "regex": re.compile(r"pub\s+fn\s+\w+\s*\(ctx:\s*Context<\w+>\)\s*->\s*ProgramResult\s*\{"), "description": "Signer check is missing, which could lead to unauthorized execution in Anchor."},
        {"id": "VULN025a", "severity": "High", "regex": re.compile(r"token::transfer\(ctx.accounts.transfer_ctx\(\).with_signer\(&\[\w+\]\),"), "description": "Sharing PDA across multiple roles without proper permission separation (Anchor)."},
        {"id": "VULN106", "severity": "High", "regex": re.compile(r"system_instruction::transfer\("), "description": "Directly transferring SOL without verifying the recipient may lead to unauthorized fund movement."},
        {"id": "VULN100b", "severity": "High", "regex": re.compile(r"fn\s+\w+\s*\(\s*accounts:\s+&\[AccountInfo<'info>\]"), "description": "Signer verification missing in raw Solana Rust, enabling unauthorized execution."},
        {"id": "VULN017b", "severity": "High", "regex": re.compile(r"fn\s+\w+\s*\(\s*accounts:\s+&\[AccountInfo<'info>\]"), "description": "Signer check is missing in raw Solana Rust programs, leading to unauthorized execution."},
        {"id": "VULN101b", "severity": "High", "regex": re.compile(r"Pubkey::find_program_address\(\[.*?\],\s*&\s*program_id\)"), "description": "Potential PDA misuse in raw Solana Rust; ensure PDA is properly verified."},
        {"id": "VULN101a", "severity": "High", "regex": re.compile(r"Pubkey::find_program_address\(\[.*?\],\s*&\s*self\.program_id\)"), "description": "Potential PDA misuse in Anchor; ensure PDA is properly verified."},
        {"id": "VULN050b", "severity": "High", "regex": re.compile(r"accounts\[\d+\]\.lamports\.borrow_mut\(\) = 0;"), "description": "Improper closing of accounts may leave them vulnerable to misuse (Raw Solana Rust)."},
        {"id": "VULN025b", "severity": "High", "regex": re.compile(r"invoke_signed\(\s*.*, &\[\s*.*?\], &\[\s*\]\)"), "description": "Sharing PDA across multiple roles without proper permission separation (Raw Solana Rust)."},
        {"id": "VULN026", "severity": "High", "regex": re.compile(r"\.clone\(|Vec::with_capacity\(|String::with_capacity\("), "description": "Potential DoS Vulnerability - Memory Exhaustion."},
        {"id": "VULN027", "severity": "Medium", "regex": re.compile(r"std::fs|std::net"), "description": "Blocking I/O in Asynchronous Code."},
        {"id": "VULN028", "severity": "Medium", "regex": re.compile(r"impl\s+Drop\s+for\s+.*?\s*\{.*\}"), "description": "Improper Implementation of Drop Trait."},
        {"id": "VULN089", "severity": "High", "regex": re.compile(r"Pubkey::create_program_address\([^,]+,\s*&\[\]"), "description": "Empty seeds in PDA derivation"},
        {"id": "VULN091", "severity": "High", "regex": re.compile(r"Instruction::new_with_bincode\("), "description": "Potential Malformed Instruction Injection"},
        {"id": "VULN092", "severity": "High", "regex": re.compile(r"Instruction::new_with_bytes\("), "description": "Potential Malformed Instruction Injection"},
        {"id": "VULN220b", "severity": "Critical", "regex": re.compile(r"\w+::try_from_slice\(&ctx\.accounts\.\w+\.data\.borrow\(\)\)"), "description": "Potential type cosplay attack in raw Solana Rust due to unchecked deserialization."},
        {"id": "VULN221b", "severity": "Critical", "regex": re.compile(r"\w+::try_from_slice\(&accounts\[\d+\]\.data\.borrow\(\)\)"), "description": "Potential type cosplay attack in raw Solana Rust due to unchecked deserialization."},
        {"id": "VULN230", "severity": "High", "regex": re.compile(r"if\s+!\s*ctx.accounts.\w+.to_account_info\(\).is_rent_exempt\(\)"), "description": "Rent exemption check is missing, which could lead to account closure issues."},
        {"id": "VULN231", "severity": "High", "regex": re.compile(r"spl_token::instruction::set_authority\(ctx.accounts.token_program, ctx.accounts.token_account, ctx.accounts.new_authority, "), "description": "Authority modification without proper validation can lead to unauthorized control over the token account."},
        {"id": "VULN232", "severity": "Critical", "regex": re.compile(r"ctx.accounts.mint.to_account_info\(\).data.borrow\(\)"), "description": "Mint authority should be explicitly checked to prevent unauthorized token minting."},
        {"id": "VULN233", "severity": "High", "regex": re.compile(r"ctx.accounts.\w+.data.borrow\(\).len\(\)"), "description": "Account data length should be validated to prevent memory corruption or unexpected behavior."},
        {"id": "VULN234", "severity": "High", "regex": re.compile(r"Pubkey::find_program_address\(\[.*?\],\s*&self.program_id\)"), "description": "Ensure PDA derivation correctly validates seeds and expected addresses to avoid security issues."},
        {"id": "VULN231", "severity": "High", "regex": re.compile(r"\bspl_token::instruction::set_authority\(\s*ctx.accounts.token_program,\s*ctx.accounts.token_account,\s*ctx.accounts.new_authority,\s*"),  "description": "Authority modification without proper validation can lead to unauthorized control over the token account."},
        {"id": "VULN232", "severity": "Critical", "regex": re.compile(r"\bctx.accounts.mint\.to_account_info\(\)\.data\.borrow\(\)"),  "description": "Mint authority should be explicitly checked to prevent unauthorized token minting."},
        {"id": "VULN233", "severity": "High", "regex": re.compile(r"\bctx.accounts\.\w+\.data\.borrow\(\)\.len\(\)"),  "description": "Account data length should be validated to prevent memory corruption or unexpected behavior."},
        {"id": "VULN234", "severity": "High", "regex": re.compile(r"\bPubkey::find_program_address\(\s*\[.*?\],\s*&self\.program_id\s*\)"),  "description": "Ensure PDA derivation correctly validates seeds and expected addresses to avoid security issues."},
        {"id": "VULN235a", "severity": "High", "regex": re.compile(r"\bif\s+ctx.accounts.\w+\.owner\s*!=\s*&\s*system_program::ID\b"),  "description": "The system program should be explicitly checked to ensure that accounts are owned by the system program (Anchor)."},
        {"id": "VULN235b", "severity": "High", "regex": re.compile(r"\baccounts\[\d+\]\.owner\s*!=\s*&\s*system_program::ID\b"),  "description": "The system program should be explicitly checked to ensure that accounts are owned by the system program (Raw Solana Rust)."},
        {"id": "VULN236a", "severity": "Critical", "regex": re.compile(r"\bPubkey::find_program_address\(\s*\[.*?\],\s*&self\.program_id\s*\)"),  "description": "Ensure that PDAs are verified against expected values to prevent unauthorized substitutions (Anchor)."},
        {"id": "VULN236b", "severity": "Critical", "regex": re.compile(r"\bPubkey::find_program_address\(\s*\[.*?\],\s*&program_id\s*\)"),  "description": "Ensure that PDAs are verified against expected values to prevent unauthorized substitutions (Raw Solana Rust)."},
        {"id": "VULN237a", "severity": "High", "regex": re.compile(r"\b(\w+\s*/\s*0)\b(?!.*checked_div)"),  "description": "Division by zero will cause runtime panic; consider using `checked_div` (Anchor)."},
        {"id": "VULN237b", "severity": "High", "regex": re.compile(r"\b(\w+\s*/\s*0)\b(?!.*checked_div)"),  "description": "Division by zero will cause runtime panic; consider using `checked_div` (Raw Solana Rust)."},
        {"id": "VULN238a", "severity": "Medium", "regex": re.compile(r"\b(f32|f64)\b\s*\.\s*\w+\s*as\s*(u8|u16|u32|u64|usize)\b"),  "description": "Lossy conversion from floating point to integer detected; ensure proper rounding or verification (Anchor)."},
        {"id": "VULN238b", "severity": "Medium", "regex": re.compile(r"\b(f32|f64)\b\s*\.\s*\w+\s*as\s*(u8|u16|u32|u64|usize)\b"),  "description": "Lossy conversion from floating point to integer detected; ensure proper rounding or verification (Raw Solana Rust)."},
        {"id": "VULN239a", "severity": "Critical", "regex": re.compile(r"\bctx.accounts.\w+\.data\.borrow_mut\(\)"),  "description": "Mutable borrowing of account data without proper access control may lead to race conditions (Anchor)."},
        {"id": "VULN239b", "severity": "Critical", "regex": re.compile(r"\baccounts\[\d+\]\.data.borrow_mut\(\)"),  "description": "Mutable borrowing of account data without proper access control may lead to race conditions (Raw Solana Rust)."},
        {"id": "VULN240a", "severity": "High", "regex": re.compile(r"\bctx.accounts.\w+\.lamports\(\)"),  "description": "Direct access to lamports without validation may lead to security risks (Anchor)."},
        {"id": "VULN240b", "severity": "High", "regex": re.compile(r"\baccounts\[\d+\]\.lamports\(\)"),  "description": "Direct access to lamports without validation may lead to security risks (Raw Solana Rust)."},
    ],
    "Anchor": [
        # Signer Authorization
        {"id": "ANCH001", "severity": "Critical", "regex": re.compile(r"AccountInfo<'info>"), "description": "Missing signer verification - Using raw AccountInfo without Signer constraint"},
        
        # Account Data Matching
        {"id": "ANCH002", "severity": "Critical", "regex": re.compile(r"SplTokenAccount::unpack\(&ctx\.accounts\.\w+\.data\.borrow\(\)\)"), "description": "Insecure account data matching - Unpacking token account without proper validation"},
        
        # Owner Checks
        {"id": "ANCH003", "severity": "Critical", "regex": re.compile(r"if\s+ctx\.accounts\.\w+\.key\s*!=\s*&token\.owner"), "description": "Insecure owner check - Manual owner verification instead of using Account<'info> constraint"},
        
        # Type Cosplay
        {"id": "ANCH004", "severity": "Critical", "regex": re.compile(r"try_from_slice\(&ctx\.accounts\.\w+\.data\.borrow\(\)\)"), "description": "Type cosplay vulnerability - Unchecked deserialization of account data"},
        
        # Initialization
        {"id": "ANCH005", "severity": "Critical", "regex": re.compile(r"try_from_slice\(&ctx\.accounts\.\w+\.data\.borrow\(\)\)(?!.*is_initialized)"), "description": "Missing initialization check - Deserializing account without checking if it's initialized"},
        
        # Arbitrary CPI
        {"id": "ANCH006", "severity": "Critical", "regex": re.compile(r"invoke\(&ctx\.accounts\.\w+\.to_account_info\(\)"), "description": "Arbitrary CPI vulnerability - Invoking program without verifying its ID"},
        
        # Duplicate Mutable Accounts
        {"id": "ANCH007", "severity": "Critical", "regex": re.compile(r"\.data\.borrow_mut\(\)"), "description": "Duplicate mutable account access - Multiple mutable borrows of same account data"},
        
        # Bump Seed Canonicalization
        {"id": "ANCH008", "severity": "Critical", "regex": re.compile(r"Pubkey::find_program_address\([^)]*\)(?!.*validate)"), "description": "Missing bump seed validation - PDA derivation without bump seed verification"},
        
        # PDA Sharing
        {"id": "ANCH009", "severity": "Critical", "regex": re.compile(r"invoke_signed\([^)]*\)(?!.*with_signer)"), "description": "Insecure PDA sharing - Using PDA as signer without proper validation"},
        
        # Closing Accounts
        {"id": "ANCH010", "severity": "Critical", "regex": re.compile(r"ctx\.accounts\.\w+\.lamports\(\)\s*=\s*0"), "description": "Insecure account closing - Setting lamports to 0 without proper validation"},
        
        # Sysvar Address Checking
        {"id": "ANCH011", "severity": "Critical", "regex": re.compile(r"sysvar::\w+::\w+::get\(\)"), "description": "Missing sysvar address validation - Direct sysvar access without address verification"}
    ]
}

    
def clone_repository(repo_url: str, clone_path: str) -> Optional[str]:
    """Clone or update a Git repository.
    
    Args:
        repo_url: URL of the Git repository to clone
        clone_path: Local path where the repository should be cloned
        
    Returns:
        Path to the cloned repository if successful, None otherwise
        
    This function will:
    1. Extract the repository name from the URL
    2. Check if the repository already exists locally
    3. If it exists, pull latest changes
    4. If it doesn't exist, clone it
    5. Return the path to the repository
    """
    try:
        # Extract repository name from URL
        repo_name = os.path.basename(repo_url).strip().split("/")[-1]
        if repo_name.endswith('.git'):
            repo_name = repo_name[:-4]
            
        target_repo_path = os.path.join(clone_path, repo_name)
        logger.info(f"Processing repository: {repo_name}")

        # Ensure the parent directory exists
        if not os.path.exists(clone_path):
            os.makedirs(clone_path, exist_ok=True)

        if os.path.exists(target_repo_path):
            try:
                repo = git.Repo(target_repo_path)
                origin = repo.remotes.origin
                origin.pull()
                logger.info(f"Repository at {target_repo_path} updated successfully")
                return target_repo_path
            except git.GitCommandError as e:
                logger.error(f"Git error updating repository: {e}")
                return None
            except Exception as e:
                logger.error(f"Unexpected error updating repository: {e}")
                return None

        # Clone new repository
        git.Repo.clone_from(repo_url, target_repo_path)
        logger.info(f"Repository cloned successfully to {target_repo_path}")
        return target_repo_path
        
    except git.GitCommandError as e:
        logger.error(f"Git error cloning repository: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error in repository operation: {e}")
        return None
    
    
def find_rust_files(base_dir: str) -> List[str]:
    """Find all Rust source files in a directory recursively.
    
    Args:
        base_dir: Base directory to start the search from
        
    Returns:
        List of absolute paths to Rust source files
        
    This function will:
    1. Walk through the directory tree
    2. Identify .rs files
    3. Skip hidden directories and files
    4. Skip target directories
    """
    rust_files = []
    for root, dirs, files in os.walk(base_dir):
        # Skip hidden directories and target directory
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'target']
        
        for file in files:
            if file.endswith('.rs') and not file.startswith('.'):
                full_path = os.path.join(root, file)
                rust_files.append(full_path)
                logger.debug(f"Found Rust file: {full_path}")
                
    logger.info(f"Found {len(rust_files)} Rust files in {base_dir}")
    return rust_files


def is_valid_rust_project(base_dir: str) -> bool:
    """Check if a directory contains a valid Rust project structure.
    
    Args:
        base_dir: Directory to check for Rust project validity
        
    Returns:
        True if the directory contains a valid Rust project, False otherwise
        
    A valid Rust project must have:
    1. A Cargo.toml file
    2. The Cargo.toml must be valid TOML
    3. The Cargo.toml must contain required fields (package, dependencies)
    """
    cargo_path = os.path.join(base_dir, "Cargo.toml")
    if not os.path.exists(cargo_path):
        logger.warning(f"No Cargo.toml found in {base_dir}")
        return False

    try:
        cargo_toml = toml.load(cargo_path)
        
        # Check for required sections
        if 'package' not in cargo_toml:
            logger.warning(f"Missing [package] section in {cargo_path}")
            return False
            
        if 'dependencies' not in cargo_toml:
            logger.warning(f"Missing [dependencies] section in {cargo_path}")
            return False
            
        # Check for src directory
        src_dir = os.path.join(base_dir, 'src')
        if not os.path.exists(src_dir):
            logger.warning(f"No src directory found in {base_dir}")
            return False
            
        logger.info(f"Found valid Rust project in {base_dir}")
        return True
        
    except toml.TomlDecodeError as e:
        logger.error(f"Invalid TOML in {cargo_path}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error validating Rust project: {e}")
        return False

def browse_and_select_valid_directory(base_dir: str) -> str:
    """Allow the user to browse directories until a valid Rust project is found."""
    while not is_valid_rust_project(base_dir):
        print(f"Current directory: {base_dir}")
        subdirs = [d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))]
        if not subdirs:
            logger.error("No subdirectories available to browse. Exiting.")
            exit(1)
        
        print("Available subdirectories:")
        for i, subdir in enumerate(subdirs):
            print(f"{i + 1}. {subdir}")

        choice = input("Select a subdirectory by number or type 'exit' to quit: ").strip()
        if choice.lower() == "exit":
            exit(1)
        
        try:
            choice_index = int(choice) - 1
            if 0 <= choice_index < len(subdirs):
                base_dir = os.path.join(base_dir, subdirs[choice_index])
            else:
                print("Invalid selection. Please try again.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    return base_dir

def remove_inline_comments(line: str) -> str:
    """Remove Rust inline comments (//) while keeping actual code."""
    return line.split("//", 1)[0].strip() if "//" in line else line.strip()

def scan_file(file_path: str, analysis_depth="Intermediate") -> List[Dict]:
    """Scan a Rust file for vulnerabilities based on depth level."""
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Get selected patterns based on depth
        selected_patterns = []
        if analysis_depth in VULNERABILITY_PATTERNS:
            for level in ["Basic", "Intermediate", "Advanced"]:
                selected_patterns.extend(VULNERABILITY_PATTERNS.get(level, []))
                if level == analysis_depth:
                    break
            # Add Anchor patterns
            selected_patterns.extend(VULNERABILITY_PATTERNS.get("Anchor", []))

        for i, line in enumerate(lines, start=1):
            clean_line = remove_inline_comments(line)
            for vuln in selected_patterns:
                if vuln["regex"].search(clean_line):
                    findings.append({
                        "file": os.path.relpath(file_path, os.getcwd()),  # Relative path from current directory
                        "line": i,
                        "id": vuln["id"],
                        "severity": vuln["severity"],
                        "description": vuln["description"],
                        "code": clean_line.strip(),
                    })
    except Exception as e:
        logger.error(f"Error scanning {file_path}: {e}")
    
    return findings



def analyze_project_multithreaded(files: List[str], analysis_depth="Intermediate") -> List[Dict]:
    """Scan multiple Rust files sequentially (simpler approach)."""
    results = [scan_file(file, analysis_depth) for file in files]
    return [item for sublist in results for item in sublist]

def analyze_project(base_dir: str, analysis_depth="Intermediate") -> List[Dict]:
    """Find Rust files and scan them for vulnerabilities with depth control."""
    base_dir = browse_and_select_valid_directory(base_dir)  # Ensure valid project directory
    rust_files = find_rust_files(base_dir)
    
    # Always include Anchor patterns regardless of depth
    selected_patterns = []
    if analysis_depth in VULNERABILITY_PATTERNS:
        for level in ["Basic", "Intermediate", "Advanced"]:
            selected_patterns.extend(VULNERABILITY_PATTERNS.get(level, []))
            if level == analysis_depth:
                break
        # Add Anchor patterns
        selected_patterns.extend(VULNERABILITY_PATTERNS.get("Anchor", []))
    
    return analyze_project_multithreaded(rust_files, analysis_depth)

def generate_report(findings):
    """Generate a summary of vulnerability occurrences."""
    severity_count = Counter(f["severity"] for f in findings if "severity" in f)
    print("\n🔍 Vulnerability Report:")
    for severity, count in severity_count.items():
        print(f"{severity}: {count} occurrences")

def save_results_csv(findings: List[Dict], filename="scan_results.csv"):
    """Save scan results to a CSV file."""
    if not findings:
        logger.info("No vulnerabilities found.")
        return

    df = pd.DataFrame(findings)
    df.to_csv(filename, index=False)
    logger.info(f"[+] Results saved in {filename}")

def save_results_json(findings: List[Dict], filename="scan_results.json"):
    """Save scan results to a JSON file."""
    if not findings:
        logger.info("No vulnerabilities found.")
        return

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=4)
    logger.info(f"[+] Results saved in {filename}")

def save_results_markdown(findings: List[Dict], filename="scan_results.md"):
    """Save scan results to a Markdown file."""
    if not findings:
        logger.info("No vulnerabilities found.")
        return

    with open(filename, "w", encoding="utf-8") as f:
        f.write("# Scan Results\n\n")
        for finding in findings:
            f.write(f"- **{finding['id']}** ({finding['severity']}): {finding['description']} - `{finding['code']}`\n")
    logger.info(f"[+] Markdown report saved in {filename}")

def save_results_html(findings: List[Dict], filename="scan_results.html"):
    """Save scan results to an interactive HTML file."""
    if not findings:
        logger.info("No vulnerabilities found.")
        return

    df = pd.DataFrame(findings)
    html_content = df.to_html(index=False, escape=False)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"<html><head><title>Rust Security Report</title></head><body>{html_content}</body></html>")
    logger.info(f"[+] HTML report saved in {filename}")

def main():
    """Run the static analyzer on a given directory."""
    
    base_dir = os.path.abspath(os.path.dirname(__file__)).join("json_reports")
    print(base_dir)
    analysis_depth = "Intermediate"  # Default depth level
    findings = analyze_project(base_dir, analysis_depth)

    generate_report(findings)
    save_results_csv(findings)
    save_results_json(findings)
    save_results_markdown(findings)
    save_results_html(findings)

if __name__ == "__main__":
    main()
