# ChapacoSolSec 🛡️

## Overview

ChapacoSolSec is an advanced security analysis tool designed specifically for Solana smart contracts. Built for macOS ARM architecture, it combines AST (Abstract Syntax Tree) analysis with machine learning to provide comprehensive security auditing capabilities for Rust-based Solana programs.

## 🎯 Key Features

### Security Analysis
- **Static Code Analysis**: Deep AST-based analysis of Rust code patterns
- **Risk Scoring**: Sophisticated severity assessment using a 4-level classification system
- **Validation Detection**: Identification of missing critical validations in smart contracts
- **Category-based Analysis**: Specialized detection for:
  - Unsafe code patterns
  - Missing validations
  - Access control issues
  - Cross-Program Invocation (CPI) vulnerabilities

### Visualization & Reporting
- **Interactive Dashboards**: Real-time visualization of security findings
- **Risk Distribution Charts**: Advanced scatter plots showing risk concentration
- **Validation Gap Analysis**: Radar charts for missing security checks
- **Multiple Export Formats**: Support for JSON, CSV, Markdown, and HTML reports

## 🛠️ Installation

### Prerequisites
- macOS with Apple Silicon (M1/M2)
- Python 3.8+
- Rust toolchain
- gcc/clang compiler
- Homebrew

### Quick Start
# Fork the repository
Feel free to fork the repository and commit changes
https://github.com/your-org/ChapacoSolSec.git

```bash
# Clone the repository
git clone https://github.com/your-org/ChapacoSolSec.git
cd ChapacoSolSec

# Install dependencies
brew install libomp
export DYLD_LIBRARY_PATH="/opt/homebrew/opt/libomp/lib:$DYLD_LIBRARY_PATH"

# Better if its running on a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Build the Rust parser
./script.sh

# Install Python dependencies
pip install -r requirements.txt

# Start the application
python app.py
```

## 💪 Strengths

1. **Specialized for Solana**
   - Built specifically for Solana's programming model
   - Deep understanding of Solana-specific vulnerabilities
   - Tailored for Rust-based smart contracts

2. **Advanced Visualization**
   - Interactive and intuitive security dashboards
   - Clear risk distribution visualization
   - Comprehensive validation gap analysis

3. **Efficient Processing**
   - Fast AST-based analysis
   - Optimized for Apple Silicon
   - Parallel processing capabilities

## 📊 Use Cases

- **Security Auditors**: Streamline the audit process with automated vulnerability detection
- **Smart Contract Developers**: Early detection of security issues during development
- **Code Reviewers**: Quick assessment of code quality and security patterns
- **Security Researchers**: Analysis of vulnerability patterns in Solana programs

## ⚠️ Limitations

1. **Platform Specific**
   - Currently optimized for macOS ARM architecture
   - Limited testing on other platforms

2. **Analysis Scope**
   - Focus on known vulnerability patterns
   - May require manual verification of findings
   - Limited to static analysis

## 🔄 Usage Workflow

1. **Project Setup**
   - Clone target Solana project or use local files
   - Place source code in the `projects/` directory

2. **Analysis**
   - Run initial analysis using the web interface
   - Review AST analysis results
   - Export findings in preferred format

3. **Reporting**
   - Generate comprehensive security reports
   - Review visualizations and risk distributions
   - Export detailed findings

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by [l3x](https://github.com/VulnPlanet/l3x) for AST analysis
- Built with [tree-sitter](https://tree-sitter.github.io/tree-sitter/) for robust parsing
- Solana Foundation for documentation and security guidelines
