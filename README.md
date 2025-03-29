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

### Machine Learning Integration
- **Unified Model Training**: Combines multiple classifiers for enhanced accuracy
- **Stacked Ensemble**: Utilizes XGBoost, LightGBM, and Random Forest
- **SMOTE Integration**: Handles class imbalance in vulnerability detection
- **Feature Engineering**: Comprehensive security pattern analysis

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

### Quick Setup Options

#### Option 1: Automated Setup (Recommended)
```bash
# Make setup script executable
chmod +x setup.sh

# Run the setup script
./setup.sh
```

This will automatically:
- Create and configure a Python virtual environment
- Install all required dependencies
- Set up tree-sitter for Rust parsing
- Configure the development environment
- Build necessary components

##### Available Setup.sh Options
The setup script provides several options for flexible installation:

```bash
./setup.sh {prepare|install|all} [log=LINES]
```

- `prepare`: Set up virtual environment and install Python dependencies
  - Checks Python version (requires 3.8+)
  - Creates and activates virtual environment
  - Installs/upgrades pip packages
  - Installs requirements from requirements.txt

- `install`: Install tree-sitter and compile grammar
  - Installs tree-sitter via Homebrew
  - Sets up tree-sitter-rust grammar
  - Creates necessary project directories (models, json_reports, projects)

- `all`: Run all setup steps (default)
  - Runs prepare and install steps
  - Processes dataset (if process_dataset.py exists)
  - Trains unified model (if unified_model_trainer.py exists)
  - Starts the application automatically

- `log=LINES`: Optional parameter to control log file size
  - Example: `./setup.sh all log=1000`
  - Default: 500 lines
  - Keeps logs/setup.log file manageable

The script includes comprehensive logging and error handling:
- Color-coded output for better visibility
- Detailed logging to logs/setup.log
- Automatic log rotation
- Clear error messages and warnings

#### Option 2: Manual Setup
```bash
# Clone the repository
git clone https://github.com/your-org/ChapacoSolSec.git
cd ChapacoSolSec

# Install system dependencies
brew install libomp
export DYLD_LIBRARY_PATH="/opt/homebrew/opt/libomp/lib:$DYLD_LIBRARY_PATH"

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Build the Rust parser
./script.sh
```

### Project Cleanup

#### Option 1: Automated Cleanup
```bash
# Make clean script executable
chmod +x clean.sh

# Run the clean script
./clean.sh
```

⚠️ **Warning**: This will delete all generated files, including:
- Virtual environment
- Generated models
- Log files
- Cache files
- Build artifacts
- Test reports
- Dataset files

Original downloaded files from the repository will be preserved.

#### Option 2: Manual Cleanup
You can manually remove specific components:
```bash
# Remove virtual environment
rm -rf venv

# Remove generated files
rm -rf models logs json_reports vendor tests projects build
rm -f tree-sitter-rust.dylib solana_dataset_enhanced.csv

# Remove Python cache
find . -type d -name "__pycache__" -exec rm -rf {} +
find . -type f -name "*.pyc" -delete
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

4. **Machine Learning Integration**
   - Ensemble-based vulnerability detection
   - Automated feature engineering
   - Robust handling of imbalanced data

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
   - Run the setup script to configure the environment
   - Ensure all dependencies are properly installed

2. **Analysis Process**
   - Run the security analysis on target code
   - Review generated reports and visualizations
   - Address identified vulnerabilities

3. **Model Training**
   - Use the unified model trainer for vulnerability detection
   - Monitor model performance and metrics
   - Update models as new patterns are discovered

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

For support, please open an issue in the GitHub repository or contact the maintainers.

## 🙏 Acknowledgments

- Inspired by [l3x](https://github.com/VulnPlanet/l3x) for AST analysis
- Built with [tree-sitter](https://tree-sitter.github.io/tree-sitter/) for robust parsing
- Solana Foundation for documentation and security guidelines
