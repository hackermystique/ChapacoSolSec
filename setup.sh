#!/usr/bin/env zsh
# set -e  # Exit on any error
# Path to the virtual environment's activate script
VENV_ACTIVATE="venv/bin/activate"

echo -e "\033[0;32mCreating or activating Python virtual environment...\033[0m"

# Create venv if it doesn't exist
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "\033[0;32mVirtual environment created.\033[0m"
else
    echo -e "\033[0;32mVirtual environment already exists.\033[0m"
fi

# Try activating the virtual environment
if [ -f "$VENV_ACTIVATE" ]; then
    # Activate the venv in the current shell
    echo -e "\033[0;32mActivating virtual environment...\033[0m"
    source "$VENV_ACTIVATE"
else
    echo -e "\033[0;31mError: venv activation script not found!\033[0m"
    exit 1
fi

# Confirm Python version inside venv
echo -e "\033[0;32mUsing Python version: $(python --version)\033[0m"
echo -e "\033[0;32mInstalling/upgrading core Python packages...\033[0m"
pip install --upgrade pip setuptools wheel

# tree-sitter setup
echo -e "\033[0;32mChecking tree-sitter installation...\033[0m"
if ! command -v tree-sitter &>/dev/null; then
    echo -e "\033[0;32mInstalling tree-sitter with Homebrew...\033[0m"
    brew install tree-sitter
else
    echo -e "\033[0;32mtree-sitter is already installed.\033[0m"
fi

# Prepare vendor dir
echo -e "\033[0;32mEnsuring vendor/tree-sitter-rust exists...\033[0m"
mkdir -p vendor/tree-sitter-rust

# Clone or update tree-sitter-rust
if [ ! -d "vendor/tree-sitter-rust/src" ]; then
    git clone https://github.com/tree-sitter/tree-sitter-rust.git vendor/tree-sitter-rust
else
    echo -e "\033[0;32mtree-sitter-rust already exists, pulling latest changes...\033[0m"
    git -C vendor/tree-sitter-rust pull
fi

# Compile tree-sitter C sources
if [ -f "vendor/tree-sitter-rust/src/parser.c" ] && [ -f "vendor/tree-sitter-rust/src/scanner.c" ]; then
    echo -e "\033[0;32mCompiling tree-sitter Rust grammar...\033[0m"
    gcc -shared -o ./tree-sitter-rust.dylib -fPIC \
        vendor/tree-sitter-rust/src/parser.c \
        vendor/tree-sitter-rust/src/scanner.c -I./
else
    echo -e "\033[0;31mError: Required tree-sitter C source files not found!\033[0m"
    exit 1
fi

# Install requirements
if [ -f "requirements.txt" ]; then
    echo -e "\033[0;32mInstalling Python requirements...\033[0m"
    pip install -r requirements.txt
else
    echo -e "\033[0;31mError: requirements.txt not found!\033[0m"
    exit 1
fi

# Run dataset processor if available
if [ -f "process_dataset.py" ]; then
    echo -e "\033[0;32mRunning dataset processing script...\033[0m"
    python process_dataset.py
else
    echo -e "\033[1;33mWarning: process_dataset.py not found, skipping...\033[0m"
fi

# Run training if available
if [ -f "unified_model_trainer.py" ]; then
    echo -e "\033[0;32mRunning unified model trainer...\033[0m"
    python unified_model_trainer.py
else
    echo -e "\033[1;33mWarning: unified_model_trainer.py not found, skipping...\033[0m"
fi

# Run the app
if [ -f "app.py" ]; then
    echo -e "\033[0;32mLaunching application...\033[0m"
    python app.py
else
    echo -e "\033[0;31mError: app.py not found!\033[0m"
    exit 1
fi

# Optional: deactivate venv at end
# deactivate

echo -e "\033[0;32m✅ Script completed successfully!\033[0m"