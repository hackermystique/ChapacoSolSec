#!/usr/bin/env zsh

# Exit on error, undefined variables, and pipe failures
set -euo pipefail

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default log file and max lines
mkdir -p vendor/tree-sitter-rust
mkdir -p logs/
log_file="logs/setup.log"
max_log_lines=500

# Parse arguments like log=1000
parse_args() {
    for arg in "$@"; do
        case $arg in
            log=*)
                max_log_lines="${arg#*=}"
                ;;
        esac
    done
}

# Logging functions
log() {
    local message="[$(date +'%Y-%m-%d %H:%M:%S')] $1"
    echo -e "${GREEN}${message}${NC}"
    echo "$message" >> "$log_file"
    tail -n "$max_log_lines" "$log_file" > "$log_file.tmp" && mv "$log_file.tmp" "$log_file"
}

warn() {
    local message="[WARNING] $1"
    echo -e "${YELLOW}${message}${NC}"
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $message" >> "$log_file"
    tail -n "$max_log_lines" "$log_file" > "$log_file.tmp" && mv "$log_file.tmp" "$log_file"
}

error() {
    local message="[ERROR] $1"
    echo -e "${RED}${message}${NC}" >&2
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $message" >> "$log_file"
    tail -n "$max_log_lines" "$log_file" > "$log_file.tmp" && mv "$log_file.tmp" "$log_file"
    exit 1
}

# Check Python version
check_python_version() {
    local required_version="3.8.0"
    local current_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')

    if ! command -v python3 &>/dev/null; then
        error "Python 3 is not installed. Please install Python 3.8 or higher."
    fi

    if ! python3 -c "import sys; exit(0 if tuple(map(int, '$current_version'.split('.'))) >= tuple(map(int, '$required_version'.split('.'))) else 1)"; then
        error "Python version $required_version or higher is required. Current version: $current_version"
    fi

    log "Python version check passed: $current_version"
}

# Setup virtual environment
setup_venv() {
    local VENV_ACTIVATE="venv/bin/activate"

    log "Setting up Python virtual environment..."

    if [ ! -d "venv" ]; then
        python3 -m venv venv || error "Failed to create virtual environment"
        log "Virtual environment created"
    else
        log "Virtual environment already exists"
    fi

    if [ -f "$VENV_ACTIVATE" ]; then
        source "$VENV_ACTIVATE" || error "Failed to activate virtual environment"
        log "Virtual environment activated"
    else
        error "Virtual environment activation script not found"
    fi
}

# Install/upgrade pip packages
install_pip_packages() {
    log "Upgrading pip and core packages..."
    pip install --upgrade pip setuptools wheel || error "Failed to upgrade pip packages"

    if [ -f "requirements.txt" ]; then
        log "Installing Python requirements..."
        pip install -r requirements.txt || error "Failed to install requirements"
    else
        error "requirements.txt not found"
    fi
}

# Setup tree-sitter
setup_tree_sitter() {
    log "Setting up tree-sitter..."

    if ! command -v brew &>/dev/null; then
        error "Homebrew is not installed. Please install Homebrew first."
    fi

    if ! command -v tree-sitter &>/dev/null; then
        log "Installing tree-sitter with Homebrew..."
        brew install tree-sitter || error "Failed to install tree-sitter"
    fi

    if [ ! -d "vendor/tree-sitter-rust/src" ]; then
        log "Cloning tree-sitter-rust..."
        git clone https://github.com/tree-sitter/tree-sitter-rust.git vendor/tree-sitter-rust || error "Failed to clone tree-sitter-rust"
    else
        log "Updating tree-sitter-rust..."
        git -C vendor/tree-sitter-rust pull || warn "Failed to update tree-sitter-rust"
    fi

    if [ -f "vendor/tree-sitter-rust/src/parser.c" ] && [ -f "vendor/tree-sitter-rust/src/scanner.c" ]; then
        log "Getting tree-sitter Rust grammar..."
    else
        error "Required tree-sitter C source files not found"
    fi
}

# Create necessary directories
setup_directories() {
    log "Creating necessary directories..."
    mkdir -p models json_reports projects || error "Failed to create directories"
}

# Run project scripts
run_scripts() {
    if [ -f "process_dataset.py" ]; then
        log "Running dataset processing script..."
        python process_dataset.py || warn "Dataset processing failed"
    else
        warn "process_dataset.py not found, skipping..."
    fi

    if [ -f "unified_model_trainer.py" ]; then
        log "Running unified model trainer..."
        python unified_model_trainer.py || warn "Model training failed"
    else
        warn "unified_model_trainer.py not found, skipping..."
    fi
}

# Prepare environment (venv + dependencies)
prepare() {
    check_python_version
    setup_venv
    install_pip_packages
}

# Install tree-sitter and compile grammar
install() {
    setup_tree_sitter
    setup_directories
}

# Run all setup steps
all() {
    prepare
    install
    run_scripts

    echo ""
    echo "To start the app, press [Enter] or run: python app.py"
    read -r _
    echo "Running python app.py..."
    python app.py
}

# Main execution
main() {
    parse_args "$@"
    case "${1:-all}" in
        "prepare")
            prepare
            ;;
        "install")
            install
            ;;
        "all")
            all
            ;;
        *)
            echo "Usage: ./setup.sh {prepare|install|all} [log=LINES]"
            echo "  prepare: Set up virtual environment and install Python dependencies"
            echo "  install: Install tree-sitter and compile grammar"
            echo "  all: Run all setup steps"
            echo "  log=N: Optional max lines in logs/setup.log"
            exit 1
            ;;
    esac
}

main "$@"
