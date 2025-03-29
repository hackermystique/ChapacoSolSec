#!/usr/bin/env zsh

# Exit on error, undefined variables, and pipe failures
set -euo pipefail

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
    exit 1
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Clean function
clean() {
    log "Cleaning project..."
    
    # Remove virtual environment
    if [ -d "venv" ]; then
        log "Removing virtual environment..."
        rm -rf venv
    fi
    
    # Remove generated files
    if [ -f "tree-sitter-rust.dylib" ]; then
        log "Removing tree-sitter-rust.dylib..."
        rm -f tree-sitter-rust.dylib
    fi
    
    # Remove logs
    if [ -d "logs" ]; then
        log "Removing logs folder..."
        rm -rf logs
        rm solana_dataset_enhanced.csv
    fi
    
    # Remove generated directories
    if [ -d "json_reports" ]; then
        log "Removing json_reports directory..."
        rm -rf json_reports
    fi
    if [ -d "models" ]; then
        log "Removing models directory..."
        rm -rf models
    fi
    
    if [ -d "vendor" ]; then
        log "Removing vendor directory..."
        rm -rf vendor
    fi
  
    if [ -d "projects" ]; then
        log "Removing projects directory..."
        rm -rf projects
    fi
    
    if [ -d "build" ]; then
        log "Removing build directory..."
        rm -rf build
    fi

    # Remove Python cache files
    log "Removing Python cache files..."
    find . -type d -name "__pycache__" -exec rm -rf {} +
    find . -type f -name "*.pyc" -delete
    find . -type f -name "*.pyo" -delete
    find . -type f -name "*.pyd" -delete
    find . -type f -name "*.log" -delete
    find . -type f -name ".pytest_cache" -delete
    find . -type f -name ".coverage" -delete
    find . -type d -name "htmlcov" -exec rm -rf {} +
    
    log "✅ Cleaning completed successfully!"
}

# Main execution
main() {
    case "${1:-clean}" in
        "clean")
            clean
            ;;
        *)
            echo "Usage: ./clean.sh [clean]"
            exit 1
            ;;
    esac
}

# Execute main function with all arguments
main "$@"
