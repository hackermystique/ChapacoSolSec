#!/bin/bash
set -e  # Exit immediately if a command exits with a non-zero status

echo -e "\033[0;32mCleaning environment\033[0m"
deactivate 2>/dev/null || true || echo -e "\033[0;31mVirtual environment was not active.\033[0m"
rm -rf  build/ json_reports/ models/ projects/ vendor/ venv/ tree-sitter-rust.dylib output/
rm -rf __pycache__/
echo -e "\033[0;32mScript execution completed successfully!\033[0m"