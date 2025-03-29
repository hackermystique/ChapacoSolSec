#!/usr/bin/env zsh

python3 -m venv venv && \
    source venv/bin/activate && \
    pip install -r requirements.txt && \
    python ast_analysis.py tests/level0