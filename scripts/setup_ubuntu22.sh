#!/usr/bin/env bash
set -euo pipefail

sudo apt update
sudo apt install -y unzip python3-venv python3-pip git build-essential

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
pytest

echo
echo "Nightjar setup complete."
echo "Activate later with: source .venv/bin/activate"
