#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"

echo "[1/4] Ensuring system prerequisites are available..."
if ! "$PYTHON_BIN" -m venv .venv >/dev/null 2>&1; then
	echo "Python venv module not available. Installing via apt..."
	sudo apt-get install -y python3-venv python3-pip || {
		echo "Direct install failed; refreshing apt indexes and retrying..."
		sudo apt-get update || true
		sudo apt-get install -y python3-venv python3-pip
	}
fi

echo "[2/4] Creating virtual environment (.venv)..."
"$PYTHON_BIN" -m venv .venv

echo "[3/4] Upgrading packaging tools..."
.venv/bin/python -m pip install --upgrade pip setuptools wheel

echo "[4/4] Installing project dependencies..."
if ! .venv/bin/python -m pip install -r requirements.txt; then
	echo "Python deps failed to install. Installing common PDF build dependencies and retrying..."
	sudo apt-get install -y pkg-config libcairo2-dev || {
		sudo apt-get update || true
		sudo apt-get install -y pkg-config libcairo2-dev
	}
	.venv/bin/python -m pip install -r requirements.txt
fi

echo
echo "Setup complete."
echo "Activate with: source .venv/bin/activate"
echo "Run app with: python main.py"