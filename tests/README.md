# Testing Instructions

Tests are designed to run on Debian/Ubuntu (Orange Pi or similar) where the application actually operates.

## Install Dependencies

```bash
# On the target device (Orange Pi)
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv aircrack-ng iw wireless-tools

# Create virtual environment if not exists
python3 -m venv venv
source venv/bin/activate

# Install pytest
pip install pytest

# Run tests
python -m pytest tests/ -v --tb=short
```

## Running Specific Test Files

```bash
# Scanner tests only
python -m pytest tests/test_scanner.py -v

# AP manager tests only
python -m pytest tests/test_ap_manager.py -v

# All tests with coverage
python -m pytest tests/ -v --tb=short --cov=wifi_auto_test
```

## Important Notes

- These tests mock all `subprocess.run` calls — no actual WiFi interfaces or root privileges are required.
- Do NOT run on Windows; the code under test uses Linux-specific tools (`iw`, `nmcli`, `ip`).
- If `pytest` is not installed in the venv on Orange Pi, install it first: `pip install pytest`.
