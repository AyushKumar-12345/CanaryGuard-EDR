# CanaryGuard-EDR

Real-time File Integrity Monitor (FIM) and Ransomware Canary Detector built with Python.

## Features

- Real-time file system monitoring using native OS events
- Cryptographic file integrity checks using SHA-256 and HMAC
- Shannon entropy detection to flag ransomware encryption
- Honeytoken canary file detection
- Rapid file modification alerts
- Machine-readable JSON audit logging and optional webhook alerts

## Installation

pip install -r requirements.txt

## Usage

Create initial baseline:
python fim.py --init --path ./test_watch

Run a one-time integrity check:
python fim.py --check --path ./test_watch

Start real-time monitoring:
python fim.py --watch --path ./test_watch

View the last report:
python fim.py --report

## Run Tests

python -m unittest test_fim.py

## License

MIT