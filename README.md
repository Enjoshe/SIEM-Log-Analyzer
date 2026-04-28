# SIEM Log Analyzer

## Overview
A lightweight Security Information and Event Management (SIEM) style project:
- Ingests system or application logs (Windows events, Linux Auth, Apache access logs).
- Normalizes and stores logs in SQLite.
- Applies rule-based detection (e.g., brute force, suspicious IPs).
- Uses a simple ML anomaly detector (Isolation Forest) for unusual activity.
- Visualization through ELK Stack.

This project is meant for learning and portfolio use — not for production SOCs.

## Quickstart
1. Create venv and install:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
