# 🛡️ SUSTUM PQC Checker (Post-Quantum Cryptography & CBOM Engine)
**Created by:** [AJAY SALUNKHE]

![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)
![Flask](https://img.shields.io/badge/Framework-Flask-green.svg)
![Compliance](https://img.shields.io/badge/Compliance-NIST%20%7C%20CNSA%202.0-orange.svg)
![License](https://img.shields.io/badge/License-MIT-purple.svg)

## 📌 Executive Summary
With the finalization of NIST FIPS 203, 204, and 205, enterprises are facing the largest cryptographic migration in history. Legacy algorithms (RSA, ECDSA) are vulnerable to Quantum threats (Shor's Algorithm). 

SUSTUM PQC Checker is an enterprise-grade Static Application Security Testing (SAST) engine designed to audit codebases, detect legacy cryptography, and map out a migration strategy with Zero-False-Positive AST parsing and CycloneDX CBOM (Cryptographic Bill of Materials) generation.

---

## 🚀 Architectural Capabilities

1. 🧠 Zero-Drift AST Engine: Uses Python's Abstract Syntax Tree (AST) to strictly analyze cryptographic function calls, completely ignoring comments and dead code.
2. 📦 Supply Chain & CBOM Export: Parses dependency manifests to generate a fully compliant CycloneDX JSON file.
3. 📊 Payload Growth Impact: Calculates network size differences (e.g., RSA's 256 bytes vs. ML-DSA's 3,309 bytes) to aid architectural network planning.

---

## ⚙️ Quick Start Guide

### Installation
1. Clone the repository and install dependencies:
pip install -r requirements.txt

### Running the Engine
1. Start the Flask backend server:
python app.py

2. Run the automated test script to generate a dummy repository and trigger the audit:
python run_test.py

*Your default web browser will automatically open the generated report.html executive dashboard.*
---
**Author:** [AJAY SALUNKHE] | Built for the Post-Quantum Era.