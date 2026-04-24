# 🏦 BankScope Testing Suite

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Testing Framework](https://img.shields.io/badge/framework-unittest-green.svg)](https://docs.python.org/3/library/unittest.html)
[![License](https://img.shields.io/badge/license-MIT-important.svg)](LICENSE)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-brightgreen.svg)](https://github.com/EngYahia25/BankScope/graphs/commit-activity)

**BankScope** is a comprehensive software testing suite designed for the **SimpliBank Online Banking System**. It demonstrates industry-standard testing methodologies, covering everything from granular unit tests to complex performance and security scenarios.

---

## 🚀 Overview

This project serves as a robust validation layer for a banking core. It ensures that the system is not only functional but also secure against common threats and capable of handling high-concurrency workloads.

### 🎯 Key Testing Objectives:
- **Accuracy**: Validate mathematical precision in deposits, withdrawals, and transfers.
- **Security**: Stress-test authentication flows and brute-force protection.
- **Resilience**: Ensure the system handles edge cases and invalid inputs gracefully.
- **Performance**: Benchmark transaction speeds under high-load conditions.

---

## 🛠️ Features

The suite is divided into five distinct testing levels:

| Level | Description | File |
| :--- | :--- | :--- |
| **Unit** | Isolated tests for `Account` and `UserAuth` classes. | `unit_tests.py` |
| **Integration** | Verifies the flow between the Bank facade and its components. | `integration_tests.py` |
| **System** | End-to-end user workflows (Registration to Transfer). | `system_tests.py` |
| **Security** | Tests for hashing integrity and account lockout logic. | `security_tests.py` |
| **Performance** | Measures latency and throughput for thousands of transactions. | `performance_tests.py` |

---

## 📂 Project Structure

```text
BankScope/
│
├── tests/
│   ├── __init__.py            # Package initialization
│   ├── unit_tests.py          # Class-level isolation tests
│   ├── integration_tests.py   # Component interaction tests
│   ├── system_tests.py        # End-to-end workflow tests
│   ├── security_tests.py      # Auth & Security validation
│   └── performance_tests.py   # Load & Stress testing
│
├── banking_system.py          # Core Banking Engine (Source Code)
├── README.md                  # Project documentation
├── requirements.txt           # Dependency list
└── .gitignore                 # Files to exclude from Git
```

---

## ⚙️ Technologies Used

- **Language**: Python 3.8+
- **Testing**: `unittest` (Standard Library)
- **Security**: `hashlib` (SHA-256), `secrets` (CSPRNG)
- **Performance**: `time`, `statistics`

---

## 🏃 How to Run Tests

### 1. Setup Environment
It is recommended to use a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Run All Tests (Recommended)
From the project root, use the discovery tool:
```bash
python -m unittest discover -s tests -p '*_tests.py' -v
```

### 3. Run Specific Test Levels
```bash
# Run Unit Tests
python -m unittest tests/unit_tests.py

# Run Security Tests
python -m unittest tests/security_tests.py
```

### 4. Example Output
```text
test_deposit_increases_balance (tests.unit_tests.TestAccountDeposit) ... ok
test_account_locks_after_five_failed_attempts (tests.security_tests.TestSecurity) ... ok
test_performance_high_load (tests.performance_tests.TestPerformance) ... ok (0.45s)

----------------------------------------------------------------------
Ran 52 tests in 1.24s

OK
```

---

## 👨‍💻 Author

**EngYahia25**  
*Senior Artificial intelligence Engineer*

---

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.
