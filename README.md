# 🏦 BankScope Full-Stack Banking System

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Backend](https://img.shields.io/badge/backend-Flask-lightgrey.svg)](https://flask.palletsprojects.com/)
[![Testing Framework](https://img.shields.io/badge/framework-unittest-green.svg)](https://docs.python.org/3/library/unittest.html)
[![License](https://img.shields.io/badge/license-MIT-important.svg)](LICENSE)

**BankScope** is a complete full-stack banking simulation system. It features a robust Flask REST API, a modern web interface, and a comprehensive suite of 97+ automated tests covering Unit, Integration, System, Security, and Performance layers.

---

## 🚀 Overview

This project has been upgraded from a pure testing suite into a working application. It demonstrates:
- **Clean Architecture**: Separation of concerns between Models, Services, and API layers.
- **Security**: SHA-256 hashing with per-user salting and brute-force lockout protection.
- **RESTful Design**: Token-based authentication and standardized JSON responses.
- **Modern UI**: A responsive dashboard for managing transactions in real-time.

---

## 📂 Project Structure

```text
BankScope/
│
├── backend/
│   ├── app.py             # Flask API Server & Routes
│   ├── services.py        # Business logic (Bank Facade)
│   ├── auth.py            # Hashing & Session management
│   └── models.py          # Account & Exception models
│
├── frontend/
│   ├── index.html         # Login/Registration portal
│   ├── dashboard.html     # User transaction dashboard
│   ├── style.css          # Premium UI styles
│   └── app.js             # API Integration (Fetch)
│
├── tests/
│   ├── unit_tests.py      # Granular isolation tests
│   ├── security_tests.py  # Auth & Security validation
│   └── ...                # Integration, System, Performance
│
├── README.md              # Documentation
├── requirements.txt       # Flask & CORS dependencies
└── .gitignore             # Git exclusions
```

---

## 🏃 How to Run

### 1. Backend Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Start the Flask server
python -m backend.app
```
The API will run at `http://127.0.0.1:5000`.

### 2. Frontend Setup
Simply open `frontend/index.html` in any modern web browser. 
No build step is required (Vanilla JS).

### 3. Running Tests
Verify the entire system logic:
```bash
python -m unittest discover -s tests -p '*_tests.py' -v
```

---

## 🛠️ API Features

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/register` | POST | Create a new account. |
| `/login` | POST | Authenticate and receive a Bearer token. |
| `/balance` | GET | Retrieve current balance (Auth required). |
| `/transfer` | POST | Move funds to another user (Auth required). |
| `/history` | GET | View transaction logs (Auth required). |

---

## 👨‍💻 Author

**EngYahia25**  
*Senior Artificial Intelligence & Full-Stack QA Engineer*

---

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.
