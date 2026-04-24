"""
BankScope - Flask API
=====================
REST API endpoints for the banking system.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from .services import Bank
from .models import AuthenticationError, InvalidInputError, InsufficientFundsError

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Singleton bank instance for the session (in-memory)
bank_service = Bank()

def get_token():
    """Extract token from Authorization header (Bearer <token>)."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    return auth_header.split(" ")[1]

# ──────────────────────────────────────────────
# Auth Routes
# ──────────────────────────────────────────────

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    try:
        bank_service.register_user(
            data.get("username"),
            data.get("password"),
            float(data.get("initial_balance", 0))
        )
        return jsonify({"message": "User registered successfully"}), 201
    except (InvalidInputError, ValueError) as e:
        return jsonify({"error": str(e)}), 400

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    try:
        token = bank_service.login(data.get("username"), data.get("password"))
        return jsonify({
            "token": token,
            "username": data.get("username")
        }), 200
    except (AuthenticationError, InvalidInputError) as e:
        return jsonify({"error": str(e)}), 401

@app.route("/logout", methods=["POST"])
def logout():
    token = get_token()
    if not token:
        return jsonify({"error": "No token provided"}), 401
    try:
        bank_service.logout(token)
        return jsonify({"message": "Logged out successfully"}), 200
    except AuthenticationError as e:
        return jsonify({"error": str(e)}), 401

# ──────────────────────────────────────────────
# Banking Routes
# ──────────────────────────────────────────────

@app.route("/balance", methods=["GET"])
def get_balance():
    token = get_token()
    if not token:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        balance = bank_service.get_balance(token)
        return jsonify({"balance": balance}), 200
    except AuthenticationError as e:
        return jsonify({"error": str(e)}), 401

@app.route("/deposit", methods=["POST"])
def deposit():
    token = get_token()
    if not token:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    try:
        new_balance = bank_service.deposit(token, float(data.get("amount", 0)))
        return jsonify({"balance": new_balance, "message": "Deposit successful"}), 200
    except (AuthenticationError, InvalidInputError, ValueError) as e:
        return jsonify({"error": str(e)}), 400

@app.route("/withdraw", methods=["POST"])
def withdraw():
    token = get_token()
    if not token:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    try:
        new_balance = bank_service.withdraw(token, float(data.get("amount", 0)))
        return jsonify({"balance": new_balance, "message": "Withdrawal successful"}), 200
    except (AuthenticationError, InvalidInputError, InsufficientFundsError, ValueError) as e:
        return jsonify({"error": str(e)}), 400

@app.route("/transfer", methods=["POST"])
def transfer():
    token = get_token()
    if not token:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    try:
        bank_service.transfer(
            token,
            data.get("to_username"),
            float(data.get("amount", 0))
        )
        return jsonify({"message": "Transfer successful"}), 200
    except (AuthenticationError, InvalidInputError, InsufficientFundsError, ValueError) as e:
        return jsonify({"error": str(e)}), 400

@app.route("/history", methods=["GET"])
def get_history():
    token = get_token()
    if not token:
        return jsonify({"error": "Unauthorized"}), 401
    try:
        history = bank_service.get_transaction_history(token)
        return jsonify({"history": history}), 200
    except AuthenticationError as e:
        return jsonify({"error": str(e)}), 401

if __name__ == "__main__":
    app.run(debug=True, port=5000)
