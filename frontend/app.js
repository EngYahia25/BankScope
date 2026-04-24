const API_URL = 'http://127.0.0.1:5000';

// ──────────────────────────────────────────────
// Auth Logic
// ──────────────────────────────────────────────

const authForm = document.getElementById('auth-form');
const toggleBtn = document.getElementById('toggle-btn');
let isLogin = true;

if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
        isLogin = !isLogin;
        document.getElementById('auth-title').innerText = isLogin ? 'Welcome Back' : 'Create Account';
        document.getElementById('submit-btn').innerText = isLogin ? 'Login' : 'Register';
        document.getElementById('balance-group').style.display = isLogin ? 'none' : 'block';
        toggleBtn.innerText = isLogin ? 'Need an account? Register' : 'Already have an account? Login';
    });
}

if (authForm) {
    authForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const initial_balance = document.getElementById('initial_balance')?.value || 0;

        const endpoint = isLogin ? '/login' : '/register';
        const body = isLogin ? { username, password } : { username, password, initial_balance };

        try {
            const res = await fetch(`${API_URL}${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });

            const data = await res.json();

            if (res.ok) {
                if (isLogin) {
                    localStorage.setItem('token', data.token);
                    localStorage.setItem('username', data.username);
                    window.location.href = 'dashboard.html';
                } else {
                    showAlert('Registration successful! Please login.', 'success');
                    toggleBtn.click();
                }
            } else {
                showAlert(data.error, 'error');
            }
        } catch (err) {
            showAlert('Server connection failed', 'error');
        }
    });
}

// ──────────────────────────────────────────────
// Dashboard Logic
// ──────────────────────────────────────────────

async function loadDashboard() {
    const token = localStorage.getItem('token');
    const username = localStorage.getItem('username');
    if (!token) {
        window.location.href = 'index.html';
        return;
    }

    document.getElementById('user-display').innerText = username;
    updateBalance();
    updateHistory();
}

async function updateBalance() {
    const token = localStorage.getItem('token');
    const res = await fetch(`${API_URL}/balance`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    const data = await res.json();
    if (res.ok) {
        document.getElementById('balance-display').innerText = `$${data.balance.toLocaleString(undefined, {minimumFractionDigits: 2})}`;
    }
}

async function updateHistory() {
    const token = localStorage.getItem('token');
    const res = await fetch(`${API_URL}/history`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    const data = await res.json();
    const container = document.getElementById('history-container');
    
    if (res.ok && data.history.length > 0) {
        container.innerHTML = data.history.reverse().map(tx => `
            <div class="history-item">
                <div>
                    <strong>${tx.type.charAt(0).toUpperCase() + tx.type.slice(1)}</strong>
                    <br><small>${new Date(tx.timestamp).toLocaleString()}</small>
                </div>
                <div class="${tx.type === 'withdrawal' || tx.type.includes('transfer') ? 'amount-negative' : 'amount-positive'}">
                    ${tx.type === 'withdrawal' ? '-' : ''}$${tx.amount.toFixed(2)}
                </div>
            </div>
        `).join('');
    }
}

async function handleTransaction(type) {
    const token = localStorage.getItem('token');
    let endpoint = `/${type}`;
    let body = {};

    if (type === 'deposit') {
        body.amount = document.getElementById('deposit-amount').value;
    } else if (type === 'withdraw') {
        body.amount = document.getElementById('withdraw-amount').value;
    } else if (type === 'transfer') {
        body.amount = document.getElementById('transfer-amount').value;
        body.to_username = document.getElementById('transfer-to').value;
    }

    try {
        const res = await fetch(`${API_URL}${endpoint}`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(body)
        });

        const data = await res.json();
        if (res.ok) {
            showAlert(data.message || 'Success!', 'success');
            updateBalance();
            updateHistory();
            // Clear inputs
            document.querySelectorAll('input').forEach(i => i.value = '');
        } else {
            showAlert(data.error, 'error');
        }
    } catch (err) {
        showAlert('Transaction failed', 'error');
    }
}

function handleLogout() {
    localStorage.clear();
    window.location.href = 'index.html';
}

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

function showAlert(msg, type) {
    const alert = document.getElementById('alert');
    alert.innerText = msg;
    alert.className = `alert alert-${type}`;
    alert.style.display = 'block';
    setTimeout(() => alert.style.display = 'none', 5000);
}
