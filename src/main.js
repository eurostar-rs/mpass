const { invoke } = window.__TAURI__.core;

console.log("JavaScript loaded successfully");

let currentUserEmail = "";
let currentUserPassword = "";
let refreshTimer = null;

// --- TIMER FUNCTIONS ---

let countdownInterval = null;

function startCountdownUpdates() {
    if (countdownInterval) clearInterval(countdownInterval);
    
    // Update immediately
    updateCountdowns();
    
    // Then update every second
    countdownInterval = setInterval(updateCountdowns, 1000);
    
    console.log("Started countdown updates");
}

function stopCountdownUpdates() {
    if (countdownInterval) {
        clearInterval(countdownInterval);
        countdownInterval = null;
        console.log("Stopped countdown updates");
    }
}

function updateCountdowns() {
    const now = Date.now();
    const seconds = Math.floor(now / 1000);
    const remainingSeconds = 30 - (seconds % 30);
    
    // Update all countdown timer elements
    document.querySelectorAll('.countdown-timer').forEach(timer => {
        timer.textContent = `${remainingSeconds}s`;
    });
    
    // Optional: Update progress bars if you add them
    document.querySelectorAll('.progress-bar').forEach(bar => {
        const progressPercent = (remainingSeconds / 30) * 100;
        bar.style.width = `${progressPercent}%`;
        
        // Change color as time runs out
        if (remainingSeconds <= 5) {
            bar.style.backgroundColor = '#f44336'; // Red
        } else if (remainingSeconds <= 10) {
            bar.style.backgroundColor = '#ff9800'; // Orange
        } else {
            bar.style.backgroundColor = '#4CAF50'; // Green
        }
    });
}

function startAutoRefresh() {
    console.log("Starting auto-refresh...");
    
    stopAutoRefresh();
    
    const now = Date.now();
    const msSinceEpoch = now;
    const secondsSinceEpoch = Math.floor(msSinceEpoch / 1000);
    const secondsIntoCurrentPeriod = secondsSinceEpoch % 30;
    const msIntoCurrentPeriod = (secondsIntoCurrentPeriod * 1000) + (msSinceEpoch % 1000);
    
    // Add 500ms buffer to ensure we are safely into the next period
    const msToNextBoundary = (30000 - msIntoCurrentPeriod) + 500;
    
    console.log(`Next TOTP refresh in: ${Math.round(msToNextBoundary/1000)} seconds`);
    
    // 1. Initial Fetch immediately
    fetchAndDisplayAccounts();
    
    // 2. Schedule the first sync at the boundary
    setTimeout(() => {
        console.log("Boundary reached! Refreshing...");
        fetchAndDisplayAccounts();
        
        // 3. Start the regular 30s interval
        refreshTimer = setInterval(() => {
            if (currentUserEmail && currentUserPassword) {
                const addForm = document.getElementById('addacc-container');
                if (addForm.classList.contains('hidden')) {
                    console.log("Auto-refreshing 2FA codes...");
                    fetchAndDisplayAccounts();
                }
            }
        }, 30000); // Repeat every 30 seconds
    }, msToNextBoundary);
    
    // Start the visual countdown
    startCountdownUpdates();
}

function stopAutoRefresh() {
    if (refreshTimer) {
        clearInterval(refreshTimer);
        refreshTimer = null;
    }
}

// --- DISPLAY LOGIC ---

async function fetchAndDisplayAccounts() {
    try {
        const accounts = await invoke('show_accounts', { 
            mail: currentUserEmail, 
            password: currentUserPassword 
        });

        const list = document.getElementById('codes-list');
        list.innerHTML = ''; 

        if (accounts.length === 0) {
            list.innerHTML = '<p style="text-align:center; color:#666;">No accounts added yet.</p>';
        }

        // Calculate time once for the initial render
        const now = Date.now();
        const remainingSeconds = 30 - (Math.floor(now / 1000) % 30);

        accounts.forEach(([name, issuer, code]) => {
            const div = document.createElement('div');
            div.style = "border-bottom: 1px solid #eee; padding: 15px 0; display: flex; justify-content: space-between; align-items: center;";
            
            // --- FIX IS BELOW ---
            // We added class="countdown-timer" to the spans containing the seconds
            div.innerHTML = `
                <div>
                    <div style="font-size: 12px; color: #666; text-transform: uppercase;">${issuer}</div>
                    <div style="font-weight: bold; font-size: 16px;">${name}</div>
                    <div style="font-size: 11px; color: #999;">
                        Updates in <span class="countdown-timer">${remainingSeconds}s</span>
                    </div>
                </div>
                <div>
                    <div style="font-size: 28px; color: #2196F3; font-family: monospace; letter-spacing: 2px;">
                        ${code}
                    </div>
                    <div class="countdown-timer" style="font-size: 11px; color: #999; text-align: right; font-family: monospace;">
                        ${remainingSeconds}s
                    </div>
                </div>
            `;
            list.appendChild(div);
        });

        const addAccContainer = document.getElementById('addacc-container');
        if (addAccContainer.classList.contains('hidden')) {
            document.getElementById('login-container').classList.add('hidden');
            document.getElementById('accounts-container').classList.remove('hidden');
        }
        
    } catch (error) {
        console.error("Fetch error:", error);
        if (!currentUserEmail) {
            showMessage('login-message', error, 'error');
        }
    }
}

// --- EVENT LISTENERS ---

document.getElementById('refresh-btn').addEventListener('click', fetchAndDisplayAccounts);

document.getElementById('logout-btn').addEventListener('click', () => {
    stopAutoRefresh(); // STOP TIMER
    currentUserEmail = "";
    currentUserPassword = "";
    document.getElementById('accounts-container').classList.add('hidden');
    showLoginForm();
});

document.getElementById('show-login').addEventListener('click', function(e) {
    e.preventDefault();
    showLoginForm();
});

document.getElementById('show-register').addEventListener('click', function(e) {
    e.preventDefault();
    showRegisterForm();
});

document.getElementById('show-addacc-btn').addEventListener('click', function() {
    document.getElementById('accounts-container').classList.add('hidden');
    document.getElementById('addacc-container').classList.remove('hidden');
    
    // Clear inputs
    document.getElementById('new-issuer').value = '';
    document.getElementById('new-name').value = '';
    document.getElementById('new-secret').value = '';
    document.getElementById('add-message').textContent = '';
});

document.getElementById('cancel-add-btn').addEventListener('click', function() {
    // Clear inputs on cancel
    document.getElementById('new-issuer').value = '';
    document.getElementById('new-name').value = '';
    document.getElementById('new-secret').value = '';
    
    document.getElementById('addacc-container').classList.add('hidden');
    document.getElementById('accounts-container').classList.remove('hidden');
    
    // Refresh immediately to show list again
    fetchAndDisplayAccounts();
});

document.getElementById('save-account-btn').addEventListener('click', async function() {
    const issuer = document.getElementById('new-issuer').value;
    const name = document.getElementById('new-name').value;
    let secret = document.getElementById('new-secret').value;
    
    if (!issuer || !name || !secret) {
        showMessage('add-message', "Please fill all fields", "error");
        return;
    }

    secret = secret.replace(/\s/g, '');

    try {
        await invoke('add_account', {
            mail: currentUserEmail,
            password: currentUserPassword,
            name: name,
            issuer: issuer,
            secret: secret
        });

        showMessage('add-message', "Saved!", "success");

        setTimeout(() => {
            document.getElementById('addacc-container').classList.add('hidden');
            document.getElementById('accounts-container').classList.remove('hidden');
            fetchAndDisplayAccounts();
        }, 500);


    } catch (error) {
        console.error(error);
        showMessage('add-message', "Failed: " + error, "error");
    }
});

// --- FORM HELPERS ---

function showLoginForm() {
    document.getElementById('register-container').classList.add('hidden');
    document.getElementById('login-container').classList.remove('hidden');
    clearMessages();
}

function showRegisterForm() {
    document.getElementById('login-container').classList.add('hidden');
    document.getElementById('register-container').classList.remove('hidden');
    clearMessages();
}

function clearMessages() {
    document.getElementById('register-message').textContent = '';
    document.getElementById('register-message').className = 'message';
    document.getElementById('login-message').textContent = '';
    document.getElementById('login-message').className = 'message';
}

function showMessage(elementId, message, type) {
    const element = document.getElementById(elementId);
    element.textContent = message;
    element.className = `message ${type}`;
}

// --- AUTHENTICATION ---

document.getElementById('register-btn').addEventListener('click', async function() {
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;
    
    if (!email || !password) {
        showMessage('register-message', 'Please fill in all fields', 'error');
        return;
    }
    
    if (password.length < 8) {
        showMessage('register-message', 'Password must be at least 8 characters', 'error');
        return;
    }

    try {
        showMessage('register-message', 'Creating account...', 'success');
        const result = await invoke('register', { mail: email, password: password });
        showMessage('register-message', result, 'success');
        document.getElementById('register-email').value = '';
        document.getElementById('register-password').value = '';
    } catch (error) {
        showMessage('register-message', 'Registration failed: ' + error, 'error');
    }
});

document.getElementById('login-btn').addEventListener('click', async function() {
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    
    if (!email || !password) {
        showMessage('login-message', 'Please fill in all fields', 'error');
        return;
    }

    try {
        showMessage('login-message', 'Logging in...', 'success');
        
        await invoke('login', { mail: email, password: password });

        currentUserEmail = email;
        currentUserPassword = password;
        
        fetchAndDisplayAccounts();
        startAutoRefresh(); // Start the timer

        showMessage('login-message', 'Login successful!', 'success');
        
    } catch (error) {
        showMessage('login-message', 'Login failed: ' + error, 'error');
    }
});

window.addEventListener('DOMContentLoaded', () => {
    showRegisterForm();
});