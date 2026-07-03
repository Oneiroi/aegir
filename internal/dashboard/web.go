package dashboard

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// newCSPNonce returns a fresh base64 nonce for per-request CSP (AEGIR-L-001).
func newCSPNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Non-fatal: an empty nonce yields a CSP that blocks the inline script,
		// which fails safe (dashboard breaks) rather than falling open.
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// ServeWebDashboard serves the main web dashboard interface.
// AEGIR-L-001: inline <style>/<script> are authorised with a per-request nonce
// instead of 'unsafe-inline', so injected inline scripts without the nonce are
// blocked by the browser.
func (api *DashboardAPI) ServeWebDashboard(c *gin.Context) {
	nonce := newCSPNonce()
	c.Header("Content-Security-Policy",
		"default-src 'self'; script-src 'self' 'nonce-"+nonce+"'; style-src 'self' 'nonce-"+nonce+"'; connect-src 'self'")
	c.Header("Content-Type", "text/html; charset=utf-8")
	page := strings.ReplaceAll(dashboardHTML, "{{CSP_NONCE}}", nonce)
	c.String(http.StatusOK, page)
}

// RegisterWebRoutes registers the web dashboard routes
func (api *DashboardAPI) RegisterWebRoutes(router *gin.RouterGroup) {
	router.GET("/dashboard", api.ServeWebDashboard)
	router.GET("/dashboard/", api.ServeWebDashboard)
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aegir</title>
    <style nonce="{{CSP_NONCE}}">
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333; min-height: 100vh;
        }
        .header {
            background: rgba(255,255,255,0.95); backdrop-filter: blur(10px);
            padding: 1rem 2rem; border-bottom: 1px solid rgba(255,255,255,0.2);
            position: sticky; top: 0; z-index: 100;
        }
        .header h1 { color: #2d3748; font-size: 1.8rem; display: flex; align-items: center; gap: 0.5rem; }
        .status-badge { padding: 0.25rem 0.75rem; border-radius: 20px; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; }
        .status-healthy { background: #48bb78; color: white; }
        .status-warning { background: #ed8936; color: white; }
        .status-critical { background: #f56565; color: white; }
        .dashboard { padding: 2rem; max-width: 1400px; margin: 0 auto; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
        .card { background: rgba(255,255,255,0.95); border-radius: 12px; padding: 1.5rem; box-shadow: 0 8px 32px rgba(31,38,135,0.37); backdrop-filter: blur(4px); border: 1px solid rgba(255,255,255,0.18); }
        .card h3 { color: #2d3748; margin-bottom: 1rem; font-size: 1.2rem; display: flex; align-items: center; gap: 0.5rem; }
        .metric { display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 0; border-bottom: 1px solid #e2e8f0; }
        .metric:last-child { border-bottom: none; }
        .metric-label { color: #4a5568; font-weight: 500; }
        .metric-value { color: #2d3748; font-weight: 600; font-size: 1.1rem; }
        .metric-value.large { font-size: 2rem; color: #667eea; }
        .progress-bar { width: 100%; height: 8px; background: #e2e8f0; border-radius: 4px; overflow: hidden; }
        .progress-fill { height: 100%; background: linear-gradient(90deg, #48bb78, #38a169); border-radius: 4px; transition: width 0.3s ease; }
        .attack-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }
        .attack-item { background: #f7fafc; padding: 1rem; border-radius: 8px; border-left: 4px solid #f56565; }
        .attack-count { font-size: 1.5rem; font-weight: 700; color: #f56565; }
        .attack-type { color: #4a5568; font-size: 0.9rem; margin-top: 0.25rem; }
        .recent-requests { max-height: 400px; overflow-y: auto; }
        .request-item { padding: 0.75rem; border-bottom: 1px solid #e2e8f0; display: grid; grid-template-columns: 1fr 2fr 1fr 1fr; gap: 1rem; align-items: center; font-size: 0.9rem; }
        .request-time { color: #4a5568; }
        .request-path { color: #2d3748; font-weight: 500; }
        .request-status { padding: 0.25rem 0.5rem; border-radius: 4px; color: white; font-weight: 600; text-align: center; }
        .status-200 { background: #48bb78; } .status-400 { background: #ed8936; } .status-500 { background: #f56565; }
        .request-duration { color: #4a5568; text-align: right; }
        .login-form { max-width: 400px; margin: 2rem auto; background: rgba(255,255,255,0.95); border-radius: 12px; padding: 2rem; box-shadow: 0 8px 32px rgba(31,38,135,0.37); }
        .login-form h2 { color: #2d3748; margin-bottom: 1.5rem; text-align: center; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; color: #4a5568; font-weight: 500; margin-bottom: 0.5rem; }
        .form-group input { width: 100%; padding: 0.75rem; border: 2px solid #e2e8f0; border-radius: 8px; font-size: 1rem; }
        .form-group input:focus { outline: none; border-color: #667eea; }
        .btn { width: 100%; padding: 0.75rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; }
        .btn:hover { transform: translateY(-2px); }
        .btn-error { background: #f56565; }
        .error-message { background: #fed7d7; color: #c53030; padding: 1rem; border-radius: 8px; margin-bottom: 1rem; text-align: center; }
        .refresh-info { text-align: center; color: #4a5568; font-size: 0.9rem; margin-top: 2rem; }
        .loading { opacity: 0.6; transition: opacity 0.3s ease; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        .pulse { animation: pulse 2s infinite; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Aegir <span id="status-badge" class="status-badge status-healthy">Healthy</span></h1>
    </div>

    <div class="dashboard">
        <div id="login-section" class="login-form">
            <h2>Sign In</h2>
            <div id="login-error" class="error-message" style="display: none;"></div>
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" placeholder="admin" autocomplete="off">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" placeholder="Password" autocomplete="off">
            </div>
            <button class="btn" onclick="handleLogin()">Sign In</button>
            <div style="text-align: center; margin-top: 1rem;">
                <small style="color: #718096;">The admin password is generated at first start and printed to the server log (set AEGIR_ADMIN_PASSWORD to choose your own).</small>
            </div>
        </div>

        <div id="dashboard-section" style="display: none;">
            <div class="grid">
                <div class="card">
                    <h3>System Overview</h3>
                    <div class="metric"><span class="metric-label">Uptime</span><span class="metric-value" id="uptime">--</span></div>
                    <div class="metric"><span class="metric-label">Total Requests</span><span class="metric-value large" id="total-requests">0</span></div>
                    <div class="metric"><span class="metric-label">Active Requests</span><span class="metric-value" id="active-requests">0</span></div>
                    <div class="metric"><span class="metric-label">Attacks Blocked</span><span class="metric-value" id="total-attacks" style="color: #f56565;">0</span></div>
                </div>
                <div class="card">
                    <h3>Performance</h3>
                    <div class="metric"><span class="metric-label">Requests/Sec</span><span class="metric-value" id="rps-current">0</span></div>
                    <div class="metric"><span class="metric-label">Peak RPS</span><span class="metric-value" id="rps-peak">0</span></div>
                    <div class="metric"><span class="metric-label">Avg Response</span><span class="metric-value" id="avg-response">0ms</span></div>
                    <div class="metric"><span class="metric-label">Longest</span><span class="metric-value" id="longest-response">0ms</span></div>
                </div>
                <div class="card">
                    <h3>System Resources</h3>
                    <div class="metric"><span class="metric-label">Memory</span><span class="metric-value" id="memory-usage">0 MB</span></div>
                    <div class="progress-bar"><div class="progress-fill" id="memory-progress" style="width: 0%"></div></div>
                    <div class="metric"><span class="metric-label">Goroutines</span><span class="metric-value" id="goroutines">0</span></div>
                    <div class="metric"><span class="metric-label">GC Count</span><span class="metric-value" id="gc-count">0</span></div>
                </div>
            </div>

            <div class="card">
                <h3>Attack Statistics</h3>
                <div class="attack-grid" id="attack-grid"></div>
            </div>

            <div class="card">
                <h3>Recent Requests</h3>
                <div class="recent-requests" id="recent-requests"></div>
            </div>

            <div class="refresh-info">Auto-refreshing every 5 seconds | Last updated: <span id="last-updated">--</span></div>
        </div>
    </div>

    <script nonce="{{CSP_NONCE}}">
    let token = localStorage.getItem('aegir_token');
    // Guard against a stale "undefined" string stored by a previous bad login.
    if (token === 'undefined' || token === 'null') {
        localStorage.removeItem('aegir_token');
        token = null;
    }
    let isLoading = false;

    if (token) {
        document.getElementById('login-section').style.display = 'none';
        document.getElementById('dashboard-section').style.display = 'block';
        updateDashboard();
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    function formatDuration(ms) {
        if (ms < 1000) return ms + 'ms';
        return (ms / 1000).toFixed(2) + 's';
    }

    function formatTime(timestamp) {
        return new Date(timestamp).toLocaleTimeString();
    }

    async function updateDashboard() {
        if (isLoading) return;
        isLoading = true;
        try {
            document.body.classList.add('loading');
            const response = await fetch('/api/dashboard/', {
                headers: token ? { 'Authorization': 'Bearer ' + token } : {}
            });
            if (response.status === 401) {
                localStorage.removeItem('aegir_token');
                token = null;
                document.getElementById('dashboard-section').style.display = 'none';
                document.getElementById('login-section').style.display = 'block';
                return;
            }
            const data = await response.json();
            const statusBadge = document.getElementById('status-badge');
            statusBadge.textContent = 'Healthy';
            statusBadge.className = 'status-badge status-healthy';
            document.getElementById('uptime').textContent = data.uptime;
            document.getElementById('total-requests').textContent = data.total_requests.toLocaleString();
            document.getElementById('active-requests').textContent = data.active_requests;
            document.getElementById('total-attacks').textContent = data.total_attacks_blocked;
            document.getElementById('rps-current').textContent = data.requests_per_second.toFixed(1);
            document.getElementById('rps-peak').textContent = data.peak_requests_per_sec.toFixed(1);
            document.getElementById('avg-response').textContent = formatDuration(data.average_request_time / 1000000);
            document.getElementById('longest-response').textContent = formatDuration(data.longest_request_time / 1000000);
            const memoryMB = data.system_stats.memory_usage / 1024 / 1024;
            document.getElementById('memory-usage').textContent = memoryMB.toFixed(1) + ' MB';
            document.getElementById('memory-progress').style.width = data.system_stats.memory_percent.toFixed(1) + '%';
            document.getElementById('goroutines').textContent = data.system_stats.goroutine_count;
            document.getElementById('gc-count').textContent = data.system_stats.gc_count;
            updateAttackStats(data.attacks_blocked);
            updateRecentRequests(data.recent_requests);
            document.getElementById('last-updated').textContent = formatTime(data.last_updated);
        } catch (error) {
            console.error('Failed to update dashboard:', error);
            document.getElementById('status-badge').textContent = 'Error';
            document.getElementById('status-badge').className = 'status-badge status-critical';
        } finally {
            document.body.classList.remove('loading');
            isLoading = false;
        }
    }

    function updateAttackStats(attacks) {
        const grid = document.getElementById('attack-grid');
        grid.innerHTML = '';
        const attackTypes = {
            'prompt_injection': 'Prompt Injection',
            'jailbreak': 'Jailbreak',
            'role_escalation': 'Role Escalation',
            'emotional_manipulation': 'Emotional Manipulation',
            'template_injection': 'Template Injection',
            'command_injection': 'Command Injection',
            'xss': 'XSS',
            'sql_injection': 'SQL Injection',
            'secret_exposure': 'Secret Exposure',
            'compliance_violation': 'Compliance Violation',
            'rate_limit': 'Rate Limit'
        };
        for (const [type, label] of Object.entries(attackTypes)) {
            const count = attacks[type] || 0;
            const div = document.createElement('div');
            div.className = 'attack-item';
            div.innerHTML = '<div class="attack-count">' + count + '</div><div class="attack-type">' + label + '</div>';
            grid.appendChild(div);
        }
    }

    function updateRecentRequests(requests) {
        const container = document.getElementById('recent-requests');
        container.innerHTML = '';
        if (!requests || requests.length === 0) {
            container.innerHTML = '<div style="text-align: center; padding: 2rem; color: #4a5568;">No recent requests</div>';
            return;
        }
        requests.slice(-20).reverse().forEach(req => {
            const item = document.createElement('div');
            item.className = 'request-item';
            const statusClass = req.status_code >= 500 ? 'status-500' : req.status_code >= 400 ? 'status-400' : 'status-200';
            item.innerHTML = '<div class="request-time">' + formatTime(req.start_time) + '</div><div class="request-path">' + (req.method || '') + ' ' + (req.path || '/') + '</div><div class="request-status ' + statusClass + '">' + req.status_code + '</div><div class="request-duration">' + formatDuration(req.duration / 1000000) + '</div>';
            container.appendChild(item);
        });
    }

    async function handleLogin() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const loginError = document.getElementById('login-error');
        loginError.style.display = 'none';
        try {
            const response = await fetch('/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            if (!response.ok) {
                const data = await response.json().catch(() => ({}));
                throw new Error(data.message || 'Login failed');
            }
            const data = await response.json();
            token = data.access_token;
            localStorage.setItem('aegir_token', token);
            document.getElementById('login-section').style.display = 'none';
            document.getElementById('dashboard-section').style.display = 'block';
            updateDashboard();
        } catch (error) {
            loginError.textContent = error.message;
            loginError.style.display = 'block';
        }
    }

    // AEGIR-L-005: idle session timeout. After 15 minutes with no user
    // interaction the token is cleared and the login form is shown, so an
    // unattended dashboard cannot be used for persistent monitoring.
    const IDLE_TIMEOUT_MS = 15 * 60 * 1000;
    let lastActivity = Date.now();
    function markActivity() { lastActivity = Date.now(); }
    ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'].forEach(
        ev => document.addEventListener(ev, markActivity, { passive: true }));
    function logout() {
        localStorage.removeItem('aegir_token');
        token = null;
        document.getElementById('dashboard-section').style.display = 'none';
        document.getElementById('login-section').style.display = 'block';
    }
    function checkIdle() {
        if (token && Date.now() - lastActivity > IDLE_TIMEOUT_MS) { logout(); }
    }

    setInterval(() => { checkIdle(); if (token) updateDashboard(); }, 5000);
    setInterval(() => {
        const el1 = document.getElementById('active-requests');
        const el2 = document.getElementById('total-attacks');
        if (parseInt(el1.textContent) > 0) { el1.classList.add('pulse'); setTimeout(() => el1.classList.remove('pulse'), 1000); }
        if (parseInt(el2.textContent) > 0) { el2.classList.add('pulse'); setTimeout(() => el2.classList.remove('pulse'), 1000); }
    }, 3000);
    </script>
</body>
</html>`