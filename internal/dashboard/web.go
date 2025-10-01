package dashboard

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ServeWebDashboard serves the main web dashboard interface
func (api *DashboardAPI) ServeWebDashboard(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, dashboardHTML)
}

// RegisterWebRoutes registers the web dashboard routes
func (api *DashboardAPI) RegisterWebRoutes(router *gin.RouterGroup) {
	// Serve the main dashboard page
	router.GET("/dashboard", api.ServeWebDashboard)
	router.GET("/dashboard/", api.ServeWebDashboard)
}

// dashboardHTML contains the complete dashboard web interface
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP Firewall Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            min-height: 100vh;
        }

        .header {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 1rem 2rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .header h1 {
            color: #2d3748;
            font-size: 1.8rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .status-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .status-healthy { background: #48bb78; color: white; }
        .status-warning { background: #ed8936; color: white; }
        .status-critical { background: #f56565; color: white; }

        .dashboard {
            padding: 2rem;
            max-width: 1400px;
            margin: 0 auto;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 8px 32px rgba(31, 38, 135, 0.37);
            backdrop-filter: blur(4px);
            border: 1px solid rgba(255, 255, 255, 0.18);
        }

        .card h3 {
            color: #2d3748;
            margin-bottom: 1rem;
            font-size: 1.2rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .metric {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem 0;
            border-bottom: 1px solid #e2e8f0;
        }

        .metric:last-child {
            border-bottom: none;
        }

        .metric-label {
            color: #4a5568;
            font-weight: 500;
        }

        .metric-value {
            color: #2d3748;
            font-weight: 600;
            font-size: 1.1rem;
        }

        .metric-value.large {
            font-size: 2rem;
            color: #667eea;
        }

        .chart-container {
            height: 200px;
            margin-top: 1rem;
            position: relative;
        }

        .progress-bar {
            width: 100%;
            height: 8px;
            background: #e2e8f0;
            border-radius: 4px;
            overflow: hidden;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #48bb78, #38a169);
            border-radius: 4px;
            transition: width 0.3s ease;
        }

        .attack-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }

        .attack-item {
            background: #f7fafc;
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid #f56565;
        }

        .attack-count {
            font-size: 1.5rem;
            font-weight: 700;
            color: #f56565;
        }

        .attack-type {
            color: #4a5568;
            font-size: 0.9rem;
            margin-top: 0.25rem;
        }

        .recent-requests {
            max-height: 400px;
            overflow-y: auto;
        }

        .request-item {
            padding: 0.75rem;
            border-bottom: 1px solid #e2e8f0;
            display: grid;
            grid-template-columns: 1fr 2fr 1fr 1fr;
            gap: 1rem;
            align-items: center;
            font-size: 0.9rem;
        }

        .request-time {
            color: #4a5568;
        }

        .request-path {
            color: #2d3748;
            font-weight: 500;
        }

        .request-status {
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            color: white;
            font-weight: 600;
            text-align: center;
        }

        .status-200 { background: #48bb78; }
        .status-400 { background: #ed8936; }
        .status-500 { background: #f56565; }

        .request-duration {
            color: #4a5568;
            text-align: right;
        }

        .refresh-info {
            text-align: center;
            color: #4a5568;
            font-size: 0.9rem;
            margin-top: 2rem;
        }

        .loading {
            opacity: 0.6;
            transition: opacity 0.3s ease;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .pulse {
            animation: pulse 2s infinite;
        }

        .emoji {
            font-size: 1.2rem;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>
            🛡️ MCP Firewall Dashboard
            <span id="status-badge" class="status-badge status-healthy">Healthy</span>
        </h1>
    </div>

    <div class="dashboard">
        <!-- Overview Cards -->
        <div class="grid">
            <div class="card">
                <h3>📊 System Overview</h3>
                <div class="metric">
                    <span class="metric-label">Uptime</span>
                    <span class="metric-value" id="uptime">--</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Total Requests</span>
                    <span class="metric-value large" id="total-requests">0</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Active Requests</span>
                    <span class="metric-value" id="active-requests">0</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Attacks Blocked</span>
                    <span class="metric-value" id="total-attacks" style="color: #f56565;">0</span>
                </div>
            </div>

            <div class="card">
                <h3>🚀 Performance</h3>
                <div class="metric">
                    <span class="metric-label">Requests/Second</span>
                    <span class="metric-value" id="rps-current">0</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Peak RPS</span>
                    <span class="metric-value" id="rps-peak">0</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Average Response</span>
                    <span class="metric-value" id="avg-response">0ms</span>
                </div>
                <div class="metric">
                    <span class="metric-label">Longest Response</span>
                    <span class="metric-value" id="longest-response">0ms</span>
                </div>
            </div>

            <div class="card">
                <h3>💾 System Resources</h3>
                <div class="metric">
                    <span class="metric-label">Memory Usage</span>
                    <span class="metric-value" id="memory-usage">0 MB</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" id="memory-progress" style="width: 0%"></div>
                </div>
                <div class="metric">
                    <span class="metric-label">Goroutines</span>
                    <span class="metric-value" id="goroutines">0</span>
                </div>
                <div class="metric">
                    <span class="metric-label">GC Count</span>
                    <span class="metric-value" id="gc-count">0</span>
                </div>
            </div>
        </div>

        <!-- Attack Statistics -->
        <div class="card">
            <h3>🚨 Attack Statistics</h3>
            <div class="attack-grid" id="attack-grid">
                <!-- Attack items will be populated here -->
            </div>
        </div>

        <!-- Recent Requests -->
        <div class="card">
            <h3>📝 Recent Requests</h3>
            <div class="recent-requests" id="recent-requests">
                <!-- Recent requests will be populated here -->
            </div>
        </div>

        <div class="refresh-info">
            🔄 Auto-refreshing every 5 seconds | Last updated: <span id="last-updated">--</span>
        </div>
    </div>

    <script>
        let isLoading = false;

        // Format bytes to human readable
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
        }

        // Format duration
        function formatDuration(ms) {
            if (ms < 1000) return ms + 'ms';
            return (ms / 1000).toFixed(2) + 's';
        }

        // Format timestamp
        function formatTime(timestamp) {
            return new Date(timestamp).toLocaleTimeString();
        }

        // Update dashboard data
        async function updateDashboard() {
            if (isLoading) return;
            isLoading = true;

            try {
                document.body.classList.add('loading');

                // Fetch dashboard data
                const response = await fetch('/api/dashboard/');
                const data = await response.json();

                // Update status badge
                const statusBadge = document.getElementById('status-badge');
                statusBadge.textContent = 'Healthy';
                statusBadge.className = 'status-badge status-healthy';

                // Update overview
                document.getElementById('uptime').textContent = data.uptime;
                document.getElementById('total-requests').textContent = data.total_requests.toLocaleString();
                document.getElementById('active-requests').textContent = data.active_requests;
                document.getElementById('total-attacks').textContent = data.total_attacks_blocked;

                // Update performance
                document.getElementById('rps-current').textContent = data.requests_per_second.toFixed(1);
                document.getElementById('rps-peak').textContent = data.peak_requests_per_sec.toFixed(1);
                document.getElementById('avg-response').textContent = formatDuration(data.average_request_time / 1000000);
                document.getElementById('longest-response').textContent = formatDuration(data.longest_request_time / 1000000);

                // Update system resources
                const memoryMB = data.system_stats.memory_usage / 1024 / 1024;
                document.getElementById('memory-usage').textContent = memoryMB.toFixed(1) + ' MB';
                document.getElementById('memory-progress').style.width = data.system_stats.memory_percent.toFixed(1) + '%';
                document.getElementById('goroutines').textContent = data.system_stats.goroutine_count;
                document.getElementById('gc-count').textContent = data.system_stats.gc_count;

                // Update attack statistics
                updateAttackStats(data.attacks_blocked);

                // Update recent requests
                updateRecentRequests(data.recent_requests);

                // Update timestamp
                document.getElementById('last-updated').textContent = formatTime(data.last_updated);

            } catch (error) {
                console.error('Failed to update dashboard:', error);
                const statusBadge = document.getElementById('status-badge');
                statusBadge.textContent = 'Error';
                statusBadge.className = 'status-badge status-critical';
            } finally {
                document.body.classList.remove('loading');
                isLoading = false;
            }
        }

        // Update attack statistics
        function updateAttackStats(attacks) {
            const attackGrid = document.getElementById('attack-grid');
            attackGrid.innerHTML = '';

            const attackTypes = {
                'prompt_injection': '🎯 Prompt Injection',
                'jailbreak': '🔓 Jailbreak',
                'role_escalation': '⬆️ Role Escalation',
                'emotional_manipulation': '😢 Emotional Manipulation',
                'template_injection': '📝 Template Injection',
                'command_injection': '💻 Command Injection',
                'xss': '🕷️ XSS',
                'sql_injection': '🗄️ SQL Injection',
                'secret_exposure': '🔑 Secret Exposure',
                'compliance_violation': '⚖️ Compliance Violation',
                'rate_limit': '🚦 Rate Limit'
            };

            for (const [type, label] of Object.entries(attackTypes)) {
                const count = attacks[type] || 0;
                const attackItem = document.createElement('div');
                attackItem.className = 'attack-item';
                attackItem.innerHTML = ` + "`" + `
                    <div class="attack-count">${count}</div>
                    <div class="attack-type">${label}</div>
                ` + "`" + `;
                attackGrid.appendChild(attackItem);
            }
        }

        // Update recent requests
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

                const statusClass = req.status_code >= 500 ? 'status-500' :
                                   req.status_code >= 400 ? 'status-400' : 'status-200';

                const attackCount = req.attacks_found ? req.attacks_found.length : 0;
                const attackIndicator = attackCount > 0 ? ` + "`" + ` 🚨${attackCount}` + "`" + ` : '';

                item.innerHTML = ` + "`" + `
                    <div class="request-time">${formatTime(req.start_time)}</div>
                    <div class="request-path">${req.method} ${req.path || '/'}${attackIndicator}</div>
                    <div class="request-status ${statusClass}">${req.status_code}</div>
                    <div class="request-duration">${formatDuration(req.duration / 1000000)}</div>
                ` + "`" + `;
                container.appendChild(item);
            });
        }

        // Initialize dashboard
        updateDashboard();

        // Auto-refresh every 5 seconds
        setInterval(updateDashboard, 5000);

        // Add pulse animation to important metrics
        setInterval(() => {
            const activeRequests = document.getElementById('active-requests');
            const totalAttacks = document.getElementById('total-attacks');

            if (parseInt(activeRequests.textContent) > 0) {
                activeRequests.classList.add('pulse');
                setTimeout(() => activeRequests.classList.remove('pulse'), 1000);
            }

            if (parseInt(totalAttacks.textContent) > 0) {
                totalAttacks.classList.add('pulse');
                setTimeout(() => totalAttacks.classList.remove('pulse'), 1000);
            }
        }, 3000);
    </script>
</body>
</html>`