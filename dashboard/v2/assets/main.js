// Security Suite Dashboard JavaScript

const API_BASE = 'http://localhost:8000/api';
let currentView = 'agents';
let currentRun = null;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    checkSystemHealth();
    loadAgents();
    loadTasks();
    loadFindings();
    loadRuns();
    loadReports();

    // Auto-refresh every 10 seconds
    setInterval(refreshAll, 10000);

    // Check health every 30 seconds
    setInterval(checkSystemHealth, 30000);
});

// View Management
function showView(viewName) {
    // Hide all views
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    // Show selected view
    document.getElementById(`${viewName}-view`).classList.add('active');

    // Highlight the corresponding nav item if exists
    const navItem = document.querySelector(`.nav-item[onclick*="${viewName}"]`);
    if (navItem) {
        navItem.classList.add('active');
    }

    currentView = viewName;

    // Load data for view
    if (viewName === 'agents') loadAgents();
    if (viewName === 'kanban') loadTasks();
    if (viewName === 'findings') loadFindings();
    if (viewName === 'runs') loadRuns();
    if (viewName === 'reports') loadReports();
}

function refreshAll() {
    if (currentView === 'agents') loadAgents();
    if (currentView === 'kanban') loadTasks();
    if (currentView === 'findings') loadFindings();
    if (currentView === 'runs') loadRuns();
    if (currentView === 'reports') loadReports();
}

// Agents View
async function loadAgents() {
    try {
        // Load system health
        const healthResponse = await fetch(`${API_BASE}/health`);
        const health = await healthResponse.json();

        // Update system status (already shown in HTML, but could add dynamic info here)
        console.log('System health:', health);
    } catch (error) {
        console.error('Error loading system status:', error);
    }
}

// Load other views
async function loadTasks() {
    try {
        const response = await fetch(`${API_BASE}/tasks?limit=500`);
        const tasks = await response.json();

        // Clear all kanban columns
        ['backlog', 'in-progress', 'blocked', 'completed'].forEach(status => {
            document.getElementById(`${status}-tasks`).innerHTML = '';
            document.getElementById(`${status}-count`).textContent = '0';
        });

        // Sort tasks by status
        const tasksByStatus = {
            'pending': [],
            'in_progress': [],
            'blocked': [],
            'completed': []
        };

        tasks.forEach(task => {
            let status = task.status;
            // Map failed tasks to blocked column
            if (status === 'failed') {
                status = 'blocked';
            }
            if (tasksByStatus[status]) {
                tasksByStatus[status].push(task);
            }
        });

        // Render tasks in each column
        Object.keys(tasksByStatus).forEach(status => {
            const columnId = status === 'pending' ? 'backlog' : status.replace('_', '-');
            const tasks = tasksByStatus[status];
            const container = document.getElementById(`${columnId}-tasks`);

            if (tasks.length === 0) {
                container.innerHTML = '<p class="empty">No tasks</p>';
            } else {
                container.innerHTML = tasks.map(task => {
                    const statusBadge = task.status === 'failed' ? '<span style="color: #ef4444; font-weight: bold;">❌ FAILED</span>' : '';
                    return `
                    <div class="task-card">
                        <div class="task-header">
                            <span class="task-type">${task.type}</span>
                            <span class="task-priority priority-${task.priority}">${task.priority}</span>
                        </div>
                        <h4>${task.title}</h4>
                        ${statusBadge}
                        <p class="task-agent">👤 ${task.assignee_agent}</p>
                        <p class="task-time">${new Date(task.created_at).toLocaleString()}</p>
                    </div>
                `;
                }).join('');
            }

            document.getElementById(`${columnId}-count`).textContent = tasks.length;
        });

        console.log('Tasks loaded:', tasks.length);
    } catch (error) {
        console.error('Error loading tasks:', error);
    }
}

async function loadFindings() {
    try {
        const response = await fetch(`${API_BASE}/findings?limit=100`);
        const findings = await response.json();
        document.getElementById('findings-list').innerHTML = '<p>Findings loaded</p>';
    } catch (error) {
        console.error('Error loading findings:', error);
    }
}

async function loadRuns() {
    try {
        const response = await fetch(`${API_BASE}/runs`);
        const data = await response.json();
        const runs = data.runs || [];

        const container = document.getElementById('runs-list');

        if (runs.length === 0) {
            container.innerHTML = '<p class="empty">No runs yet. Click "New Run" to start!</p>';
            return;
        }

        container.innerHTML = runs.map(run => {
            const summary = run.summary || {};
            const statusIcon = run.status === 'completed' ? '✅' : '🔄';

            return `
                <div class="run-card">
                    <div class="run-header">
                        <h3>${statusIcon} ${run.run_id}</h3>
                        <span class="run-status status-${run.status}">${run.status}</span>
                    </div>
                    <div class="run-details">
                        <p><strong>Started:</strong> ${new Date(run.started_at).toLocaleString()}</p>
                        ${run.completed_at ? `<p><strong>Completed:</strong> ${new Date(run.completed_at).toLocaleString()}</p>` : ''}
                        <p><strong>Scope:</strong> ${(run.scope?.in_scope || []).join(', ')}</p>
                        <p><strong>Tasks:</strong> ${summary.completed || 0} completed, ${summary.failed || 0} failed, ${summary.total_tasks || run.total_tasks || 0} total</p>
                    </div>
                </div>
            `;
        }).join('');

        console.log('Runs loaded:', runs.length);
    } catch (error) {
        console.error('Error loading runs:', error);
        document.getElementById('runs-list').innerHTML = '<p class="error">Failed to load runs</p>';
    }
}

async function loadReports() {
    try {
        const response = await fetch(`${API_BASE}/reports`);
        const data = await response.json();
        const reports = data.reports || [];

        const container = document.getElementById('reports-list');

        if (reports.length === 0) {
            container.innerHTML = '<p class="empty">No reports yet. Run a scan to generate reports!</p>';
            return;
        }

        container.innerHTML = reports.map(report => {
            const icon = report.type === 'recon' ? '🔍' : '📱';
            const title = report.type === 'recon'
                ? `EASD Report: ${report.target}`
                : `APK Analysis: ${report.apk_name}`;
            const details = report.type === 'recon'
                ? `${report.subdomains} subdomains discovered`
                : `${report.vulnerabilities} vulnerabilities found`;

            // Generate report action buttons
            let actionButtons = '';
            if (report.type === 'recon') {
                // EASD reports have both HTML and JSON
                actionButtons = `
                    <div style="display: flex; gap: 0.5rem; flex-direction: column;">
                        ${report.html_report ? `
                            <a href="/api/reports/${report.run_id}/html"
                               target="_blank"
                               class="btn btn-primary"
                               style="white-space: nowrap; text-align: center;">
                                🌐 View HTML Report
                            </a>
                        ` : ''}
                        <a href="/api/reports/${report.run_id}/json"
                           class="btn"
                           download
                           style="white-space: nowrap; text-align: center;">
                            📥 Download JSON
                        </a>
                    </div>
                `;
            } else {
                // APK reports have both HTML and JSON
                actionButtons = `
                    <div style="display: flex; gap: 0.5rem; flex-direction: column;">
                        ${report.html_report ? `
                            <a href="/api/reports/${report.run_id}/html"
                               target="_blank"
                               class="btn btn-primary"
                               style="white-space: nowrap; text-align: center;">
                                🌐 View HTML Report
                            </a>
                        ` : ''}
                        <a href="/api/artifacts/download?path=${encodeURIComponent(report.file)}"
                           class="btn"
                           download
                           style="white-space: nowrap; text-align: center;">
                            📥 Download JSON
                        </a>
                    </div>
                `;
            }

            return `
                <div class="report-card" style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem;">
                    <div style="display: flex; justify-content: space-between; align-items: start; gap: 1rem;">
                        <div style="flex: 1;">
                            <h3 style="color: var(--accent-blue); margin-bottom: 0.5rem;">${icon} ${title}</h3>
                            <p style="color: var(--text-secondary); margin: 0.25rem 0;">${details}</p>
                            <p style="color: var(--text-secondary); font-size: 0.85rem; margin: 0.25rem 0;">
                                Run ID: <code style="background: var(--bg-primary); padding: 0.25rem 0.5rem; border-radius: 4px;">${report.run_id}</code>
                            </p>
                            <p style="color: var(--text-secondary); font-size: 0.85rem;">
                                Generated: ${new Date(report.timestamp * 1000).toLocaleString()}
                            </p>
                        </div>
                        <div style="min-width: 180px;">
                            ${actionButtons}
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        console.log('Reports loaded:', reports.length);
    } catch (error) {
        console.error('Error loading reports:', error);
        document.getElementById('reports-list').innerHTML = '<p class="error">Failed to load reports</p>';
    }
}

function showNewRunModal() {
    document.getElementById('new-run-modal').style.display = 'flex';
}

function closeNewRunModal() {
    document.getElementById('new-run-modal').style.display = 'none';
}

async function startNewRun() {
    const startButton = event.target;
    const originalText = startButton.textContent;

    try {
        // Disable button and show loading state
        startButton.disabled = true;
        startButton.textContent = '⏳ Starting...';

        const inScope = document.getElementById('in-scope').value.split('\n').filter(x => x.trim());
        const dryRun = document.getElementById('dry-run').checked;

        console.log('Starting new run with:', {inScope, dryRun});

        // Categorize targets: domains or APKs
        const domains = [];
        const apks = [];

        inScope.forEach(item => {
            const trimmed = item.trim();
            if (trimmed.endsWith('.apk') || trimmed.includes('.apk') || (trimmed.startsWith('http') && trimmed.includes('.apk'))) {
                apks.push(trimmed);
            } else if (trimmed) {
                // Assume it's a domain
                domains.push(trimmed);
            }
        });

        console.log('Categorized targets:', {domains, apks});

        if (domains.length === 0 && apks.length === 0) {
            alert('❌ Please enter at least one domain or APK file');
            return;
        }

        const payload = {
            domains: domains,
            apks: apks,
            dry_run: dryRun
        };
        console.log('Sending payload to API:', payload);

        const response = await fetch(`${API_BASE}/runs/start`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });

        console.log('Response status:', response.status);

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Error response:', errorText);
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        const result = await response.json();
        console.log('✅ Run started successfully:', result);

        alert(`✅ ${result.message}\nRun ID: ${result.run_id}\n\nCheck the Tasks tab to see progress!`);

        // Clear the form
        document.getElementById('in-scope').value = '';

        closeNewRunModal();

        // Switch to tasks view to show progress
        showView('kanban');
        refreshAll();

    } catch (error) {
        console.error('❌ Error starting run:', error);
        alert(`❌ Error starting run:\n${error.message}\n\nCheck browser console (F12) for details`);
    } finally {
        // Re-enable button
        startButton.disabled = false;
        startButton.textContent = originalText;
    }
}

async function checkSystemHealth() {
    try {
        const response = await fetch(`${API_BASE}/health/system`);
        const health = await response.json();
        console.log('System health:', health);
    } catch (error) {
        console.error('Health check failed:', error);
    }
}
