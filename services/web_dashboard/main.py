# Copyright 2026 CCR <chenchunrun@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Web Dashboard Service - Frontend interface for security triage system."""

import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, Optional

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from shared.database import DatabaseManager, get_database_manager
from shared.utils import Config, get_logger

logger = get_logger(__name__)
config = Config()

db_manager: DatabaseManager = None

# Service URLs (can be configured via environment)
SERVICE_URLS = {
    "analytics": "http://localhost:8006",
    "reporting": "http://localhost:8007",
    "notification": "http://localhost:8008",
    "configuration": "http://localhost:8009",
    "llm_router": "http://localhost:8001",
    "workflow": "http://localhost:8004",
    "automation": "http://localhost:8005",
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan."""
    global db_manager

    logger.info("Starting Web Dashboard service...")

    # Initialize database
    db_manager = get_database_manager()
    await db_manager.initialize()

    logger.info("Web Dashboard service started successfully")

    yield

    await db_manager.close()
    logger.info("Web Dashboard service stopped")


app = FastAPI(
    title="Web Dashboard Service",
    description="Frontend interface for security triage system",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# API Proxy endpoints - Forward requests to backend services


async def proxy_request(service: str, path: str, method: str = "GET", data: Dict = None):
    """Proxy request to backend service."""
    try:
        service_url = SERVICE_URLS.get(service)
        if not service_url:
            return {"error": f"Unknown service: {service}"}

        url = f"{service_url}/api/v1{path}"

        async with httpx.AsyncClient() as client:
            if method == "GET":
                response = await client.get(url, timeout=30.0)
            elif method == "POST":
                response = await client.post(url, json=data, timeout=30.0)
            elif method == "PUT":
                response = await client.put(url, json=data, timeout=30.0)
            elif method == "DELETE":
                response = await client.delete(url, timeout=30.0)
            else:
                return {"error": f"Unsupported method: {method}"}

            response.raise_for_status()
            return response.json()

    except Exception as e:
        logger.error(f"Proxy request failed: {e}", exc_info=True)
        return {"error": str(e)}


@app.get("/api/proxy/{service}/{path:path}", response_model=Dict[str, Any])
async def proxy_get(service: str, path: str):
    """Proxy GET request to backend service."""
    return await proxy_request(service, f"/{path}", "GET")


@app.post("/api/proxy/{service}/{path:path}", response_model=Dict[str, Any])
async def proxy_post(service: str, path: str, request: Request):
    """Proxy POST request to backend service."""
    data = await request.json()
    return await proxy_request(service, f"/{path}", "POST", data)


# HTML Templates


def get_base_template(title: str = "Security Triage Dashboard") -> str:
    """Get base HTML template."""
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f5f5f5;
            color: #333;
        }}

        .header {{
            background: #2c3e50;
            color: white;
            padding: 1rem 2rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .header h1 {{
            font-size: 1.5rem;
            font-weight: 600;
        }}

        .nav {{
            background: #34495e;
            padding: 0.5rem 2rem;
        }}

        .nav a {{
            color: #ecf0f1;
            text-decoration: none;
            padding: 0.5rem 1rem;
            margin-right: 0.5rem;
            border-radius: 4px;
            transition: background 0.3s;
        }}

        .nav a:hover {{
            background: #2c3e50;
        }}

        .nav a.active {{
            background: #3498db;
        }}

        .container {{
            max-width: 1400px;
            margin: 2rem auto;
            padding: 0 2rem;
        }}

        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}

        .card {{
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .card h3 {{
            color: #2c3e50;
            margin-bottom: 1rem;
            font-size: 1.1rem;
        }}

        .metric {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem 0;
            border-bottom: 1px solid #ecf0f1;
        }}

        .metric:last-child {{
            border-bottom: none;
        }}

        .metric-label {{
            color: #7f8c8d;
            font-size: 0.9rem;
        }}

        .metric-value {{
            font-size: 1.5rem;
            font-weight: 600;
            color: #2c3e50;
        }}

        .status-healthy {{
            color: #27ae60;
        }}

        .status-warning {{
            color: #f39c12;
        }}

        .status-critical {{
            color: #e74c3c;
        }}

        .btn {{
            display: inline-block;
            padding: 0.5rem 1rem;
            background: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            border: none;
            cursor: pointer;
            font-size: 0.9rem;
            transition: background 0.3s;
        }}

        .btn:hover {{
            background: #2980b9;
        }}

        .btn-success {{
            background: #27ae60;
        }}

        .btn-success:hover {{
            background: #229954;
        }}

        .btn-danger {{
            background: #e74c3c;
        }}

        .btn-danger:hover {{
            background: #c0392b;
        }}

        .table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }}

        .table th,
        .table td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #ecf0f1;
        }}

        .table th {{
            background: #f8f9fa;
            font-weight: 600;
            color: #2c3e50;
        }}

        .badge {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: 600;
        }}

        .badge-critical {{
            background: #fadbd8;
            color: #c0392b;
        }}

        .badge-high {{
            background: #fdebd0;
            color: #dc7633;
        }}

        .badge-medium {{
            background: #fcf3cf;
            color: #f39c12;
        }}

        .badge-low {{
            background: #d5f5e3;
            color: #27ae60;
        }}

        .loading {{
            text-align: center;
            padding: 2rem;
            color: #7f8c8d;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Security Triage System</h1>
    </div>
    <div class="nav">
        <a href="/" class="active">Dashboard</a>
        <a href="/alerts">Alerts</a>
        <a href="/workflows">Workflows</a>
        <a href="/automation">Automation</a>
        <a href="/reports">Reports</a>
        <a href="/settings">Settings</a>
    </div>
"""


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Main dashboard page."""
    html = get_base_template("Dashboard - Security Triage")

    html += """
    <div class="container">
        <div class="grid">
            <div class="card">
                <h3>Total Alerts</h3>
                <div class="metric">
                    <span class="metric-label">Today</span>
                    <span class="metric-value" id="total-alerts">Loading...</span>
                </div>
            </div>

            <div class="card">
                <h3>Triage Performance</h3>
                <div class="metric">
                    <span class="metric-label">Avg Time</span>
                    <span class="metric-value" id="avg-triage-time">Loading...</span>
                </div>
            </div>

            <div class="card">
                <h3>Automation</h3>
                <div class="metric">
                    <span class="metric-label">Playbooks Run</span>
                    <span class="metric-value" id="automation-count">Loading...</span>
                </div>
            </div>

            <div class="card">
                <h3>System Status</h3>
                <div class="metric">
                    <span class="metric-label">Health</span>
                    <span class="metric-value status-healthy">All Systems Operational</span>
                </div>
            </div>
        </div>

        <div class="card">
            <h3>Recent Alerts</h3>
            <div id="recent-alerts" class="loading">Loading...</div>
        </div>
    </div>

    <script>
        // Fetch dashboard data
        async function loadDashboard() {
            try {
                const response = await fetch('/api/proxy/analytics/dashboard');
                const data = await response.json();

                if (data.success && data.data) {
                    const dashboard = data.data;

                    // Update metrics
                    document.getElementById('total-alerts').textContent = dashboard.alert_metrics?.total_alerts || 0;
                    document.getElementById('avg-triage-time').textContent =
                        (dashboard.triage_metrics?.avg_triage_time_seconds || 0).toFixed(1) + 's';
                    document.getElementById('automation-count').textContent =
                        dashboard.automation_metrics?.playbooks_executed || 0;
                }
            } catch (error) {
                console.error('Failed to load dashboard:', error);
            }
        }

        // Load dashboard on page load
        loadDashboard();

        // Refresh every 30 seconds
        setInterval(loadDashboard, 30000);
    </script>
</body>
</html>
    """

    return html


@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page():
    """Alerts list page."""
    html = get_base_template("Alerts - Security Triage")

    html += """
    <div class="container">
        <div class="card">
            <h3>Security Alerts</h3>
            <div class="grid">
                <button class="btn btn-success" onclick="filterAlerts('all')">All</button>
                <button class="btn" onclick="filterAlerts('critical')">Critical</button>
                <button class="btn" onclick="filterAlerts('high')">High</button>
                <button class="btn" onclick="filterAlerts('medium')">Medium</button>
                <button class="btn" onclick="filterAlerts('low')">Low</button>
            </div>
            <div id="alerts-list" class="loading">Loading alerts...</div>
        </div>
    </div>

    <script>
        async function loadAlerts() {
            try {
                const response = await fetch('/api/proxy/analytics/metrics/alerts');
                const data = await response.json();

                if (data.success && data.data) {
                    displayAlerts(data.data);
                }
            } catch (error) {
                console.error('Failed to load alerts:', error);
            }
        }

        function displayAlerts(metrics) {
            const container = document.getElementById('alerts-list');

            // Mock alerts for demo
            const mockAlerts = [
                {id: 'ALT-001', type: 'malware', severity: 'critical', description: 'Ransomware detected'},
                {id: 'ALT-002', type: 'phishing', severity: 'high', description: 'Spear phishing attempt'},
                {id: 'ALT-003', type: 'intrusion', severity: 'medium', description: 'Suspicious login activity'},
                {id: 'ALT-004', type: 'malware', severity: 'low', description: 'Potentially unwanted program'}
            ];

            let html = '<table class="table"><thead><tr><th>ID</th><th>Type</th><th>Severity</th><th>Description</th><th>Actions</th></tr></thead><tbody>';

            mockAlerts.forEach(alert => {
                const badgeClass = `badge-${alert.severity}`;
                html += `
                    <tr>
                        <td>${alert.id}</td>
                        <td>${alert.type}</td>
                        <td><span class="badge ${badgeClass}">${alert.severity.toUpperCase()}</span></td>
                        <td>${alert.description}</td>
                        <td><button class="btn" onclick="viewAlert('${alert.id}')">View</button></td>
                    </tr>
                `;
            });

            html += '</tbody></table>';
            container.innerHTML = html;
        }

        function filterAlerts(severity) {
            console.log('Filtering by severity:', severity);
            // TODO: Implement filtering
        }

        function viewAlert(alertId) {
            console.log('Viewing alert:', alertId);
            // TODO: Show alert details modal
        }

        loadAlerts();
    </script>
</body>
</html>
    """

    return html


@app.get("/workflows", response_class=HTMLResponse)
async def workflows_page():
    """Workflows management page."""
    html = get_base_template("Workflows - Security Triage")

    html += """
    <div class="container">
        <div class="card">
            <h3>Active Workflows</h3>
            <div id="workflows-list" class="loading">Loading workflows...</div>
        </div>

        <div class="card">
            <h3>Workflow Executions</h3>
            <div id="executions-list" class="loading">Loading executions...</div>
        </div>
    </div>

    <script>
        async function loadWorkflows() {
            try {
                const response = await fetch('/api/proxy/workflow/workflows/definitions');
                const data = await response.json();

                if (data.success && data.data) {
                    displayWorkflows(data.data.workflows || []);
                }
            } catch (error) {
                console.error('Failed to load workflows:', error);
            }
        }

        function displayWorkflows(workflows) {
            const container = document.getElementById('workflows-list');
            let html = '<table class="table"><thead><tr><th>ID</th><th>Name</th><th>Steps</th><th>Actions</th></tr></thead><tbody>';

            workflows.forEach(wf => {
                html += `
                    <tr>
                        <td>${wf.workflow_id}</td>
                        <td>${wf.name}</td>
                        <td>${wf.steps?.length || 0}</td>
                        <td><button class="btn" onclick="executeWorkflow('${wf.workflow_id}')">Execute</button></td>
                    </tr>
                `;
            });

            html += '</tbody></table>';
            container.innerHTML = html;
        }

        function executeWorkflow(workflowId) {
            console.log('Executing workflow:', workflowId);
            // TODO: Implement workflow execution
        }

        loadWorkflows();
    </script>
</body>
</html>
    """

    return html


@app.get("/reports", response_class=HTMLResponse)
async def reports_page():
    """Reports page."""
    html = get_base_template("Reports - Security Triage")

    html += """
    <div class="container">
        <div class="card">
            <h3>Generate Report</h3>
            <div class="grid">
                <button class="btn btn-success" onclick="generateReport('daily_summary')">Daily Summary</button>
                <button class="btn" onclick="generateReport('incident_report')">Incident Report</button>
                <button class="btn" onclick="generateReport('trend_analysis')">Trend Analysis</button>
            </div>
            <div id="report-status" style="margin-top: 1rem;"></div>
        </div>

        <div class="card">
            <h3>Recent Reports</h3>
            <div id="reports-list" class="loading">Loading reports...</div>
        </div>
    </div>

    <script>
        async function generateReport(reportType) {
            const statusDiv = document.getElementById('report-status');
            statusDiv.innerHTML = '<p class="loading">Generating report...</p>';

            try {
                const response = await fetch('/api/proxy/reporting/reports/generate', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({report_type: reportType})
                });

                const data = await response.json();

                if (data.success) {
                    statusDiv.innerHTML = `<p class="status-healthy">Report generated: ${data.data.report_id}</p>`;
                    loadReports();
                } else {
                    statusDiv.innerHTML = `<p class="status-critical">Failed to generate report</p>`;
                }
            } catch (error) {
                console.error('Failed to generate report:', error);
                statusDiv.innerHTML = `<p class="status-critical">Error: ${error.message}</p>`;
            }
        }

        async function loadReports() {
            try {
                const response = await fetch('/api/proxy/reporting/reports');
                const data = await response.json();

                if (data.success && data.data) {
                    displayReports(data.data.reports || []);
                }
            } catch (error) {
                console.error('Failed to load reports:', error);
            }
        }

        function displayReports(reports) {
            const container = document.getElementById('reports-list');
            if (reports.length === 0) {
                container.innerHTML = '<p>No reports generated yet.</p>';
                return;
            }

            let html = '<table class="table"><thead><tr><th>ID</th><th>Type</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead><tbody>';

            reports.forEach(report => {
                html += `
                    <tr>
                        <td>${report.report_id}</td>
                        <td>${report.report_type}</td>
                        <td>${report.status}</td>
                        <td>${new Date(report.created_at).toLocaleString()}</td>
                        <td><button class="btn" onclick="downloadReport('${report.report_id}')">Download</button></td>
                    </tr>
                `;
            });

            html += '</tbody></table>';
            container.innerHTML = html;
        }

        function downloadReport(reportId) {
            window.open(`/api/proxy/reporting/reports/${reportId}/download?format=html`, '_blank');
        }

        loadReports();
    </script>
</body>
</html>
    """

    return html


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "web-dashboard",
        "timestamp": datetime.utcnow().isoformat(),
        "services": SERVICE_URLS,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.host, port=8010)
