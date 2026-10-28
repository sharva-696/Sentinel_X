/**
 * Sentinel-X Overview Dashboard Component
 * Aggregates high-level metrics, risk distribution, and recent assessments.
 */

import { api } from '../api.js';
import { state, formatDate, escapeHtml } from '../state.js';

export async function renderOverview(container) {
    container.innerHTML = `
        <div class="view-header">
            <div>
                <h1 class="view-title">Security Assessment Overview</h1>
                <p class="view-subtitle">Executive summary of firmware artifacts and connected ESP32 hardware.</p>
            </div>
            <div class="view-actions">
                <button class="btn btn-primary" id="btn-quick-analyze">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                        <polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
                    </svg>
                    New Firmware Scan
                </button>
            </div>
        </div>

        <div class="overview-loading" id="overview-loading">
            <div class="spinner"></div>
            <span>Loading telemetry from local database...</span>
        </div>

        <div id="overview-content" style="display: none;">
            <!-- Metrics Grid -->
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-label">Total Assessments</div>
                    <div class="metric-val" id="metric-total-assessments">0</div>
                    <div class="metric-hint">Analyzed firmware binaries</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Highest Risk Score</div>
                    <div class="metric-val" id="metric-max-risk">0</div>
                    <div class="metric-hint" id="metric-max-risk-label">Clean</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">High / Critical Findings</div>
                    <div class="metric-val text-danger" id="metric-crit-findings">0</div>
                    <div class="metric-hint">Actionable security indicators</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Identified Devices</div>
                    <div class="metric-val text-primary" id="metric-devices-count">0</div>
                    <div class="metric-hint">ESP32 hardware targets</div>
                </div>
            </div>

            <!-- Recent Assessments Section -->
            <div class="card mt-4">
                <div class="card-header flex-between">
                    <h2 class="card-title">Recent Firmware Assessments</h2>
                    <button class="btn btn-secondary btn-sm" id="btn-view-all-history">View All History &rarr;</button>
                </div>
                <div class="table-responsive">
                    <table class="data-table" id="recent-assessments-table">
                        <thead>
                            <tr>
                                <th>Target File</th>
                                <th>Detected Format</th>
                                <th>Risk Score</th>
                                <th>Severity Summary</th>
                                <th>Date</th>
                                <th class="text-right">Action</th>
                            </tr>
                        </thead>
                        <tbody id="recent-assessments-tbody">
                            <!-- Populated dynamically -->
                        </tbody>
                    </table>
                </div>
                <div id="overview-empty-state" class="empty-state" style="display: none;">
                    <div class="empty-icon">
                        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                            <polyline points="14 2 14 8 20 8"/>
                        </svg>
                    </div>
                    <h3>No Firmware Assessments Recorded</h3>
                    <p>Upload an ESP32 application binary, bootloader, or flash dump to begin vulnerability analysis.</p>
                    <button class="btn btn-primary mt-2" id="btn-empty-analyze">Upload Firmware</button>
                </div>
            </div>
        </div>
    `;

    // Hook quick scan buttons
    container.querySelector('#btn-quick-analyze')?.addEventListener('click', () => state.setRoute('analyze'));
    container.querySelector('#btn-empty-analyze')?.addEventListener('click', () => state.setRoute('analyze'));
    container.querySelector('#btn-view-all-history')?.addEventListener('click', () => state.setRoute('history'));

    // Fetch live data
    try {
        const [assessmentsData, devicesData] = await Promise.all([
            api.listAssessments({ skip: 0, limit: 10 }),
            api.listDevices(),
        ]);

        const assessments = assessmentsData.assessments || [];
        const totalCount = assessmentsData.total_assessments || assessments.length;
        const devices = devicesData.devices || [];

        state.setAssessments(assessments, totalCount);
        state.setDevices(devices);

        // Calculate overview stats
        let maxRisk = 0;
        let maxRiskRating = 'Clean';
        let critHighCount = 0;

        for (const a of assessments) {
            if (a.risk_score > maxRisk) {
                maxRisk = a.risk_score;
                maxRiskRating = a.risk_rating;
            }
            if (a.findings_summary) {
                critHighCount += (a.findings_summary.critical || 0) + (a.findings_summary.high || 0);
            }
        }

        // Populate metrics
        document.getElementById('metric-total-assessments').textContent = totalCount;
        document.getElementById('metric-max-risk').textContent = maxRisk;
        document.getElementById('metric-max-risk-label').textContent = `${maxRiskRating} Rating Band`;
        document.getElementById('metric-crit-findings').textContent = critHighCount;
        document.getElementById('metric-devices-count').textContent = devices.length;

        const tbody = document.getElementById('recent-assessments-tbody');
        const emptyState = document.getElementById('overview-empty-state');
        const table = document.getElementById('recent-assessments-table');

        if (assessments.length === 0) {
            table.style.display = 'none';
            emptyState.style.display = 'block';
        } else {
            table.style.display = 'table';
            emptyState.style.display = 'none';
            tbody.innerHTML = '';

            for (const item of assessments.slice(0, 5)) {
                const tr = document.createElement('tr');
                const summ = item.findings_summary || {};

                tr.innerHTML = `
                    <td>
                        <div class="font-medium text-main">${escapeHtml(item.filename)}</div>
                        <div class="text-xs text-muted">ID: ${escapeHtml(item.id.slice(0, 8))}...</div>
                    </td>
                    <td><code>${escapeHtml(item.image_type)}</code></td>
                    <td>
                        <span class="risk-badge risk-${item.risk_rating.toLowerCase()}">
                            ${item.risk_score} &bull; ${escapeHtml(item.risk_rating)}
                        </span>
                    </td>
                    <td>
                        <div class="severity-pills">
                            ${summ.critical ? `<span class="pill pill-critical">${summ.critical} Crit</span>` : ''}
                            ${summ.high ? `<span class="pill pill-high">${summ.high} High</span>` : ''}
                            ${summ.medium ? `<span class="pill pill-medium">${summ.medium} Med</span>` : ''}
                            ${summ.low ? `<span class="pill pill-low">${summ.low} Low</span>` : ''}
                            ${!summ.total_unique ? `<span class="text-xs text-muted">Clean (0)</span>` : ''}
                        </div>
                    </td>
                    <td class="text-sm text-muted">${formatDate(item.created_at)}</td>
                    <td class="text-right">
                        <button class="btn btn-secondary btn-sm btn-inspect" data-id="${escapeHtml(item.id)}">
                            Inspect
                        </button>
                    </td>
                `;

                tr.querySelector('.btn-inspect').addEventListener('click', () => {
                    state.setRoute('detail', item.id);
                });

                tbody.appendChild(tr);
            }
        }

        document.getElementById('overview-loading').style.display = 'none';
        document.getElementById('overview-content').style.display = 'block';

    } catch (err) {
        document.getElementById('overview-loading').innerHTML = `
            <div class="alert alert-danger">
                <strong>Error loading overview:</strong> ${escapeHtml(err.message)}
            </div>
        `;
    }
}
