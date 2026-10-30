/**
 * Sentinel-X Assessment History Component
 * Paginated history, risk filters, inspection links, and safe deletion confirmation.
 */

import { api } from '../api.js';
import { state, formatDate, formatBytes, escapeHtml } from '../state.js';

export async function renderHistory(container) {
    container.innerHTML = `
        <div class="view-header flex-between">
            <div>
                <h1 class="view-title">Assessment History</h1>
                <p class="view-subtitle">Review historical firmware assessments, findings distributions, and reports.</p>
            </div>
            <div class="flex-center gap-3">
                <select class="form-select" id="history-filter-risk">
                    <option value="">All Risk Bands</option>
                    <option value="Critical">Critical (80–100)</option>
                    <option value="High">High (50–79)</option>
                    <option value="Moderate">Moderate (20–49)</option>
                    <option value="Low">Low (1–19)</option>
                    <option value="Clean">Clean (0)</option>
                </select>
                <button class="btn btn-secondary" id="btn-refresh-history">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="23 4 23 10 17 10"/>
                        <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                    </svg>
                    Refresh
                </button>
            </div>
        </div>

        <div class="card mt-4">
            <div id="history-loading" class="overview-loading">
                <div class="spinner"></div>
                <span>Loading assessment records...</span>
            </div>

            <div class="table-responsive">
                <table class="data-table" id="history-table" style="display: none;">
                    <thead>
                        <tr>
                            <th>Firmware Target</th>
                            <th>Image Format</th>
                            <th>File Size</th>
                            <th>Risk Score</th>
                            <th>Findings Summary</th>
                            <th>Date (IST)</th>
                            <th class="text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody id="history-tbody">
                        <!-- Dynamic assessment rows -->
                    </tbody>
                </table>
            </div>

            <div id="history-empty" class="empty-state" style="display: none;">
                <p class="text-muted">No assessments match the selected filter criteria.</p>
            </div>
        </div>

        <!-- Deletion Confirmation Modal -->
        <div class="modal-backdrop" id="delete-modal" style="display: none;">
            <div class="modal-card">
                <h3 class="modal-title">Confirm Assessment Deletion</h3>
                <p class="text-sm text-muted mt-2" id="delete-modal-text">
                    Are you sure you want to delete this assessment? All associated findings and stored binary data will be permanently removed.
                </p>
                <div class="modal-actions mt-4 flex-between">
                    <button class="btn btn-secondary" id="btn-cancel-delete">Cancel</button>
                    <button class="btn btn-danger" id="btn-confirm-delete">Delete Assessment</button>
                </div>
            </div>
        </div>
    `;

    let activeFilterRisk = '';
    let pendingDeleteId = null;

    const tbody = container.querySelector('#history-tbody');
    const table = container.querySelector('#history-table');
    const emptyState = container.querySelector('#history-empty');
    const loadingState = container.querySelector('#history-loading');
    const filterSelect = container.querySelector('#history-filter-risk');
    const refreshBtn = container.querySelector('#btn-refresh-history');

    const deleteModal = container.querySelector('#delete-modal');
    const deleteText = container.querySelector('#delete-modal-text');
    const cancelDeleteBtn = container.querySelector('#btn-cancel-delete');
    const confirmDeleteBtn = container.querySelector('#btn-confirm-delete');

    const fetchHistory = async () => {
        loadingState.style.display = 'flex';
        table.style.display = 'none';
        emptyState.style.display = 'none';

        try {
            const data = await api.listAssessments({
                skip: 0,
                limit: 100,
                risk_rating: activeFilterRisk || undefined,
            });

            const assessments = data.assessments || [];
            loadingState.style.display = 'none';

            if (assessments.length === 0) {
                emptyState.style.display = 'block';
                return;
            }

            table.style.display = 'table';
            tbody.innerHTML = '';

            for (const item of assessments) {
                const tr = document.createElement('tr');
                const summ = item.findings_summary || {};

                tr.innerHTML = `
                    <td>
                        <div class="font-medium text-main">${escapeHtml(item.filename)}</div>
                        <div class="text-xs text-muted">ID: <code>${escapeHtml(item.id)}</code></div>
                    </td>
                    <td><code>${escapeHtml(item.image_type)}</code></td>
                    <td class="text-sm text-muted">${formatBytes(item.file_size_bytes)}</td>
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
                            ${!summ.total_unique ? `<span class="text-xs text-muted">Clean</span>` : ''}
                        </div>
                    </td>
                    <td class="text-sm text-muted">${formatDate(item.created_at)}</td>
                    <td class="text-right">
                        <div class="flex-center justify-end gap-2">
                            <button class="btn btn-secondary btn-sm btn-view-detail" data-id="${escapeHtml(item.id)}">
                                Inspect
                            </button>
                            <button class="btn btn-icon btn-icon-danger btn-delete-assessment" data-id="${escapeHtml(item.id)}" data-name="${escapeHtml(item.filename)}" title="Delete Assessment">
                                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <polyline points="3 6 5 6 21 6"/>
                                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                                </svg>
                            </button>
                        </div>
                    </td>
                `;

                tr.querySelector('.btn-view-detail').addEventListener('click', () => {
                    state.setRoute('detail', item.id);
                });

                tr.querySelector('.btn-delete-assessment').addEventListener('click', () => {
                    pendingDeleteId = item.id;
                    deleteText.textContent = `Are you sure you want to delete assessment for "${item.filename}" (${item.id})? All associated findings and binary records will be permanently removed.`;
                    deleteModal.style.display = 'flex';
                });

                tbody.appendChild(tr);
            }

        } catch (err) {
            loadingState.style.display = 'none';
            emptyState.innerHTML = `<div class="alert alert-danger">Failed to load history: ${escapeHtml(err.message)}</div>`;
            emptyState.style.display = 'block';
        }
    };

    filterSelect.addEventListener('change', (e) => {
        activeFilterRisk = e.target.value;
        fetchHistory();
    });

    refreshBtn.addEventListener('click', fetchHistory);

    // Modal cancellation & confirmation
    cancelDeleteBtn.addEventListener('click', () => {
        pendingDeleteId = null;
        deleteModal.style.display = 'none';
    });

    confirmDeleteBtn.addEventListener('click', async () => {
        if (!pendingDeleteId) return;
        confirmDeleteBtn.disabled = true;
        confirmDeleteBtn.textContent = 'Deleting...';

        try {
            await api.deleteAssessment(pendingDeleteId);
            deleteModal.style.display = 'none';
            state.setNotification('success', 'Assessment deleted successfully');
            fetchHistory();
        } catch (err) {
            state.setNotification('error', `Failed to delete: ${err.message}`);
        } finally {
            confirmDeleteBtn.disabled = false;
            confirmDeleteBtn.textContent = 'Delete Assessment';
            pendingDeleteId = null;
        }
    });

    fetchHistory();
}
