/**
 * Sentinel-X Firmware Analysis Component
 * Drag-and-drop file upload, validation, scanning progress, and instant results.
 */

import { api } from '../api.js';
import { state, formatBytes, escapeHtml } from '../state.js';

export function renderAnalyze(container) {
    container.innerHTML = `
        <div class="view-header">
            <div>
                <h1 class="view-title">Firmware Security Analysis</h1>
                <p class="view-subtitle">Upload ESP32 application binaries, bootloaders, or flash dumps for offline security assessment.</p>
            </div>
        </div>

        <div class="grid grid-2-col gap-6">
            <!-- Upload Panel -->
            <div class="card">
                <h2 class="card-title">Artifact Ingestion</h2>
                <p class="text-sm text-muted mb-4">Supported targets: ESP32 / S2 / S3 / C3 / C6 / H2 binaries up to 32 MB.</p>

                <div class="drop-zone" id="drop-zone">
                    <input type="file" id="file-input" class="file-input-hidden" accept=".bin,.img,.dump,.raw" />
                    <div class="drop-zone-content" id="drop-zone-prompt">
                        <svg class="drop-icon" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                            <polyline points="17 8 12 3 7 8"/>
                            <line x1="12" y1="3" x2="12" y2="15"/>
                        </svg>
                        <p class="drop-title">Drag & drop firmware binary here</p>
                        <p class="drop-sub">or <span class="link-span">browse local files</span></p>
                    </div>

                    <div class="file-selected-box" id="file-selected-box" style="display: none;">
                        <div class="flex-between">
                            <div class="flex-center">
                                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                                    <polyline points="14 2 14 8 20 8"/>
                                </svg>
                                <div class="ml-3">
                                    <div class="font-medium text-main" id="selected-filename">filename.bin</div>
                                    <div class="text-xs text-muted" id="selected-filesize">0 KB</div>
                                </div>
                            </div>
                            <button type="button" class="btn btn-icon" id="btn-remove-file" title="Remove file">&times;</button>
                        </div>
                    </div>
                </div>

                <div id="upload-error" class="alert alert-danger mt-3" style="display: none;"></div>

                <div class="mt-4 flex-between">
                    <span class="text-xs text-muted">100% Offline Static Scan &bull; Zero Cloud Leakage</span>
                    <button class="btn btn-primary" id="btn-submit-scan" disabled>
                        Start Security Assessment
                    </button>
                </div>
            </div>

            <!-- Analysis Guidance & Scope Panel -->
            <div class="card">
                <h2 class="card-title">Assessment Capabilities</h2>
                <div class="guidance-list">
                    <div class="guidance-item">
                        <div class="guidance-icon check-icon">&check;</div>
                        <div>
                            <strong>ESP32 Header & Partition Validation:</strong>
                            <p class="text-xs text-muted">Parses 0xE9 magic byte, flash memory mapping, entry points, and OTA partition slots.</p>
                        </div>
                    </div>
                    <div class="guidance-item">
                        <div class="guidance-icon check-icon">&check;</div>
                        <div>
                            <strong>Hardcoded Secret & Key Extraction:</strong>
                            <p class="text-xs text-muted">Scans ASCII/Unicode strings and raw binary for PEM private keys, AWS/cloud credentials, and Wi-Fi passphrases.</p>
                        </div>
                    </div>
                    <div class="guidance-item">
                        <div class="guidance-icon check-icon">&check;</div>
                        <div>
                            <strong>Deterministic Heuristic Scoring:</strong>
                            <p class="text-xs text-muted">Calculates an audited 0–100 risk score with dampening for repetitive string hits.</p>
                        </div>
                    </div>
                    <div class="guidance-item">
                        <div class="guidance-icon shield-icon">&bull;</div>
                        <div>
                            <strong>Defensive Non-Execution Guarantee:</strong>
                            <p class="text-xs text-muted">Firmware is analyzed strictly as static binary data. Sentinel-X never executes binary payloads.</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Scan Progress / Result Card -->
        <div id="scan-result-card" class="card mt-6" style="display: none;">
            <div class="flex-between">
                <div>
                    <h2 class="card-title" id="scan-result-title">Scan Completed Successfully</h2>
                    <p class="text-sm text-muted" id="scan-result-sub">Assessment record created in local SQLite database.</p>
                </div>
                <div id="scan-result-action"></div>
            </div>
            <div id="scan-result-summary" class="mt-4"></div>
        </div>
    `;

    // State variables
    let currentSelectedFile = null;

    const dropZone = container.querySelector('#drop-zone');
    const fileInput = container.querySelector('#file-input');
    const promptBox = container.querySelector('#drop-zone-prompt');
    const selectedBox = container.querySelector('#file-selected-box');
    const filenameEl = container.querySelector('#selected-filename');
    const filesizeEl = container.querySelector('#selected-filesize');
    const removeBtn = container.querySelector('#btn-remove-file');
    const submitBtn = container.querySelector('#btn-submit-scan');
    const errorEl = container.querySelector('#upload-error');
    const resultCard = container.querySelector('#scan-result-card');
    const resultSummary = container.querySelector('#scan-result-summary');
    const resultAction = container.querySelector('#scan-result-action');

    const showError = (msg) => {
        errorEl.textContent = msg;
        errorEl.style.display = 'block';
    };

    const clearError = () => {
        errorEl.textContent = '';
        errorEl.style.display = 'none';
    };

    const selectFile = (file) => {
        clearError();
        if (!file) return;

        // Size check (32 MB)
        const maxBytes = 32 * 1024 * 1024;
        if (file.size > maxBytes) {
            showError(`Selected file exceeds the 32 MB limit (${formatBytes(file.size)}).`);
            return;
        }

        if (file.size === 0) {
            showError('Selected file is empty (0 bytes).');
            return;
        }

        currentSelectedFile = file;
        filenameEl.textContent = file.name;
        filesizeEl.textContent = formatBytes(file.size);

        promptBox.style.display = 'none';
        selectedBox.style.display = 'block';
        submitBtn.disabled = false;
    };

    const resetFileSelection = () => {
        currentSelectedFile = null;
        fileInput.value = '';
        promptBox.style.display = 'block';
        selectedBox.style.display = 'none';
        submitBtn.disabled = true;
        clearError();
    };

    // Event listeners for file selection
    dropZone.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', (e) => {
        if (e.target.files && e.target.files[0]) {
            selectFile(e.target.files[0]);
        }
    });

    removeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        resetFileSelection();
    });

    // Drag-and-drop support
    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.add('drag-active');
        });
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.remove('drag-active');
        });
    });

    dropZone.addEventListener('drop', (e) => {
        if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
            selectFile(e.dataTransfer.files[0]);
        }
    });

    // Submit scanning
    submitBtn.addEventListener('click', async () => {
        if (!currentSelectedFile) return;

        clearError();
        submitBtn.disabled = true;
        submitBtn.innerHTML = `
            <span class="btn-spinner"></span>
            Analyzing Firmware...
        `;

        try {
            const result = await api.uploadAndAnalyze(currentSelectedFile);

            resultCard.style.display = 'block';
            resultSummary.innerHTML = `
                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-label">Detected Format</div>
                        <div class="metric-val text-sm"><code>${escapeHtml(result.image_type)}</code></div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-label">Risk Score</div>
                        <div class="metric-val">
                            <span class="risk-badge risk-${result.risk_rating.toLowerCase()}">
                                ${result.risk_score} &bull; ${escapeHtml(result.risk_rating)}
                            </span>
                        </div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-label">Unique Findings</div>
                        <div class="metric-val text-danger">${result.summary.total_unique}</div>
                    </div>
                </div>
            `;

            resultAction.innerHTML = `
                <button class="btn btn-primary" id="btn-goto-detail">
                    Inspect Full Assessment &rarr;
                </button>
            `;

            container.querySelector('#btn-goto-detail').addEventListener('click', () => {
                state.setRoute('detail', result.assessment_id);
            });

            resetFileSelection();
            state.setNotification('success', `Assessment completed for ${result.filename}`);

        } catch (err) {
            showError(`Analysis failed: ${err.message}`);
        } finally {
            submitBtn.disabled = false;
            submitBtn.innerHTML = 'Start Security Assessment';
        }
    });
}
