/**
 * Sentinel-X Assessment Details & Findings Explorer Component
 * Renders deep technical metadata, findings explorer, score breakdown, and report exports.
 */

import { api } from '../api.js';
import { state, formatDate, formatBytes, escapeHtml } from '../state.js';

export async function renderDetail(container, assessmentId) {
    if (!assessmentId) {
        state.setRoute('history');
        return;
    }

    container.innerHTML = `
        <div class="view-header flex-between">
            <div class="flex-center gap-3">
                <button class="btn btn-secondary btn-sm" id="btn-back-history">&larr; Back to History</button>
                <div>
                    <h1 class="view-title" id="detail-filename">Loading Assessment...</h1>
                    <p class="view-subtitle" id="detail-id">ID: <code>${escapeHtml(assessmentId)}</code></p>
                </div>
            </div>
            <div class="flex-center gap-2" id="detail-export-actions">
                <button class="btn btn-secondary" id="btn-download-html" disabled>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                        <polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                    </svg>
                    Download HTML Report
                </button>
                <button class="btn btn-primary" id="btn-download-pdf" disabled>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                        <polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                    </svg>
                    Download PDF Report
                </button>
            </div>
        </div>

        <div id="detail-loading" class="overview-loading mt-6">
            <div class="spinner"></div>
            <span>Retrieving normalized assessment telemetries and findings...</span>
        </div>

        <div id="detail-content" style="display: none;">
            <!-- Executive Metrics Row -->
            <div class="metrics-grid mt-4">
                <div class="metric-card">
                    <div class="metric-label">Composite Risk Score</div>
                    <div class="metric-val" id="detail-score">0</div>
                    <div id="detail-score-band" class="mt-2"></div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Total Unique Findings</div>
                    <div class="metric-val" id="detail-findings-count">0</div>
                    <div class="metric-hint">Normalized &amp; Deduplicated</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Detected Format</div>
                    <div class="metric-val text-sm font-mono" id="detail-format">APP_BINARY</div>
                    <div class="metric-hint" id="detail-format-hint">ESP32 Firmware Image</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Target File Size</div>
                    <div class="metric-val text-sm" id="detail-filesize">0 KB</div>
                    <div class="metric-hint" id="detail-date">Uploaded Recently</div>
                </div>
            </div>

            <!-- Scope Callout Banner -->
            <div id="detail-scope-banner" class="mt-4"></div>

            <!-- Technical Metadata Grid -->
            <div class="card mt-4">
                <h2 class="card-title">Artifact Hashes &amp; Image Telemetry</h2>
                <div class="table-responsive">
                    <table class="data-table">
                        <tbody>
                            <tr>
                                <th style="width: 20%;">SHA-256 Hash</th>
                                <td><code id="meta-sha256" class="select-all">...</code></td>
                            </tr>
                            <tr>
                                <th>MD5 Hash</th>
                                <td><code id="meta-md5" class="select-all">...</code></td>
                            </tr>
                            <tr>
                                <th>Assessment Timestamp</th>
                                <td id="meta-timestamp">...</td>
                            </tr>
                            <tr id="row-device-meta" style="display: none;">
                                <th>Associated Device</th>
                                <td id="meta-device">Offline Assessment (No live serial board connected)</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                <div id="detail-partitions-box" class="mt-3" style="display: none;">
                    <h3 class="text-sm font-semibold mb-2">Partition Layout</h3>
                    <div class="table-responsive">
                        <table class="data-table text-xs">
                            <thead>
                                <tr><th>Label</th><th>Type</th><th>Subtype</th><th>Offset</th><th>Size</th></tr>
                            </thead>
                            <tbody id="detail-partitions-tbody"></tbody>
                        </table>
                    </div>
                </div>
            </div>

            <!-- Findings Explorer Section -->
            <div class="card mt-6">
                <div class="card-header flex-between flex-wrap gap-3">
                    <div>
                        <h2 class="card-title">Findings Explorer</h2>
                        <p class="text-xs text-muted">All findings represent potential indicators detected via static analysis.</p>
                    </div>
                    <div class="flex-center gap-2 flex-wrap">
                        <input type="text" class="form-input text-sm" id="findings-search-input" placeholder="Search findings, rules, offsets..." style="width: 220px;" />
                        <div class="filter-pill-group" id="severity-filter-pills">
                            <button class="filter-pill active" data-sev="">All</button>
                            <button class="filter-pill" data-sev="Critical">Critical</button>
                            <button class="filter-pill" data-sev="High">High</button>
                            <button class="filter-pill" data-sev="Medium">Medium</button>
                            <button class="filter-pill" data-sev="Low">Low</button>
                        </div>
                        <label class="faculty-demo-switch flex-center gap-2" title="Reveal raw passwords and credentials with red highlight for faculty demonstration">
                            <input type="checkbox" id="faculty-demo-toggle" style="accent-color: #ef4444; width: 15px; height: 15px; cursor: pointer;" />
                            <span class="text-xs font-bold text-danger flex-center gap-1">
                                🛡️ Faculty Demo Mode <span class="badge-red-pulse">LIVE</span>
                            </span>
                        </label>
                    </div>
                </div>

                <div id="findings-container" class="mt-4">
                    <!-- Populated dynamically -->
                </div>

                <div id="findings-empty" class="empty-state" style="display: none;">
                    <p class="text-muted">No findings match the current filter criteria.</p>
                </div>
            </div>

            <!-- Risk Score Explanation & Breakdown -->
            <div class="card mt-6">
                <h2 class="card-title">Risk Scoring Breakdown &amp; Heuristic Formula</h2>
                <div class="formula-box text-xs">
                    Finding Points = Base Weight(Severity) &times; Confidence Multiplier &times; (1.0 + 0.2 &times; min(N - 1, 5))<br>
                    Composite Risk Score = min(100, round(&sum; Finding Points))
                </div>
                <div class="table-responsive mt-3">
                    <table class="data-table" id="breakdown-table">
                        <thead>
                            <tr>
                                <th>Rule ID</th>
                                <th>Indicator Title</th>
                                <th>Severity</th>
                                <th>Confidence</th>
                                <th>Occurrences (N)</th>
                                <th>Dampening Multiplier</th>
                                <th>Points</th>
                            </tr>
                        </thead>
                        <tbody id="breakdown-tbody"></tbody>
                    </table>
                </div>
                <p class="text-xs text-muted mt-2">
                    <em>The Sentinel-X Risk Score is an explainable heuristic metric reflecting static security indicators. A score of 0 does not certify that the device is free of vulnerabilities.</em>
                </p>
            </div>
        </div>
    `;

    container.querySelector('#btn-back-history').addEventListener('click', () => {
        state.setRoute('history');
    });

    try {
        const assessment = await api.getAssessment(assessmentId);
        const findings = assessment.findings || [];
        const breakdown = assessment.score_breakdown || {};
        const breakdownItems = breakdown.finding_breakdown || breakdown.rule_breakdown || [];

        // Enable report download buttons
        const htmlBtn = container.querySelector('#btn-download-html');
        const pdfBtn = container.querySelector('#btn-download-pdf');
        htmlBtn.disabled = false;
        pdfBtn.disabled = false;

        htmlBtn.addEventListener('click', async () => {
            htmlBtn.disabled = true;
            htmlBtn.textContent = 'Downloading...';
            try {
                await api.downloadReport(assessmentId, 'html');
            } catch (err) {
                state.setNotification('error', `HTML download failed: ${err.message}`);
            } finally {
                htmlBtn.disabled = false;
                htmlBtn.textContent = 'Download HTML Report';
            }
        });

        pdfBtn.addEventListener('click', async () => {
            pdfBtn.disabled = true;
            pdfBtn.textContent = 'Downloading...';
            try {
                await api.downloadReport(assessmentId, 'pdf');
            } catch (err) {
                state.setNotification('error', `PDF download failed: ${err.message}`);
            } finally {
                pdfBtn.disabled = false;
                pdfBtn.textContent = 'Download PDF Report';
            }
        });

        // Populate Header & Metrics
        container.querySelector('#detail-filename').textContent = assessment.filename;
        container.querySelector('#detail-score').textContent = assessment.risk_score;
        container.querySelector('#detail-score-band').innerHTML = `
            <span class="risk-badge risk-${assessment.risk_rating.toLowerCase()}">
                ${escapeHtml(assessment.risk_rating)} Rating
            </span>
        `;
        container.querySelector('#detail-findings-count').textContent = findings.length;
        container.querySelector('#detail-format').textContent = assessment.image_type;
        container.querySelector('#detail-filesize').textContent = formatBytes(assessment.file_size_bytes);
        container.querySelector('#detail-date').textContent = formatDate(assessment.created_at);

        // Scope Advisory Banner
        const scopeBanner = container.querySelector('#detail-scope-banner');
        if (assessment.device_id) {
            scopeBanner.innerHTML = `
                <div class="alert alert-info">
                    <strong>Hardware-Associated Assessment:</strong> This assessment is linked to ESP32 device record #${assessment.device_id}.
                </div>
            `;
        } else {
            scopeBanner.innerHTML = `
                <div class="alert alert-info">
                    <strong>Offline Firmware Analysis Scope:</strong> This assessment was executed strictly on an offline binary artifact. 
                    No physical ESP32 development board was connected or interrogated over serial. Physical eFuses and runtime encryption keys cannot be determined without physical connection.
                </div>
            `;
        }

        // Hashes & Meta
        container.querySelector('#meta-sha256').textContent = assessment.sha256;
        container.querySelector('#meta-md5').textContent = assessment.md5;
        container.querySelector('#meta-timestamp').textContent = `${formatDate(assessment.created_at)} (IST)`;

        // Partitions
        if (assessment.image_metadata && assessment.image_metadata.partitions && assessment.image_metadata.partitions.length > 0) {
            const partBox = container.querySelector('#detail-partitions-box');
            const partTbody = container.querySelector('#detail-partitions-tbody');
            partBox.style.display = 'block';
            partTbody.innerHTML = assessment.image_metadata.partitions.map(p => {
                const offsetHex = typeof p.offset === 'string' && p.offset.startsWith('0x') 
                    ? p.offset 
                    : `0x${Number(p.offset || p.offset_dec || 0).toString(16).padStart(6, '0')}`;
                const sizeVal = p.size_bytes ?? p.size_dec ?? (typeof p.size === 'string' && p.size.startsWith('0x') ? parseInt(p.size, 16) : Number(p.size || 0));
                const sizeKb = !isNaN(sizeVal) && sizeVal > 0 ? `${Math.round(sizeVal / 1024)} KB` : '0 KB';
                const labelStr = p.label ? String(p.label).replace(/[^\x20-\x7E]/g, '?') : 'unnamed';
                return `
                    <tr>
                        <td><code>${escapeHtml(labelStr)}</code></td>
                        <td>${escapeHtml(p.type || 'N/A')}</td>
                        <td>${escapeHtml(p.subtype || 'N/A')}</td>
                        <td><code>${escapeHtml(offsetHex)}</code></td>
                        <td>${escapeHtml(sizeKb)}</td>
                    </tr>
                `;
            }).join('');
        }

        // Findings Rendering & Filtering Logic
        let currentSeverityFilter = '';
        let currentSearchQuery = '';
        let demoModeActive = false;
        const manuallyToggled = new Set();

        const findingsContainer = container.querySelector('#findings-container');
        const findingsEmpty = container.querySelector('#findings-empty');

        function renderEvidenceSnippet(f, isRevealed) {
            const masked = (f.evidence && f.evidence.snippet_masked) || f.evidence_masked || '[REDACTED]';
            const raw = (f.evidence && f.evidence.snippet_raw) || f.evidence_raw;
            const token = (f.evidence && f.evidence.secret_token) || f.secret_token;

            if (isRevealed && raw) {
                if (token && raw.includes(token)) {
                    const idx = raw.indexOf(token);
                    const before = escapeHtml(raw.substring(0, idx));
                    const highToken = `<span class="secret-leak-badge">${escapeHtml(token)}</span>`;
                    const after = escapeHtml(raw.substring(idx + token.length));
                    return {
                        html: `${before}${highToken}${after}`,
                        label: 'Extracted Secret Context (Live Demonstration):',
                        revealed: true,
                    };
                } else {
                    return {
                        html: `<span class="secret-leak-badge">${escapeHtml(raw)}</span>`,
                        label: 'Extracted Secret Context (Live Demonstration):',
                        revealed: true,
                    };
                }
            } else {
                return {
                    html: escapeHtml(masked),
                    label: 'Sanitized Evidence Context (Report Format):',
                    revealed: false,
                };
            }
        }

        const renderFindingsList = () => {
            const filtered = findings.filter(f => {
                const matchSev = !currentSeverityFilter || (f.severity.toLowerCase() === currentSeverityFilter.toLowerCase());
                const query = currentSearchQuery.toLowerCase();
                const matchSearch = !query || 
                    f.title.toLowerCase().includes(query) || 
                    f.rule_id.toLowerCase().includes(query) || 
                    f.category.toLowerCase().includes(query) || 
                    (f.byte_offset && f.byte_offset.toLowerCase().includes(query));
                return matchSev && matchSearch;
            });

            if (filtered.length === 0) {
                findingsContainer.innerHTML = '';
                findingsEmpty.style.display = 'block';
                return;
            }

            findingsEmpty.style.display = 'none';
            findingsContainer.innerHTML = '';

            filtered.forEach((f, idx) => {
                const card = document.createElement('div');
                card.className = 'finding-card';

                const addOffsets = (f.evidence && f.evidence.additional_offsets) || f.additional_offsets || [];
                const addOffsetsHtml = addOffsets.length > 0 
                    ? `<div class="mt-2 text-xs"><strong>Additional Offsets (${addOffsets.length}):</strong> ${addOffsets.map(o => `<code>${escapeHtml(o)}</code>`).join(', ')}</div>` 
                    : '';

                // Header
                const header = document.createElement('div');
                header.className = 'finding-header flex-between';
                header.innerHTML = `
                    <div>
                        <span class="finding-num">#${idx + 1}</span>
                        <h3 class="finding-title">${escapeHtml(f.title)}</h3>
                        <span class="finding-rule">[${escapeHtml(f.rule_id)}]</span>
                    </div>
                    <span class="pill pill-${f.severity.toLowerCase()} font-bold">${escapeHtml(f.severity)}</span>
                `;
                card.appendChild(header);

                // Meta Bar
                const metaBar = document.createElement('div');
                metaBar.className = 'finding-meta-bar mt-2';
                metaBar.innerHTML = `
                    <span><strong>Category:</strong> ${escapeHtml(f.category)}</span>
                    <span><strong>Confidence:</strong> ${escapeHtml(f.confidence)}</span>
                    <span><strong>Primary Offset:</strong> <code>${escapeHtml(f.byte_offset || 'N/A')}</code></span>
                    <span><strong>Status:</strong> <em class="text-warning">Potential Indicator</em></span>
                `;
                card.appendChild(metaBar);

                if (addOffsetsHtml) {
                    const offsetDiv = document.createElement('div');
                    offsetDiv.innerHTML = addOffsetsHtml;
                    card.appendChild(offsetDiv);
                }

                // Evidence Snippet with Live Demo Reveal & Red Highlight
                const evidenceBox = document.createElement('div');
                evidenceBox.className = 'evidence-box mt-3';

                const isRevealed = demoModeActive ? !manuallyToggled.has(f.id) : manuallyToggled.has(f.id);
                const snippetData = renderEvidenceSnippet(f, isRevealed);
                const hasRawData = Boolean((f.evidence && f.evidence.snippet_raw) || f.evidence_raw);

                const headerRow = document.createElement('div');
                headerRow.className = 'flex-between mb-2 flex-wrap gap-2';

                const evidenceLabel = document.createElement('div');
                evidenceLabel.className = 'evidence-label';
                evidenceLabel.textContent = snippetData.label;
                headerRow.appendChild(evidenceLabel);

                if (hasRawData || demoModeActive) {
                    const toggleBtn = document.createElement('button');
                    toggleBtn.className = isRevealed ? 'btn btn-xs btn-outline-secondary' : 'btn btn-xs btn-outline-danger';
                    toggleBtn.innerHTML = isRevealed ? '🙈 Mask' : '👁️ Reveal';
                    toggleBtn.title = isRevealed ? 'Mask secret token' : 'Reveal raw secret with red highlight';
                    toggleBtn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        if (manuallyToggled.has(f.id)) {
                            manuallyToggled.delete(f.id);
                        } else {
                            manuallyToggled.add(f.id);
                        }
                        renderFindingsList();
                    });
                    headerRow.appendChild(toggleBtn);
                }

                const pre = document.createElement('pre');
                pre.className = 'evidence-code';
                pre.innerHTML = snippetData.html;

                evidenceBox.appendChild(headerRow);
                evidenceBox.appendChild(pre);
                card.appendChild(evidenceBox);

                // Details collapsible / block
                const detailsBox = document.createElement('div');
                detailsBox.className = 'finding-details-list mt-3 text-sm';
                if (f.rationale) {
                    detailsBox.innerHTML += `<div class="f-detail-row"><strong>Security Rationale:</strong> ${escapeHtml(f.rationale)}</div>`;
                }
                if (f.false_positive_cases) {
                    detailsBox.innerHTML += `<div class="f-detail-row"><strong>False Positive Scenarios:</strong> ${escapeHtml(f.false_positive_cases)}</div>`;
                }
                if (f.remediation) {
                    detailsBox.innerHTML += `<div class="f-detail-row text-success"><strong>Remediation:</strong> ${escapeHtml(f.remediation)}</div>`;
                }
                if (f.verification_limitations) {
                    detailsBox.innerHTML += `<div class="f-detail-row text-muted"><strong>Limitations:</strong> ${escapeHtml(f.verification_limitations)}</div>`;
                }
                card.appendChild(detailsBox);

                findingsContainer.appendChild(card);
            });
        };

        // Faculty Demo Mode toggle listener
        const demoToggle = container.querySelector('#faculty-demo-toggle');
        if (demoToggle) {
            demoToggle.addEventListener('change', async (e) => {
                demoModeActive = e.target.checked;
                manuallyToggled.clear();

                // If demo mode turned ON and we don't have snippet_raw yet, fetch from backend with reveal_secrets=true
                const needsFetch = demoModeActive && findings.some(f => !((f.evidence && f.evidence.snippet_raw) || f.evidence_raw));
                if (needsFetch) {
                    try {
                        const fresh = await api.getAssessment(assessmentId, { revealSecrets: true });
                        if (fresh && fresh.findings) {
                            findings.length = 0;
                            findings.push(...fresh.findings);
                        }
                    } catch (err) {
                        console.error('Failed to load raw credentials for demo mode:', err);
                    }
                }
                renderFindingsList();
            });
        }

        // Filter pills event listeners
        container.querySelectorAll('.filter-pill').forEach(pill => {
            pill.addEventListener('click', () => {
                container.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
                pill.classList.add('active');
                currentSeverityFilter = pill.dataset.sev;
                renderFindingsList();
            });
        });

        // Search input event listener
        container.querySelector('#findings-search-input').addEventListener('input', (e) => {
            currentSearchQuery = e.target.value.trim();
            renderFindingsList();
        });

        renderFindingsList();

        // Render Score Breakdown
        const breakdownTbody = container.querySelector('#breakdown-tbody');
        if (breakdownItems.length === 0) {
            breakdownTbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">Zero score points attributed; clean scan.</td></tr>`;
        } else {
            breakdownTbody.innerHTML = breakdownItems.map(item => `
                <tr>
                    <td><code>${escapeHtml(item.rule_id)}</code></td>
                    <td>${escapeHtml(item.title)}</td>
                    <td><span class="pill pill-${(item.severity || 'low').toLowerCase()}">${escapeHtml(item.severity)}</span></td>
                    <td>${escapeHtml(item.confidence)} (${item.confidence_factor || 0.8})</td>
                    <td>${item.occurrences || 1}</td>
                    <td>${item.multiplier || 1.0}x</td>
                    <td><strong>${item.calculated_points || 0.0} pts</strong></td>
                </tr>
            `).join('');
        }

        container.querySelector('#detail-loading').style.display = 'none';
        container.querySelector('#detail-content').style.display = 'block';

    } catch (err) {
        container.querySelector('#detail-loading').innerHTML = `
            <div class="alert alert-danger">
                <strong>Failed to load assessment details:</strong> ${escapeHtml(err.message)}
            </div>
        `;
    }
}
