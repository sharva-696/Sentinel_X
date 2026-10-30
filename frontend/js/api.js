/**
 * Sentinel-X Centralized API Client
 * Secure, modular client for all Sentinel-X backend REST endpoints.
 * Handles request timeouts, error normalization, and safe blob downloads.
 */

export class ApiClient {
    constructor(baseUrl = '') {
        // Use relative path by default to leverage same-origin FastAPI hosting
        this.baseUrl = baseUrl.replace(/\/+$/, '');
    }

    async _request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = { ...options.headers };

        // Auto-set JSON content-type if body is not FormData
        if (options.body && !(options.body instanceof FormData) && !headers['Content-Type']) {
            headers['Content-Type'] = 'application/json';
        }

        try {
            const response = await fetch(url, { ...options, headers });
            
            // Handle HTTP error responses
            if (!response.ok) {
                let errorDetail = `HTTP ${response.status} ${response.statusText}`;
                try {
                    const errorJson = await response.json();
                    if (errorJson && errorJson.detail) {
                        errorDetail = typeof errorJson.detail === 'string' 
                            ? errorJson.detail 
                            : JSON.stringify(errorJson.detail);
                    }
                } catch {
                    // Non-JSON error response
                }
                const error = new Error(errorDetail);
                error.status = response.status;
                throw error;
            }

            // Return JSON if present
            const contentType = response.headers.get('content-type') || '';
            if (contentType.includes('application/json')) {
                return await response.json();
            }
            return response;
        } catch (err) {
            if (err.name === 'TypeError' && err.message.includes('fetch')) {
                throw new Error('Unable to connect to Sentinel-X backend service. Please check if the server is running.');
            }
            throw err;
        }
    }

    // Health Check
    async getHealth() {
        return this._request('/api/health');
    }

    // Assessment Management
    async listAssessments({ skip = 0, limit = 50, status, risk_rating } = {}) {
        const params = new URLSearchParams({ skip, limit });
        if (status) params.append('status', status);
        if (risk_rating) params.append('risk_rating', risk_rating);
        return this._request(`/api/assessments?${params.toString()}`);
    }

    async getAssessment(id, { revealSecrets = false } = {}) {
        const query = revealSecrets ? '?reveal_secrets=true' : '';
        return this._request(`/api/assessments/${encodeURIComponent(id)}${query}`);
    }

    async getAssessmentFindings(id, { severity, category, revealSecrets = false } = {}) {
        const params = new URLSearchParams();
        if (severity) params.append('severity', severity);
        if (category) params.append('category', category);
        if (revealSecrets) params.append('reveal_secrets', 'true');
        const query = params.toString() ? `?${params.toString()}` : '';
        return this._request(`/api/assessments/${encodeURIComponent(id)}/findings${query}`);
    }

    async deleteAssessment(id) {
        return this._request(`/api/assessments/${encodeURIComponent(id)}`, {
            method: 'DELETE',
        });
    }

    // Firmware Analysis
    async uploadAndAnalyze(file) {
        const formData = new FormData();
        formData.append('file', file);
        return this._request('/api/firmware/analyze', {
            method: 'POST',
            body: formData,
        });
    }

    // Report Downloads
    async downloadReport(assessmentId, format = 'html') {
        const ext = format === 'pdf' ? 'pdf' : 'html';
        const endpoint = `/api/assessments/${encodeURIComponent(assessmentId)}/report/${ext}`;
        const url = `${this.baseUrl}${endpoint}`;

        const response = await fetch(url);
        if (!response.ok) {
            let errorMsg = `Failed to generate ${ext.toUpperCase()} report (HTTP ${response.status})`;
            try {
                const errJson = await response.json();
                if (errJson && errJson.detail) errorMsg = errJson.detail;
            } catch {
                // Ignore parse error
            }
            throw new Error(errorMsg);
        }

        const blob = await response.blob();
        const safeFilename = `Sentinel-X_Assessment_${assessmentId}.${ext}`;

        // Trigger safe browser download
        const downloadUrl = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = downloadUrl;
        link.download = safeFilename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(downloadUrl);
        return true;
    }

    // Device Interrogation & Acquisition
    async listSerialPorts() {
        return this._request('/api/devices/ports');
    }

    async identifyDevice(port, mock = false) {
        return this._request('/api/devices/identify', {
            method: 'POST',
            body: JSON.stringify({
                port,
                force_mock: mock,
                mock: mock,
                timeout_seconds: 15.0,
            }),
        });
    }

    async dumpDeviceFirmware({ port, baudrate = 460800, flash_size_bytes = 4194304, mock = false, device_id = null }) {
        return this._request('/api/devices/dump-firmware', {
            method: 'POST',
            body: JSON.stringify({
                port,
                baudrate,
                flash_size_bytes,
                force_mock: mock,
                mock: mock,
                device_id,
            }),
        });
    }

    async listDevices() {
        return this._request('/api/devices');
    }

    async getDevice(id) {
        return this._request(`/api/devices/${encodeURIComponent(id)}`);
    }

    async deleteDevice(id) {
        return this._request(`/api/devices/${encodeURIComponent(id)}`, {
            method: 'DELETE',
        });
    }
}

export const api = new ApiClient();
