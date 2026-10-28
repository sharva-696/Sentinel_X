/**
 * Sentinel-X Navigation Component
 * Responsive sidebar, branding, route links, and health badge.
 */

import { state } from '../state.js';
import { api } from '../api.js';

export function initNav(container) {
    const navHtml = `
        <div class="sidebar-brand">
            <div class="brand-icon">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <circle cx="12" cy="11" r="3"/>
                </svg>
            </div>
            <div class="brand-text">
                <span class="brand-title">Sentinel-X</span>
                <span class="brand-subtitle">ESP32 Security Suite</span>
            </div>
        </div>

        <nav class="sidebar-menu" role="navigation" aria-label="Main Navigation">
            <button class="nav-item active" data-route="overview">
                <svg class="nav-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/>
                    <rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/>
                </svg>
                <span>Overview</span>
            </button>

            <button class="nav-item" data-route="analyze">
                <svg class="nav-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                    <polyline points="17 8 12 3 7 8"/>
                    <line x1="12" y1="3" x2="12" y2="15"/>
                </svg>
                <span>Analyze Firmware</span>
            </button>

            <button class="nav-item" data-route="history">
                <svg class="nav-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"/>
                    <polyline points="12 6 12 12 16 14"/>
                </svg>
                <span>Assessment History</span>
            </button>

            <button class="nav-item" data-route="devices">
                <svg class="nav-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>
                    <rect x="2" y="14" width="20" height="8" rx="2" ry="2"/>
                    <line x1="6" y1="6" x2="6.01" y2="6"/>
                    <line x1="6" y1="18" x2="6.01" y2="18"/>
                </svg>
                <span>Hardware & Devices</span>
            </button>
        </nav>

        <div class="sidebar-footer">
            <div class="system-status" id="system-health-badge">
                <span class="status-dot"></span>
                <span class="status-text">Connecting...</span>
            </div>
            <div class="version-label">v1.0.0 &bull; Local Engine</div>
        </div>
    `;

    container.innerHTML = navHtml;

    // Attach click handlers to nav buttons
    container.querySelectorAll('.nav-item').forEach(btn => {
        btn.addEventListener('click', () => {
            const route = btn.dataset.route;
            state.setRoute(route);
        });
    });

    // Check backend health periodically
    const checkHealth = async () => {
        const badge = document.getElementById('system-health-badge');
        if (!badge) return;
        try {
            const health = await api.getHealth();
            if (health.status === 'OK') {
                badge.className = 'system-status status-healthy';
                badge.querySelector('.status-text').textContent = 'Backend Online';
            } else {
                badge.className = 'system-status status-warning';
                badge.querySelector('.status-text').textContent = 'Backend Degraded';
            }
        } catch {
            badge.className = 'system-status status-error';
            badge.querySelector('.status-text').textContent = 'Backend Offline';
        }
    };

    checkHealth();
    setInterval(checkHealth, 30000);

    // Update active state when route changes
    state.subscribe(s => {
        container.querySelectorAll('.nav-item').forEach(btn => {
            const route = btn.dataset.route;
            const isActive = (s.currentRoute === route) || (s.currentRoute === 'detail' && route === 'history');
            btn.classList.toggle('active', isActive);
        });
    });
}
