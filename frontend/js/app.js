/**
 * Sentinel-X Frontend Application Router & Bootstrap
 * Orchestrates client-side routing, route dispatching, and notification toasts.
 */

import { state, escapeHtml } from './state.js';
import { initNav } from './components/nav.js';
import { renderOverview } from './components/overview.js';
import { renderAnalyze } from './components/analyze.js';
import { renderHistory } from './components/history.js';
import { renderDetail } from './components/detail.js';
import { renderDevices } from './components/devices.js';

document.addEventListener('DOMContentLoaded', () => {
    const navContainer = document.getElementById('sidebar-container');
    const mainContent = document.getElementById('main-content');
    const toastContainer = document.getElementById('toast-container');

    // 1. Initialize Navigation
    initNav(navContainer);

    let currentRenderedKey = null;

    // 2. Route Dispatcher
    const dispatchRoute = () => {
        const route = state.state.currentRoute;
        const selectedId = state.state.selectedAssessmentId;
        const targetKey = `${route}:${selectedId || ''}`;

        if (targetKey === currentRenderedKey) {
            return;
        }
        currentRenderedKey = targetKey;

        // Clean current view container
        mainContent.innerHTML = '';
        window.scrollTo({ top: 0, behavior: 'instant' });

        const targetHash = route === 'detail' && selectedId ? `#detail/${selectedId}` : `#${route}`;
        if (window.location.hash !== targetHash) {
            history.replaceState(null, '', targetHash);
        }

        switch (route) {
            case 'overview':
                renderOverview(mainContent);
                break;
            case 'analyze':
                renderAnalyze(mainContent);
                break;
            case 'history':
                renderHistory(mainContent);
                break;
            case 'detail':
                renderDetail(mainContent, selectedId);
                break;
            case 'devices':
                renderDevices(mainContent);
                break;
            default:
                renderOverview(mainContent);
        }
    };

    // 3. Hash Change Listener for Browser History Navigation
    const handleHashChange = () => {
        const hash = window.location.hash.replace(/^#/, '');
        if (!hash) {
            state.setRoute('overview');
            return;
        }

        if (hash.startsWith('detail/')) {
            const id = hash.replace('detail/', '');
            state.setRoute('detail', id);
        } else if (['overview', 'analyze', 'history', 'devices'].includes(hash)) {
            state.setRoute(hash);
        } else {
            state.setRoute('overview');
        }
    };

    window.addEventListener('hashchange', handleHashChange);

    // 4. Notification Toast Renderer
    state.subscribe(s => {
        if (!toastContainer) return;
        if (!s.notification) {
            toastContainer.innerHTML = '';
            toastContainer.style.display = 'none';
            return;
        }

        const { type, message } = s.notification;
        const alertClass = type === 'success' ? 'alert-success' : type === 'error' ? 'alert-danger' : 'alert-info';

        toastContainer.innerHTML = `
            <div class="toast-item alert ${alertClass}">
                <span>${escapeHtml(message)}</span>
                <button type="button" class="btn-close-toast" id="btn-close-toast">&times;</button>
            </div>
        `;
        toastContainer.style.display = 'block';

        toastContainer.querySelector('#btn-close-toast')?.addEventListener('click', () => {
            state.clearNotification();
        });
    });

    // 5. Initial boot
    handleHashChange();
    dispatchRoute();
    state.subscribe(() => dispatchRoute());
});
