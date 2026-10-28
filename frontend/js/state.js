/**
 * Sentinel-X Global Application State
 * Centralized, observable state manager for navigation, selections, and alerts.
 */

class AppState {
    constructor() {
        this.state = {
            currentRoute: 'overview',
            selectedAssessmentId: null,
            assessments: [],
            totalAssessments: 0,
            devices: [],
            serialPorts: [],
            isLoading: false,
            notification: null, // { type: 'success' | 'error' | 'info', message: string }
        };
        this.listeners = new Set();
    }

    subscribe(listener) {
        this.listeners.add(listener);
        return () => this.listeners.delete(listener);
    }

    notify() {
        for (const listener of this.listeners) {
            listener(this.state);
        }
    }

    setRoute(route, assessmentId = null) {
        this.state.currentRoute = route;
        if (assessmentId) {
            this.state.selectedAssessmentId = assessmentId;
        }
        this.notify();
    }

    setLoading(loading) {
        this.state.isLoading = loading;
        this.notify();
    }

    setNotification(type, message, durationMs = 5000) {
        this.state.notification = { type, message };
        this.notify();
        if (durationMs > 0) {
            setTimeout(() => {
                if (this.state.notification && this.state.notification.message === message) {
                    this.state.notification = null;
                    this.notify();
                }
            }, durationMs);
        }
    }

    clearNotification() {
        this.state.notification = null;
        this.notify();
    }

    setAssessments(list, total) {
        this.state.assessments = list;
        this.state.totalAssessments = total !== undefined ? total : list.length;
        this.notify();
    }

    setSerialPorts(ports) {
        this.state.serialPorts = ports;
        this.notify();
    }

    setDevices(devices) {
        this.state.devices = devices;
        this.notify();
    }
}

export const state = new AppState();

// Utility Formatters
export function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    if (!bytes || isNaN(bytes)) return 'N/A';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export function formatDate(isoStr) {
    if (!isoStr) return 'N/A';
    try {
        const d = new Date(isoStr);
        return d.toLocaleDateString(undefined, {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
        });
    } catch {
        return isoStr;
    }
}

export function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
