/**
 * Sentinel-X ESP32 Hardware & Serial Device Discovery Component
 * Discovers host serial ports, runs safe non-destructive chip identification,
 * and maintains history of interrogated hardware boards.
 */

import { api } from '../api.js';
import { state, formatDate, escapeHtml } from '../state.js';

export async function renderDevices(container) {
    container.innerHTML = `
        <div class="view-header flex-between">
            <div>
                <h1 class="view-title">ESP32 Hardware Discovery &amp; Identification</h1>
                <p class="view-subtitle">Non-destructive serial discovery and chip interrogation via esptool.</p>
            </div>
            <button class="btn btn-secondary" id="btn-scan-ports">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                </svg>
                Scan Serial Ports
            </button>
        </div>

        <!-- Port Selection & Interrogation Panel -->
        <div class="card mt-4">
            <h2 class="card-title">Available Serial Ports</h2>
            <p class="text-sm text-muted mb-3">
                Select a connected USB-to-UART bridge (CP210x, CH340, FTDI, or native ESP32-USB).
            </p>

            <div id="ports-loading" class="overview-loading" style="display: none;">
                <div class="spinner"></div>
                <span>Scanning host system serial ports...</span>
            </div>

            <div class="table-responsive" id="ports-table-wrapper">
                <table class="data-table" id="ports-table">
                    <thead>
                        <tr>
                            <th style="width: 50px;">Select</th>
                            <th>Port Device</th>
                            <th>Description</th>
                            <th>Hardware VID:PID</th>
                            <th>OS Permissions</th>
                        </tr>
                    </thead>
                    <tbody id="ports-tbody">
                        <!-- Populated dynamically -->
                    </tbody>
                </table>
            </div>

            <div id="ports-empty" class="empty-state" style="display: none;">
                <p class="text-muted">No USB serial devices detected. Ensure your ESP32 board is connected via a data-capable USB cable.</p>
            </div>

            <!-- Interrogation Trigger Controls -->
            <div class="alert alert-info mt-3 text-xs">
                <strong>Connection Tip:</strong> If your board fails to synchronize with esptool (common on boards with CH340 USB bridges), press and hold the <strong>BOOT</strong> (or <strong>IO0</strong>) button on your board while clicking <em>Identify</em> or <em>Dump &amp; Analyze</em>.
            </div>

            <div class="mt-4 pt-4 border-top flex-between flex-wrap gap-3">
                <div class="flex-center gap-3">
                    <label class="checkbox-label text-sm">
                        <input type="checkbox" id="check-mock-mode" />
                        <span>Emulation / Mock Mode (Test without physical hardware)</span>
                    </label>
                </div>
                <div class="flex-center gap-2">
                    <button class="btn btn-secondary" id="btn-identify-device" disabled>
                        Identify Selected ESP32
                    </button>
                    <button class="btn btn-primary" id="btn-dump-device" disabled>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                            <polyline points="7 10 12 15 17 10"/>
                            <line x1="12" y1="15" x2="12" y2="3"/>
                        </svg>
                        Dump &amp; Analyze Firmware
                    </button>
                </div>
            </div>

            <div id="identify-status" class="mt-3" style="display: none;"></div>
        </div>

        <!-- Interrogated Device Telemetry Card (Shown after successful interrogation) -->
        <div id="identified-device-card" class="card mt-6" style="display: none;">
            <div class="flex-between">
                <div>
                    <span class="pill pill-success text-xs font-bold">Hardware Verified</span>
                    <h2 class="card-title mt-1" id="id-chip-model">ESP32-D0WD-V3</h2>
                    <p class="text-sm text-muted" id="id-port-label">Connected on /dev/ttyUSB0</p>
                </div>
                <div class="text-right">
                    <div class="text-xs text-muted">MAC Address</div>
                    <code class="font-bold text-sm" id="id-mac-address">24:0a:c4:00:00:00</code>
                </div>
            </div>

            <div class="metrics-grid mt-4">
                <div class="metric-card">
                    <div class="metric-label">Flash Memory Size</div>
                    <div class="metric-val text-sm font-mono" id="id-flash-size">4 MB</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Crystal Frequency</div>
                    <div class="metric-val text-sm font-mono" id="id-crystal-freq">40 MHz</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">Flash Vendor ID</div>
                    <div class="metric-val text-sm font-mono" id="id-flash-params">0x68</div>
                </div>
                <div class="metric-card">
                    <div class="metric-label">SDK Version</div>
                    <div class="metric-val text-sm font-mono" id="id-sdk-ver">v5.1</div>
                </div>
            </div>

            <div class="alert alert-info mt-4 text-xs">
                <strong>Non-Destructive Guarantee:</strong> Sentinel-X identified this microcontroller using safe, read-only esptool operations (chip-id, read-mac, flash-id). No flash modifications, write operations, or eFuse burning were performed.
            </div>
        </div>

        <!-- Previously Recorded Devices -->
        <div class="card mt-6">
            <h2 class="card-title">Interrogated Hardware Registry</h2>
            <div class="table-responsive mt-3">
                <table class="data-table" id="devices-history-table">
                    <thead>
                        <tr>
                            <th>Device ID</th>
                            <th>Chip Model &amp; Revision</th>
                            <th>Port</th>
                            <th>MAC Address</th>
                            <th>Flash (Size &amp; Vendor)</th>
                            <th>Crystal</th>
                            <th>First Registered (IST)</th>
                            <th class="text-right">Action</th>
                        </tr>
                    </thead>
                    <tbody id="devices-history-tbody">
                        <!-- Populated dynamically -->
                    </tbody>
                </table>
            </div>
            <div id="devices-history-empty" class="empty-state" style="display: none;">
                <p class="text-muted">No previously interrogated hardware registered in database.</p>
            </div>
        </div>
    `;

    let selectedPortPath = null;

    const portsTbody = container.querySelector('#ports-tbody');
    const portsTableWrapper = container.querySelector('#ports-table-wrapper');
    const portsEmpty = container.querySelector('#ports-empty');
    const portsLoading = container.querySelector('#ports-loading');
    const scanPortsBtn = container.querySelector('#btn-scan-ports');
    const identifyBtn = container.querySelector('#btn-identify-device');
    const dumpBtn = container.querySelector('#btn-dump-device');
    const mockCheck = container.querySelector('#check-mock-mode');
    const identifyStatus = container.querySelector('#identify-status');

    const identifiedCard = container.querySelector('#identified-device-card');
    const idChipModel = container.querySelector('#id-chip-model');
    const idPortLabel = container.querySelector('#id-port-label');
    const idMac = container.querySelector('#id-mac-address');
    const idFlashSize = container.querySelector('#id-flash-size');
    const idCrystal = container.querySelector('#id-crystal-freq');
    const idFlashParams = container.querySelector('#id-flash-params');
    const idSdk = container.querySelector('#id-sdk-ver');

    const devicesTbody = container.querySelector('#devices-history-tbody');
    const devicesEmpty = container.querySelector('#devices-history-empty');
    const devicesTable = container.querySelector('#devices-history-table');

    // 1. Scan Ports
    const scanPorts = async () => {
        portsLoading.style.display = 'flex';
        portsTableWrapper.style.display = 'none';
        portsEmpty.style.display = 'none';
        selectedPortPath = null;
        identifyBtn.disabled = true;
        if (dumpBtn) dumpBtn.disabled = true;

        try {
            const data = await api.listSerialPorts();
            const ports = data.ports || [];
            portsLoading.style.display = 'none';

            if (ports.length === 0) {
                portsEmpty.style.display = 'block';
                return;
            }

            portsTableWrapper.style.display = 'block';
            portsTbody.innerHTML = '';

            ports.forEach((p, idx) => {
                const tr = document.createElement('tr');
                const isAccessible = p.accessible !== false;

                tr.innerHTML = `
                    <td class="text-center">
                        <input type="radio" name="port-radio" class="port-radio-input" value="${escapeHtml(p.device)}" id="port-radio-${idx}" />
                    </td>
                    <td>
                        <label for="port-radio-${idx}" class="font-mono font-medium cursor-pointer">
                            ${escapeHtml(p.device)}
                        </label>
                    </td>
                    <td class="text-sm">${escapeHtml(p.description || 'USB Serial Device')}</td>
                    <td class="text-xs font-mono text-muted">
                        ${p.vid && p.pid ? `${escapeHtml(p.vid)}:${escapeHtml(p.pid)}` : 'N/A'}
                    </td>
                    <td>
                        ${isAccessible 
                            ? `<span class="pill pill-success text-xs">Read/Write Access</span>` 
                            : `<span class="pill pill-danger text-xs">Permission Denied</span>`}
                    </td>
                `;

                tr.querySelector('.port-radio-input').addEventListener('change', (e) => {
                    selectedPortPath = e.target.value;
                    identifyBtn.disabled = false;
                    if (dumpBtn) dumpBtn.disabled = false;
                });

                portsTbody.appendChild(tr);
            });

        } catch (err) {
            portsLoading.style.display = 'none';
            portsEmpty.innerHTML = `<div class="alert alert-danger">Error scanning ports: ${escapeHtml(err.message)}</div>`;
            portsEmpty.style.display = 'block';
        }
    };

    // 2. Identify Device
    identifyBtn.addEventListener('click', async () => {
        const useMock = mockCheck.checked;
        const targetPort = selectedPortPath || (useMock ? '/dev/ttyUSB0' : null);

        if (!targetPort && !useMock) {
            state.setNotification('error', 'Please select a serial port from the table above.');
            return;
        }

        identifyBtn.disabled = true;
        if (dumpBtn) dumpBtn.disabled = true;
        identifyBtn.innerHTML = `
            <span class="btn-spinner"></span>
            Interrogating ESP32...
        `;
        identifyStatus.style.display = 'none';

        try {
            const result = await api.identifyDevice(targetPort, useMock);

            if (result.success && result.device) {
                const dev = result.device;
                idChipModel.textContent = `${dev.chip_family || 'ESP32'} (rev ${dev.chip_revision || 0})`;
                idPortLabel.textContent = `Connected on ${dev.port || targetPort}`;
                idMac.textContent = dev.mac_address || 'Unavailable';
                idFlashSize.textContent = dev.flash_size || 'N/A';
                idCrystal.textContent = dev.crystal_freq || 'N/A';
                idFlashParams.textContent = `${dev.flash_mode || 'DIO'} • ${dev.flash_speed || '40MHz'}`;
                idSdk.textContent = dev.sdk_version || 'N/A';

                identifiedCard.style.display = 'block';
                state.setNotification('success', `Identified ESP32 on ${dev.port}`);
                fetchDevicesHistory();
            } else {
                identifyStatus.className = 'alert alert-warning';
                identifyStatus.innerHTML = `
                    <strong>Identification Incomplete:</strong> ${escapeHtml(result.error || 'Device did not respond to esptool interrogation.')}
                    ${result.guidance ? `<div class="mt-2 text-xs">${escapeHtml(result.guidance)}</div>` : ''}
                `;
                identifyStatus.style.display = 'block';
            }

        } catch (err) {
            identifyStatus.className = 'alert alert-danger';
            identifyStatus.innerHTML = `
                <strong>Identification Failed:</strong> ${escapeHtml(err.message)}
                <div class="mt-2 text-xs">Tip: On Linux, ensure your user belongs to dialout group: <code>sudo usermod -a -G dialout $USER</code></div>
            `;
            identifyStatus.style.display = 'block';
        } finally {
            identifyBtn.disabled = false;
            if (dumpBtn) dumpBtn.disabled = false;
            identifyBtn.textContent = 'Identify Selected ESP32';
        }
    });

    // 3. Dump & Analyze Firmware Directly
    if (dumpBtn) {
        dumpBtn.addEventListener('click', async () => {
            const useMock = mockCheck.checked;
            const targetPort = selectedPortPath || (useMock ? '/dev/ttyUSB0' : null);

            if (!targetPort && !useMock) {
                state.setNotification('error', 'Please select a serial port from the table above.');
                return;
            }

            dumpBtn.disabled = true;
            identifyBtn.disabled = true;
            dumpBtn.innerHTML = `
                <span class="btn-spinner"></span>
                Dumping &amp; Analyzing...
            `;
            identifyStatus.className = 'alert alert-info';
            identifyStatus.innerHTML = `
                <strong>Dumping Flash:</strong> Reading SPI flash memory from ESP32 on <code>${escapeHtml(targetPort)}</code> and running vulnerability engine. Please wait...
            `;
            identifyStatus.style.display = 'block';

            try {
                const result = await api.dumpDeviceFirmware({ port: targetPort, mock: useMock });
                if (result && result.assessment_id) {
                    state.setNotification('success', `Firmware dumped and analyzed successfully! Assessment ID: ${result.assessment_id}`);
                    state.setRoute('detail', result.assessment_id);
                } else {
                    identifyStatus.className = 'alert alert-warning';
                    identifyStatus.innerHTML = `<strong>Dump Completed:</strong> Firmware dumped but assessment ID was missing.`;
                }
            } catch (err) {
                identifyStatus.className = 'alert alert-danger';
                identifyStatus.innerHTML = `
                    <strong>Firmware Dump Failed:</strong> ${escapeHtml(err.message)}
                    <div class="mt-2 text-xs">Tip: Press and hold the <strong>BOOT</strong> button on your ESP32 board while triggering the dump to ensure bootloader sync.</div>
                `;
            } finally {
                dumpBtn.disabled = false;
                identifyBtn.disabled = false;
                dumpBtn.innerHTML = `
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                        <polyline points="7 10 12 15 17 10"/>
                        <line x1="12" y1="15" x2="12" y2="3"/>
                    </svg>
                    Dump &amp; Analyze Firmware
                `;
            }
        });
    }

    // 4. Load Device History
    const fetchDevicesHistory = async () => {
        try {
            const data = await api.listDevices();
            const devices = data.devices || [];

            if (devices.length === 0) {
                devicesTable.style.display = 'none';
                devicesEmpty.style.display = 'block';
                return;
            }

            devicesTable.style.display = 'table';
            devicesEmpty.style.display = 'none';
            devicesTbody.innerHTML = '';

            devices.forEach(dev => {
                const tr = document.createElement('tr');
                const flashVendorStr = dev.flash_vendor_id ? ` (${escapeHtml(dev.flash_vendor_id)})` : '';
                tr.innerHTML = `
                    <td><code>#${dev.id}</code></td>
                    <td><strong>${escapeHtml(dev.chip_family || 'ESP32')}</strong> (rev ${dev.chip_revision || 0})</td>
                    <td><code>${escapeHtml(dev.port)}</code></td>
                    <td><code>${escapeHtml(dev.mac_address || 'N/A')}</code></td>
                    <td>${escapeHtml(dev.flash_size || 'N/A')}${flashVendorStr}</td>
                    <td>${escapeHtml(dev.crystal_freq || 'N/A')}</td>
                    <td class="text-sm text-muted">${formatDate(dev.created_at)}</td>
                    <td class="text-right">
                        <button class="btn btn-danger btn-sm btn-delete-device" data-id="${dev.id}" title="Delete device from registry">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="3 6 5 6 21 6"/>
                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                            </svg>
                            Delete
                        </button>
                    </td>
                `;

                tr.querySelector('.btn-delete-device').addEventListener('click', async (e) => {
                    const id = e.currentTarget.dataset.id;
                    if (confirm(`Are you sure you want to remove ESP32 device record #${id} from the registry?`)) {
                        try {
                            await api.deleteDevice(id);
                            state.setNotification('success', `Device #${id} removed.`);
                            await fetchDevicesHistory();
                        } catch (err) {
                            state.setNotification('error', `Failed to delete device #${id}: ${err.message}`);
                        }
                    }
                });

                devicesTbody.appendChild(tr);
            });

        } catch (err) {
            devicesTable.style.display = 'none';
            devicesEmpty.innerHTML = `<p class="text-muted">Error loading registry: ${escapeHtml(err.message)}</p>`;
            devicesEmpty.style.display = 'block';
        }
    };

    scanPortsBtn.addEventListener('click', scanPorts);
    mockCheck.addEventListener('change', () => {
        const canAct = mockCheck.checked || Boolean(selectedPortPath);
        identifyBtn.disabled = !canAct;
        if (dumpBtn) dumpBtn.disabled = !canAct;
    });

    // Initial triggers
    scanPorts();
    fetchDevicesHistory();
}
