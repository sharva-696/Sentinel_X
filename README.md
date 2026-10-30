# Sentinel-X

> **Automated ESP32 Hardware Identification, Firmware Extraction & Security Auditing Platform**

Sentinel-X is a comprehensive embedded security assessment framework designed for IoT security researchers, hardware penetration testers, and academic evaluators. It automates device enumeration, ESP32 ROM bootloader firmware extraction, multi-rule vulnerability scanning, CVSS-weighted risk scoring, and export of sanitized compliance reports alongside an interactive web dashboard.

---

## Key Features

- **Automated Hardware Discovery**:
  - Live serial bus enumeration (`/dev/ttyUSB*`, `/dev/ttyACM*`, COM ports).
  - Chip identification extracting exact model (ESP32-D0WD-V3, ESP32-S3, ESP32-C3, etc.), silicon revision, MAC address, crystal frequency, and SPI flash characteristics.
  - Zero-hang fallback: Gracefully handles hardware stub timeouts and ROM bootloader sync.

- **Firmware Acquisition / Dump**:
  - Direct flash memory dumping over UART using optimized baud rates (115200 to 921600 baud).
  - Handles boards requiring manual `BOOT` / GPIO0 pull-down or automatic RTS/DTR state transitions.

- **Static Firmware Analysis Engine**:
  - **Secret & Credential Scanner**: Detects embedded Wi-Fi PSKs, hardcoded passwords, JWT tokens, AWS/GCP keys, and private keys.
  - **Network Security Auditing**: Identifies insecure plaintext endpoints (HTTP, Telnet, unencrypted MQTT) and hardcoded IP addresses.
  - **Debug & Telemetry Leak Detection**: Uncovers left-over UART debug statements, panic dumps (Guru Meditation Errors), and JTAG/GDB symbol tables.
  - **Memory & Entropy Profiling**: Analyzes section entropy to flag encrypted vs unencrypted partitions.

- **Dual-Layer Security & Faculty Demo Mode**:
  - **Web Dashboard**: Includes a **🛡️ Faculty Demo Mode** toggle and individual **👁️ Reveal / 🙈 Mask** switches that highlight extracted passwords in high-visibility badges for live evaluations.
  - **Responsible Disclosure Guarantee**: Exported PDF and HTML reports are strictly **100% sanitized and redacted** (`***********************`), ensuring compliance when sharing reports externally.

- **Automated Test Suite**:
  - 111 comprehensive tests verifying hardware mocking, security scanning, scoring calculations, sanitization guarantees, and REST API endpoints.

---

## Architecture & Tech Stack

```
Sentinel_X/
├── backend/
│   ├── app/
│   │   ├── models/            # SQLAlchemy database models (Device, Assessment, Finding)
│   │   ├── modules/
│   │   │   ├── analysis/      # Secret scanner, regex rules, string extractor, risk scorer
│   │   │   ├── assessment/    # Finding normalizer, deduplication, scoring engine
│   │   │   ├── hardware/      # Serial discovery, ESP32 chip detection, firmware dumper
│   │   │   └── reporting/     # HTML & ReportLab PDF report generators
│   │   ├── routers/           # FastAPI routers (/devices, /firmware, /assessments, /health)
│   │   └── main.py            # FastAPI application entry point & lifespan setup
│   ├── tests/                 # Full pytest test suite (111 tests)
│   └── storage/               # SQLite database & artifact directories
├── frontend/                  # Vanilla JS SPA Dashboard (zero external build tools)
│   ├── css/styles.css         # Modern dark-mode UI with high-contrast secret badges
│   ├── js/app.js              # State manager & view router
│   └── index.html             # Dashboard entry point
├── docs/                      # Architectural specifications & phase guides
├── requirements.txt           # Python dependencies
├── run.py                     # Self-contained launcher script
└── pytest.ini                 # Pytest configuration
```

- **Backend**: Python 3.10+, FastAPI, SQLAlchemy, SQLite, Pydantic, ReportLab.
- **Frontend**: Lightweight Vanilla JavaScript (ES6+), Modern CSS3, HTML5 (no Node.js build step required).
- **Embedded & Hardware**: PySerial, esptool, Linux udev/ch341/cp210x serial drivers.

---

## Setup & Installation

### 1. Prerequisites
- **Python**: 3.10, 3.11, 3.12, 3.13, or 3.14.
- **Operating System**: Linux (Ubuntu, Debian, Fedora, Arch), macOS, or Windows.
- **Hardware (Optional for Live Dumps)**: An ESP32 connected via USB cable with data lines.

### 2. Clone the Repository
```bash
git clone https://github.com/sharva-696/Sentinel_X.git
cd Sentinel_X
```

### 3. Create a Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```
*(On Windows: `venv\Scripts\activate`)*

### 4. Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Serial Port Permissions (Linux Only)

If you are running Sentinel-X on Linux and plan to connect an ESP32 board, your user must have permission to access serial TTY devices:

1. Add your user to the `dialout` (or `uucp`) group:
   ```bash
   sudo usermod -aG dialout $USER
   ```
2. Log out and log back in, or activate the group in your current shell:
   ```bash
   newgrp dialout
   ```
3. *(Alternative for quick testing)*:
   ```bash
   sudo chmod 666 /dev/ttyUSB0
   ```

---

## Running the Application

### Option A: Launcher Script (Recommended)
```bash
python3 run.py
```

### Option B: Direct Uvicorn Command
```bash
python3 -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Once running:
- **Web Dashboard**: [http://127.0.0.1:8000/dashboard/](http://127.0.0.1:8000/dashboard/)
- **Interactive API Docs (Swagger)**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Alternative API Docs (ReDoc)**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## Running the Automated Tests

Verify that all unit tests, integration routes, and security audit rules pass:

```bash
pytest -q
```
Expected output:
```
============================= 111 passed in 1.80s ==============================
```

---

## Faculty Demonstration Guide

When presenting Sentinel-X to faculty or evaluators, follow this recommended walkthrough:

1. **Device Identification**:
   - Connect the ESP32 board to any USB port.
   - Navigate to the **Connected Devices** tab on the Dashboard.
   - Click **Scan Serial Ports**. Observe the detected chip family, silicon revision (e.g. `ESP32-D0WD-V3 rev 3.1`), MAC address, and baud rate.

2. **Firmware Dump & Acquisition**:
   - In the Connected Devices panel, click **Dump Firmware**.
   - Watch the live progress as Sentinel-X establishes communication with the ROM bootloader and saves the binary image to storage.

3. **Static Security Analysis**:
   - Go to **Firmware Analysis** and analyze the newly acquired firmware (or select any previous dump).
   - Review the calculated Risk Score and severity breakdown (Critical / High / Medium / Low).

4. **Live Faculty Demo Mode**:
   - Open the **Assessment Detail** view.
   - Show the **Findings Explorer**. By default, all credentials and passwords are redacted (`***********************`).
   - Toggle **🛡️ Faculty Demo Mode LIVE** or click individual **👁️ Reveal** buttons. Extracted passwords (such as Wi-Fi credentials or admin tokens) will illuminate in a glowing red badge.

5. **Compliance & Export**:
   - Click **Download PDF Report** or **Download HTML Report**.
   - Open the generated report to show the faculty that all exported artifacts automatically sanitize credentials for responsible disclosure compliance.

---

## License

Sentinel-X is developed for authorized hardware security research and academic education. Only analyze firmware and hardware you own or have explicit authorization to audit.
