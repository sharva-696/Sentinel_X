# Sentinel-X: Hardware Verification & ESP32 Interrogation Guide

This guide explains how to connect and interrogate a physical ESP32 development board using the Sentinel-X hardware discovery and identification engine.

---

## 1. Safety & Non-Destructive Operation Guarantee

Sentinel-X is a **defensive, read-only assessment platform**:
* **No Flash Writing**: The tool never executes `write_flash` or modifies flash memory.
* **No Flash Erasing**: The tool never executes `erase_flash` or `erase_region`.
* **No Fuse Modification**: The tool never burns eFuses or alters hardware security registers.
* **Controlled Interrogation**: The only operations invoked on connected boards are read-only inquiries (`flash-id`, `read-mac`, `chip-id`).

---

## 2. Physical USB Connection & Port Identification

### Step 1: Connect the Development Board
Connect your ESP32 board (ESP32, ESP32-S2, ESP32-S3, ESP32-C3, or ESP32-C6) to your Linux host using a data-capable USB cable.

### Step 2: Identify the Serial Port
Run the kernel log command to identify the device node assigned by the OS:

```bash
dmesg | grep -E "ttyUSB|ttyACM|ch341|cp210x|ftdi" | tail -n 10
```

Typical device nodes:
* **CP2102 / CH340 / FTDI bridge**: `/dev/ttyUSB0`, `/dev/ttyUSB1`
* **ESP32-S3 / ESP32-C3 native USB**: `/dev/ttyACM0`, `/dev/ttyACM1`

---

## 3. Checking and Configuring Linux Permissions

By default on Linux (Debian, Ubuntu, Kali, Arch), serial port device nodes are owned by the `root` user and the `dialout` (or `uucp`) group:

```bash
ls -l /dev/ttyUSB0
# crw-rw---- 1 root dialout 188, 0 Oct 28 23:50 /dev/ttyUSB0
```

### Checking User Group Membership
Run:
```bash
groups $USER
```

If `dialout` is not listed, grant your user access by adding yourself to the `dialout` group:

```bash
sudo usermod -aG dialout $USER
```

> **Security Note**: Adding a user to the `dialout` group grants permissions to read and write to attached serial devices. It does not grant general root/sudo administrative privileges. You must log out and log back in (or run `newgrp dialout`) for the group change to take effect in your shell session.

---

## 4. Resolving Port Conflicts (Port Busy / Locked)

If another program is currently using the serial port (such as an active terminal monitor or IDE), esptool will fail with `PORT_BUSY` (`Device or resource busy`).

To find and release the blocking process:

```bash
# Identify process using the serial port
lsof /dev/ttyUSB0
# or
fuser /dev/ttyUSB0

# Close any running serial monitors (minicom, screen, picocom, idf.py monitor)
killall minicom screen picocom
```

---

## 5. Initiating Identification via the API

### Step 1: Discover Available Ports
```bash
curl -X GET "http://localhost:8000/api/devices/ports" -H "accept: application/json"
```

**Example Response:**
```json
{
  "total_ports": 1,
  "ports": [
    {
      "device": "/dev/ttyUSB0",
      "name": "ttyUSB0",
      "description": "CP2102 USB to UART Bridge Controller",
      "hwid": "USB VID:PID=10C4:EA60",
      "manufacturer": "Silicon Labs",
      "vid": "0x10c4",
      "pid": "0xea60",
      "is_usb_adapter": true,
      "is_likely_esp": true,
      "is_accessible": true,
      "permission_warning": null
    }
  ]
}
```

### Step 2: Interrogate the Connected Device
```bash
curl -X POST "http://localhost:8000/api/devices/identify" \
  -H "Content-Type: application/json" \
  -d '{
    "port": "/dev/ttyUSB0",
    "baudrate": 115200,
    "timeout_seconds": 3.0
  }'
```

**Expected Successful Response:**
```json
{
  "status": "SUCCESS",
  "device": {
    "port": "/dev/ttyUSB0",
    "chip_family": "ESP32-S3 (QFN56) (revision v0.2)",
    "chip_revision": 2,
    "mac_address": "84:f7:03:a1:b2:c3",
    "crystal_freq": "40MHz",
    "features": ["WiFi", "BLE"],
    "flash_size": "8MB",
    "flash_vendor_id": "c8 (Device: 4017)",
    "flash_mode": "Unavailable (requires image header inspection)",
    "flash_speed": "Unavailable (requires image header inspection)",
    "sdk_version": "UNAVAILABLE_VIA_BOOTLOADER",
    "tool_version": "esptool 5.6.0",
    "warnings": [],
    "notes": [
      "Retrieved via non-destructive esptool flash-id query.",
      "SDK version is unavailable via ROM bootloader interrogation."
    ]
  },
  "persisted": true,
  "device_id": 1
}
```

---

## 6. Diagnostic Reference & Common Error States

| Status Code | Cause | Resolution |
|---|---|---|
| **`TIMEOUT`** | The ESP32 failed to respond to the serial bootloader sync handshake within the timeout period. | 1. Ensure the board is in download mode: hold down the **BOOT / IO0** button, tap the **RTS / EN / RESET** button, and release BOOT.<br>2. Verify the USB cable supports data transfer (many cheap cables are power-only). |
| **`PERMISSION_DENIED`** | Current Linux user is not in the `dialout` group. | Run `sudo usermod -aG dialout $USER` and log back into your session. |
| **`PORT_BUSY`** | Another application (`minicom`, `screen`, `idf.py monitor`) has locked the port. | Close the conflicting program or run `fuser -k /dev/ttyUSB0`. |
| **`UNRECOGNIZED_DEVICE`** | The serial device responded, but the protocol did not match any supported ESP32 ROM bootloader. | Ensure the selected port is an actual ESP32 board and not an Arduino, mouse, or unrelated microcontroller. |

---

## 7. Status of Physical Verification

> **Notice**: All automated test cases in `backend/tests/test_hardware.py` run against mocked hardware drivers and captured esptool 5.6.0 outputs. **Verification with an actual physical ESP32 board remains outstanding until physical USB hardware testing is conducted.**
