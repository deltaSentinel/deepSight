# Deep Sight Edition (v4.0)

[![CI](https://github.com/deltaSentinel/deepSight/actions/workflows/ci.yml/badge.svg)](https://github.com/deltaSentinel/deepSight/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/License-GPL--3.0-blue.svg)
![Platform](https://img.shields.io/badge/Platform-ESP32--S3-informational.svg)
![Framework](https://img.shields.io/badge/Framework-Arduino%20%2F%20FreeRTOS-success.svg)

A passive WiFi + BLE intrusion detection and reconnaissance system built on the ESP32-S3, running on the Arduino framework with FreeRTOS multithreading.

> **Legal / Ethical Notice:** This is a passive monitoring and security-audit tool intended for use on networks you own or are authorized to assess. Captured handshakes, PMKIDs, and WPS data are logged for analysis and cracking of your own networks only. Unauthorized monitoring of wireless networks is illegal in most jurisdictions. Use responsibly.

---

## Features

### WiFi Recon and Detection
- Passive channel hopping sniffing: 802.11 b/g/n/ax across channels 1-13 with adaptive dwell times
- WPA2/WPA3 handshake capture: 4-way EAPOL tracking, exported as .cap pcap files
- PMKID capture: auto-saved in Hashcat-ready format (`/pmkid_hashes.txt`)
- Evil Twin detection: duplicate SSIDs across BSSIDs trigger max threat score plus audible alert
- KARMA attack detection: flags suspicious probe request/response ratios (>0.8)
- WPA3-SAE and Wi-Fi 6 detection: identifies HE tag (0x6B) and WPA3 transition-mode exposure
- Mesh network detection: tag 0x84
- Hidden SSID reveal: recovers hidden networks from Probe Responses
- Deauth and disassociation forensics: logs reason codes, source and destination MACs
- MAC randomization detection
- WPS PIN exposure detection: passive extraction via vendor IE 0xDD (Broadcom OUI)
- Known-bad device alerts: OUI vendor lookup against a local device database

### Threat Scoring (0-100 per AP)
Weighted factors include: TKIP (+30), PMKID capture (+50), evil twin (+100), WPA3 transition mode (+15), exposed WPS PIN (+25), suspicious vendor tags (+40), and more. Networks are auto-tagged by SSID keyword: Public, Enterprise, IoT, Personal, Mesh, Suspicious, Hidden, Open.

### Reporting and Logging
- Sortable, color-coded HTML report (`/report.html`) with high, medium, and low threat severity
- KML network map export (`/networks.kml`) for Google Earth
- Delta logging: only writes when RSSI changes by 5 dBm or more, or 30 s elapse (roughly 80% storage reduction)
- Automatic log rotation: CSV at 512 KB, pcap at 2 MB
- Client-to-AP association mapping (up to 128 entries)
- Channel utilization and noise floor statistics

### BLE Scanning
NimBLE-powered passive BLE and iBeacon discovery with periodic scanning intervals.

### Power Management
- Battery saver mode (longer scan intervals, deep sleep with GPIO wake)
- LiPo voltage monitoring via ADC divider
- Optional DS3231 RTC (survives power loss, set from compile time)

---

## Architecture

FreeRTOS multithreaded design with tasks pinned across both cores:

| Task | Core | Role |
|------|------|------|
| `packetProcessorTask` | 1 (prio 3, 8 KB stack) | Parses all WiFi/BLE frames |
| `logWriterTask` | 0 | Batched CSV writes |
| `pcapWriterTask` | 0 | Batched pcap writes |
| `cleanupTask` | - | Evicts stale APs/clients after timeout |
| `healthTask` | - | Monitors heap/PSRAM, watchdog feed, auto-restart on low memory |

Key internals: mutex-protected data structures (10 mutexes), PSRAM-backed packet buffer pool (64-pool/128-queue), task watchdog (10 s, panic), atomic rename-based log rotation, DHCP disabled, static buffer allocation.

---

## Hardware

| Component | Details |
|-----------|---------|
| MCU | ESP32-S3 Dev Module (OPI PSRAM, 16 MB flash) |
| Display | SSD1306 0.96" OLED (I2C @ 0x3C, SDA 16 / SCL 17) |
| GPS | UART @ 9600 baud (RX 1 / TX 3) |
| Storage | microSD over SPI (CS 10) |
| Alert | Piezo buzzer (GPIO 4) |
| RTC | DS3231 (optional) |
| Buttons | 5x on GPIO 5, 6, 7, 8, 9 (remapped to avoid JTAG/strapping/UART0 conflicts) |
| Power | LiPo + ADC voltage divider (GPIO 2) |

### Button Controls

| Button | Short press | Long press |
|--------|------------|-----------|
| LOG | Toggle logging | none |
| HOP | Force channel hop | none |
| CLEAR | Generate HTML report | 5 s or more: battery saver toggle; 8 s or more: flush files, save fingerprints, shutdown |
| PANIC | Wipe SD logs and restart | 3 s or more: graceful shutdown |
| HEALTH | Toggle health dashboard | none |

Health dashboard shows: free heap, PSRAM, queue depths, dropped packets, total packets, current channel, battery level.

---

## Dependencies

- Arduino core for ESP32 (ESP-IDF hybrid APIs)
- `Adafruit_SSD1306` and `Adafruit_GFX`
- `TinyGPS++`
- `RTClib`
- `NimBLE-Arduino`
- Built-in: `WiFi.h`, `esp_wifi`, `esp_task_wdt`, `SPI`, `SD`, `Wire`, `HardwareSerial`

---

## SD Card Layout

| Path | Purpose |
|------|---------|
| `/config.csv` | BSSID filters, whitelist mode (`W`) |
| `/ouilist.csv` | Vendor OUI database |
| `/known_devices.csv` | Known device classifications (GOOD / BAD / SUSPICIOUS) |
| `/fingerprints.csv` | Device fingerprints |
| `/vendor_aliases.csv` | Vendor name aliases |
| `/log_N.csv` | Rotating event logs |
| `/capture_N.pcap` | Rotating packet captures |
| `/HS_<bssid>_<ms>.cap` | Individual handshake captures |
| `/pmkid_hashes.txt` | Hashcat-format PMKIDs |
| `/report.html` | Threat report |
| `/networks.kml` | Geographic map export |

---

## Getting Started

1. Flash the sketch to an ESP32-S3 Dev Module (Arduino IDE or PlatformIO)
2. Insert a FAT32-formatted microSD card (optionally pre-load the CSV databases above)
3. Wire up display, GPS, buzzer, and buttons per the hardware table (or adjust pin defines)
4. Power on. The device banner reads "ESP32-S3 WIDS v4.0 Deep Sight"
5. Serial console at 115200 baud for diagnostics

---

## Contributing

Contributions are welcome. By submitting a pull request, you agree that your contributions will be licensed under GPL-3.0 along with the rest of the project. Please keep changes consistent with the existing code style and test on real hardware where possible.

---

## License

This project is licensed under the **GNU General Public License v3.0**. See [LICENSE](LICENSE) for details.

    WIDS — Deep Sight Edition
    Copyright (C) 2026  Raymond Balesky

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

---

Built with love and far too many packets.
