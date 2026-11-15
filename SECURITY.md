# Security Policy

## Supported Versions

Only the latest tagged release and the `main` branch are actively maintained. Please verify your issue reproduces against a current build before reporting.

| Version | Supported |
|---------|-----------|
| latest release / main | Yes |
| older releases | No |

## Scope

This project is firmware for an ESP32-S3 based wireless monitoring device. Reports are in scope if they affect:

- The firmware itself: buffer overflows, memory corruption, crashes, lockups, or unexpected behavior caused by malformed WiFi, BLE, or crafted input (pcap parsing, beacon/probe frame handling, malformed packets in the queue pipeline)
- SD card file handling: path traversal, corrupted-file crashes, or failure modes when loading `config.csv`, `ouilist.csv`, `known_devices.csv`, `fingerprints.csv`, or `vendor_aliases.csv`
- Sensitive data leakage: handshake captures, PMKIDs, or WPS data being written to unintended locations or left unprotected on the SD card
- Build integrity: tampering or supply-chain issues in the build scripts or PlatformIO configuration

Out of scope:

- Misuse of the tool to attack or monitor networks without authorization. That is a legal matter, not a security vulnerability in this project
- Vulnerabilities in third-party libraries (Adafruit SSD1306, TinyGPS++, RTClib, NimBLE). Report those upstream first, then let us know so we can track the fix
- Flaws that require physical possession of the device and its unlocked SD card, unless they also permit remote code execution or data exfiltration over the air
- Denial of service via RF flooding that merely degrades scanning performance without crashing or corrupting the device

## Reporting a Vulnerability

Do not open a public GitHub issue for security reports.

Report privately through GitHub's "Report a vulnerability" feature (Security tab, then Advisory), which notifies the maintainer directly. Alternatively, email the contact listed in the repository owner's GitHub profile.

When reporting, please include:

- Firmware version or commit hash, and the build environment (Arduino IDE or PlatformIO)
- Hardware setup (board revision, peripherals connected)
- A description of the issue and the steps or packets needed to reproduce it
- Relevant files: a sanitized pcap/log excerpt, crash log from the serial console at 115200 baud, or stack trace
- Your assessment of severity and impact

Please do not include real captured credentials, handshake files, PMKIDs, or third-party network identifiers in your report. Sanitize traces before attaching them.

## Response Process

1. You will receive an acknowledgment within 7 days
2. Triage and impact assessment, typically within 14 days
3. Fix development and validation on real hardware
4. Coordinated release, followed by a public advisory crediting you (unless you prefer to remain anonymous)

We aim to release a patch for high-severity issues within 90 days of the report. Embedded hardware constraints (limited OTA capacity, manual flashing) may mean fixes ship in the next tagged release rather than as emergency patches.

## Safe Harbor

We will not pursue legal action against researchers who report vulnerabilities in good faith, use only devices they own or are authorized to test, avoid privacy violations, and give us reasonable time to issue a fix before public disclosure. Full public disclosure is fine 90 days after the report.

## Hardening Recommendations for Operators

Since this device stores sensitive captures, consider the following when deploying it:

- Encrypt or physically secure the SD card; any handshake or PMKID file it produces is crackable offline
- Set `BTN_PANIC` before transporting the device through untrusted environments; long press performs a graceful shutdown with file flushing rather than leaving partial writes
- Do not leave `pmkid_hashes.txt` on removable media that leaves your possession
