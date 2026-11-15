---
name: Bug Report
about: Report something broken in the firmware (detection, parsing, UI, storage, etc.)
title: "[BUG] <short summary>"
labels: bug
assignees: ''
---

**Component / file affected**
Which module? e.g. `detect.cpp`, `packets.cpp`, `sensors.cpp`, `ui.cpp`, `logging.cpp`, `storage.cpp`, `tasks.cpp`

**Hardware / build info**
- Board: e.g. ESP32 dev module / board variant
- Firmware version / commit:
- Build environment: e.g. PlatformIO, Arduino IDE, ESP-IDF version

**Describe the bug**
A clear description of what happens vs. what you expected.

**Steps to reproduce**
1. Flash firmware ...
2. Set channel / scan mode to ...
3. Observe ...

**Expected behaviour**

**Actual behaviour / logs**
Paste relevant serial monitor output. Do NOT paste captured handshakes, PMKIDs, or data belonging to third-party networks.

**Frequency**
Always / intermittent (roughly X in Y runs) / once

**Regression check**
Did this work in a previous version? Which one?

**Additional context**
Screenshots of the UI, SD card files, sketches, anything else.
