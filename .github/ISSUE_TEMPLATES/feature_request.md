---
name: Feature Request
about: Suggest an idea or new capability for the firmware
title: "[FEATURE] <short summary>"
labels: enhancement
assignees: ''
---

**Problem / motivation**
What problem does this solve? Is it related to a frustration? e.g. "threat score misses Karma attacks that start mid-scan".

**Proposed solution**
What should happen? Describe the behaviour, not the implementation.

**Where it fits**
Which area does this touch?
- [ ] Detection engines (`detect.*`) — evil twin / Karma / anomaly / PMKID / WPS / WPA3 heuristics
- [ ] Packet handling (`packets.*`)
- [ ] UI / display (`ui.*`)
- [ ] Storage / logging (`storage.*`, `logging.*`)
- [ ] Task scheduling (`tasks.*`)
- [ ] Sensors / hardware (`sensors.*`)
- [ ] Config (`config.h`, `globals.*`)

**Alternatives considered**

**Trade-offs / constraints**
e.g. RAM/flash impact on ESP32, extra scan time, false-positive risk in threat scoring.

**Are you willing to help implement / test it?**
