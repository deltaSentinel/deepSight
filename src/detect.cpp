// ============================================================
// src/detect.cpp — VERBATIM from original (lookups + detection)
// ============================================================
#include "detect.h"
#include "helpers.h"
#include "logging.h"

// ======================================================
// LOOKUPS
// ======================================================

const char* getVendorFromOui(const uint8_t* mac) {
  char ouiStr[9];
  snprintf(ouiStr, 9, "%02X:%02X:%02X", mac[0], mac[1], mac[2]);
  for (int i = 0; i < aliasCount; i++)
    if (strcmp(vendorAliases[i].oui, ouiStr) == 0) return vendorAliases[i].alias;
  for (int i = 0; i < ouiCount; i++)
    if (strcmp(ouiDatabase[i].oui, ouiStr) == 0) return ouiDatabase[i].vendor;
  return "Unknown";
}

int getDeviceStatus(const uint8_t* mac) {
  for (int i = 0; i < knownDeviceCount; i++) {
    if (knownDevices[i].active && macEqual(knownDevices[i].mac, mac)) {
      if (strcmp(knownDevices[i].type, "GOOD") == 0) return 1;
      if (strcmp(knownDevices[i].type, "BAD") == 0) return 2;
      if (strcmp(knownDevices[i].type, "SUSPICIOUS") == 0) return 3;
    }
  }
  return 0;
}

// ======================================================
// DETECTION & PROTOCOL LOGIC (v4.0 Enhanced)
// ======================================================

bool checkEvilTwin(const uint8_t* bssid, const char* ssid) {
  for (int i = 0; i < knownDeviceCount; i++) {
    if (knownDevices[i].active && strcmp(knownDevices[i].nickname, ssid) == 0) {
      if (!macEqual(knownDevices[i].mac, bssid)) return true;
    }
  }
  for (int i = 0; i < fpCount; i++) {
    if (fpDB[i].active && strcmp(fpDB[i].ssid, ssid) == 0) {
      char hex[13];
      snprintf(hex, 13, "%02X%02X%02X%02X%02X%02X", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
      if (strstr(fpDB[i].id, hex) == NULL) return true;
    }
  }
  return false;
}

bool checkPMKID(const uint8_t* payload, int len) {
  if (len < 38) return false;
  for (int i = 0; i < len - 2; i++) {
    if (payload[i] == 0x30 && payload[i+1] >= 18) return true;
  }
  return false;
}

// --- WPS PIN Extraction ---
int extractWPSPin(const uint8_t* payload, int len) {
  for (int i = 0; i < len - 2; i++) {
    if (payload[i] == 0xDD) {
      int ieLen = payload[i+1];
      if (ieLen < 10) continue;
      if (payload[i+2] == 0x00 && payload[i+3] == 0x50 && payload[i+4] == 0xF2) {
        int pos = i + 5; // After OUI and Type
        while (pos < i + 2 + ieLen - 4) {
          uint16_t attrId = payload[pos] | (payload[pos+1] << 8);
          uint16_t attrLen = payload[pos+2] | (payload[pos+3] << 8);
          if (attrId == 0x10 && attrLen == 4) { // PIN attribute
             int pin = (payload[pos+4] << 24) | (payload[pos+5] << 16) | (payload[pos+6] << 8) | payload[pos+7];
             return pin;
          }
          pos += 4 + attrLen;
        }
      }
    }
    i += payload[i+1] + 1;
  }
  return 0;
}

// --- WPA3 Transition Mode Detection ---
bool checkWPA3Transition(const uint8_t* payload, int len) {
  for (int i = 0; i < len - 2; i++) {
    if (payload[i] == 0x30) {
      int ieLen = payload[i+1];
      if (ieLen < 20) continue;
      int offset = 2; // Skip Ver
      offset += 4; // Skip Group Suite
      int pwCnt = payload[i+2+offset] | (payload[i+2+offset+1] << 8);
      offset += 2 + (pwCnt * 4);
      int authCnt = payload[i+2+offset] | (payload[i+2+offset+1] << 8);
      offset += 2;

      bool hasPSK = false;
      bool hasSAE = false;
      for (int j = 0; j < authCnt; j++) {
        if (offset + 4 > i + 2 + ieLen) break;
        uint8_t akm = payload[offset + 3];
        if (akm == 0x02) hasPSK = true;
        if (akm == 0x08) hasSAE = true;
        offset += 4;
      }
      if (hasPSK && hasSAE) return true;
    }
  }
  return false;
}

// ======================================================
// PMKID EXTRACTION & HASHCAT FORMATTING
// ======================================================

void extractAndSavePMKID(const uint8_t* bssid, const uint8_t* payload, int len, const char* ssid) {
  int pos = 38;
  uint8_t pmkid[16];
  bool found = false;

  if (len < 40) return;

  while (pos < len - 2) {
    uint8_t tag = payload[pos];
    uint8_t tagLen = payload[pos+1];

    if (pos + 2 + tagLen > len) break;

    if (tag == 0x30) {
      if (tagLen >= 18) {
        int offset = 2;
        offset += 2; // Version

        if (offset + 4 > tagLen) { pos += 2 + tagLen; continue; }
        offset += 4; // Group Suite

        if (offset + 2 > tagLen) { pos += 2 + tagLen; continue; }
        int pwCnt = payload[pos+offset] | (payload[pos+offset+1] << 8);
        offset += 2 + (pwCnt * 4);

        if (offset + 2 > tagLen) { pos += 2 + tagLen; continue; }
        int authCnt = payload[pos+offset] | (payload[pos+offset+1] << 8);
        offset += 2 + (authCnt * 4);

        if (offset + 2 <= tagLen) {
          int pmkidCnt = payload[pos+offset] | (payload[pos+offset+1] << 8);
          offset += 2;

          if (pmkidCnt > 0 && offset + 16 <= tagLen) {
            memcpy(pmkid, &payload[pos+offset], 16);
            found = true;
            break;
          }
        }
      }
    }

    pos += 2 + tagLen;
  }

  if (!found) {
    Serial.println("[WARN] PMKID IE found but could not parse hash");
    return;
  }

  char bssidStr[18];
  char staMacStr[18];
  char pmkidHex[33];

  snprintf(bssidStr, 18, "%02X:%02X:%02X:%02X:%02X:%02X", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
  snprintf(staMacStr, 18, "%02X:%02X:%02X:%02X:%02X:%02X", 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF);

  for (int i = 0; i < 16; i++) sprintf(pmkidHex + (i * 2), "%02X", pmkid[i]);

  char hashLine[256];
  snprintf(hashLine, sizeof(hashLine), "*AP*%s*%s*%s*%s*", bssidStr, staMacStr, pmkidHex, ssid);

  bool written = false;
  for (int retry = 0; retry < 3; retry++) {
    File pmkidFile = SD.open("/pmkid_hashes.txt", FILE_APPEND);
    if (pmkidFile) {
      pmkidFile.println(hashLine);
      pmkidFile.flush();
      pmkidFile.close();
      written = true;
      break;
    }
    delay(50);
  }

  if (written) {
    Serial.printf("[SUCCESS] PMKID Saved: %s (Hash: %s)\n", ssid, pmkidHex);
    if (!batterySaverMode) { playTone(3500, 150); delay(50); playTone(4500, 150); }
  } else {
    Serial.println("[ERROR] Failed to write PMKID after 3 retries");
  }
}

void decodeAdvancedFeatures(const uint8_t* payload, int len, bool& isWPA3, bool& isWifi6, bool& isMesh) {
  isWPA3 = false; isWifi6 = false; isMesh = false;
  if (len < 40) return;
  int pos = 38;
  while (pos < len - 2) {
    uint8_t tag = payload[pos];
    uint8_t lenIE = payload[pos+1];
    if (pos + 2 + lenIE > len) break;
    if (tag == 0x13) isWPA3 = true;
    if (tag == 0x30 && lenIE >= 20) {
      if (payload[pos+2]==0x00 && payload[pos+3]==0x0F && payload[pos+4]==0xAC && payload[pos+5]==0x05) isWPA3 = true;
    }
    if (tag == 0x6B) isWifi6 = true;
    if (tag == 0x84) isMesh = true;
    pos += 2 + lenIE;
  }
}

void parseSecurity(const uint8_t* payload, int len, char* cipher, char* auth) {
  strcpy(cipher, "UNK"); strcpy(auth, "UNK");
  if (len < 40) return;
  for (int i = 0; i < len - 2; i++) {
    if (payload[i] == 0x30) {
      int ieLen = payload[i+1];
      if (ieLen < 20) continue;
      uint8_t gs = payload[i+2+4];
      uint8_t pc = payload[i+2+6] | (payload[i+2+7] << 8);
      if (gs == 0x04) strcpy(cipher, "CCMP");
      else if (gs == 0x02) strcpy(cipher, "TKIP");
      else if (gs == 0x08) strcpy(cipher, "GCMP");
      int akmOff = i + 2 + 8 + (pc * 4);
      if (akmOff + 4 <= len) {
        uint8_t akm = payload[akmOff+4];
        if (akm == 0x02) strcpy(auth, "PSK");
        else if (akm == 0x01) strcpy(auth, "802.1X");
        else if (akm == 0x08) strcpy(auth, "SAE");
      }
      return;
    }
  }
}

// --- Channel Utilization Update ---
void updateChannelStats(int channel, int rssi) {
  if (channel < 1 || channel > 13 || !channelStats) return;
  channelStats[channel].totalPackets++;
  // Use RSSI as proxy for noise floor (approximate)
  if (rssi < channelStats[channel].noiseFloor || channelStats[channel].noiseFloor == 0) {
    channelStats[channel].noiseFloor = rssi;
  }
  // Calculate utilization percentage based on packet rate
  unsigned long now = millis();
  unsigned long elapsed = now - channelStats[channel].totalTime;
  if (elapsed > 60000) { // Reset every 60 seconds
    channelStats[channel].utilizationPercent =
      (channelStats[channel].totalPackets * 100.0) / (elapsed / 100.0);
    channelStats[channel].totalPackets = 0;
    channelStats[channel].totalTime = now;
  }
}

// --- Client-to-AP Mapping ---
void updateClientMap(const uint8_t* clientMac, const uint8_t* apBssid, int rssi) {
  if (!clientMap) return;
  for (int i = 0; i < MAX_CLIENT_MAP; i++) {
    if (clientMap[i].active && macEqual(clientMap[i].clientMac, clientMac)) {
      clientMap[i].rssi = rssi;
      clientMap[i].lastSeen = millis();
      memcpy(clientMap[i].apBssid, apBssid, 6);
      return;
    }
  }
  // New entry
  for (int i = 0; i < MAX_CLIENT_MAP; i++) {
    if (!clientMap[i].active) {
      clientMap[i].active = true;
      memcpy(clientMap[i].clientMac, clientMac, 6);
      memcpy(clientMap[i].apBssid, apBssid, 6);
      clientMap[i].rssi = rssi;
      clientMap[i].lastSeen = millis();
      return;
    }
  }
}

void updateBandwidth(AccessPoint* ap, uint16_t len) {
  unsigned long now = millis();
  if (now - ap->lastByteUpdate > 10000) {
    ap->bandwidthMbps = (ap->bytesReceived * 8.0) / 10000000.0;
    ap->bytesReceived = 0;
    ap->lastByteUpdate = now;
  }
  ap->bytesReceived += len;
}

bool addClientToAP(AccessPoint* ap, const uint8_t* mac) {
  if (ap->trackedClientCount >= 16) return false;
  for (int i = 0; i < ap->trackedClientCount; i++)
    if (macEqual(ap->trackedClients[i], mac)) return false;
  memcpy(ap->trackedClients[ap->trackedClientCount], mac, 6);
  ap->trackedClientCount++;
  ap->clientCount = ap->trackedClientCount;
  return true;
}

bool checkRandomized(const uint8_t* mac) { return (mac[0] & 0x02) != 0; }

void updateKarmaTracking(const uint8_t* bssid, bool isRequest) {
  if (!karmaDB) return;
  int idx = -1;
  for (int i = 0; i < 32; i++) if (karmaDB[i].active && macEqual(karmaDB[i].bssid, bssid)) { idx = i; break; }
  if (idx == -1) { for (int i = 0; i < 32; i++) { if (!karmaDB[i].active) { idx = i; break; } } }
  if (idx != -1 && idx < 32) {
    if (isRequest) karmaDB[idx].reqCount++;
    else karmaDB[idx].respCount++;
    karmaDB[idx].lastProbeReq = millis();
    karmaDB[idx].active = true;
    memcpy(karmaDB[idx].bssid, bssid, 6);
  }
}

void checkKarmaAttack() {
  if (!karmaDB) return;
  unsigned long now = millis();
  for (int i = 0; i < 32; i++) {
    if (!karmaDB[i].active) continue;
    if (now - karmaDB[i].lastProbeReq > 10000) { karmaDB[i].reqCount = 0; karmaDB[i].respCount = 0; continue; }
    if (karmaDB[i].reqCount > 5 && karmaDB[i].respCount > 0) {
      float ratio = (float)karmaDB[i].respCount / (float)karmaDB[i].reqCount;
      if (ratio > 0.8) {
        char msg[64];
        snprintf(msg, sizeof(msg), "KARMA_ATTACK: %d/%d", karmaDB[i].respCount, karmaDB[i].reqCount);
        enqueueLog("WiFi", "KARMA_DETECTED", msg, -100, currentChannel);
        beepAlert();
        karmaDB[i].reqCount = 0; karmaDB[i].respCount = 0;
      }
    }
  }
}

void updateAnomalyTracking(const uint8_t* bssid, int rssi) {
  if (!anomalyDB) return;
  int idx = -1;
  for (int i = 0; i < 32; i++) { if (anomalyDB[i].active && macEqual(anomalyDB[i].bssid, bssid)) { idx = i; break; } }
  if (idx == -1) { for (int i = 0; i < 32; i++) { if (!anomalyDB[i].active) { idx = i; break; } } }
  if (idx != -1 && idx < 32) {
    unsigned long now = millis();
    if (now - anomalyDB[idx].lastUpdate > 5000) {
      if (abs(rssi - anomalyDB[idx].avgRssi) > 15) {
         char msg[64];
         snprintf(msg, sizeof(msg), "ANOMALY_RSSI: %d vs %d", rssi, (int)anomalyDB[idx].avgRssi);
         enqueueLog("WiFi", "ANOMALY", msg, rssi, currentChannel);
      }
      anomalyDB[idx].avgRssi = (anomalyDB[idx].avgRssi + rssi) / 2;
      anomalyDB[idx].lastUpdate = now;
    }
  }
}

// ======================================================
// AUTO-TAGGING ENGINE
// ======================================================

void autoTag(const char* ssid, bool isOpen, bool isMesh, int clientCount, char* tag) {
  strcpy(tag, "General");
  if (strlen(ssid) == 0 || strcmp(ssid, "<hidden>") == 0) { strcpy(tag, "Hidden"); return; }
  String s = String(ssid); s.toLowerCase();
  if (s.indexOf("guest") >= 0 || s.indexOf("public") >= 0 || s.indexOf("free") >= 0 || s.indexOf("wifi") >= 0 || s.indexOf("open") >= 0 || s.indexOf("library") >= 0 || s.indexOf("airport") >= 0 || s.indexOf("cafe") >= 0 || s.indexOf("hotel") >= 0 || s.indexOf("mall") >= 0 || s.indexOf("starbucks") >= 0 || s.indexOf("mcdonald") >= 0) { strcpy(tag, "Public"); return; }
  if (s.indexOf("corp") >= 0 || s.indexOf("office") >= 0 || s.indexOf("admin") >= 0 || s.indexOf("internal") >= 0 || s.indexOf("enterprise") >= 0 || s.indexOf("staff") >= 0 || s.indexOf("secure") >= 0 || s.indexOf("private") >= 0) { strcpy(tag, "Enterprise"); return; }
  if (s.indexOf("smart") >= 0 || s.indexOf("iot") >= 0 || s.indexOf("home") >= 0 || s.indexOf("nest") >= 0 || s.indexOf("ring") >= 0 || s.indexOf("hue") >= 0 || s.indexOf("tplink") >= 0 || s.indexOf("esp_") >= 0 || s.indexOf("sonoff") >= 0 || s.indexOf("tuya") >= 0) { strcpy(tag, "IoT"); return; }
  if (s.indexOf("iphone") >= 0 || s.indexOf("android") >= 0 || s.indexOf("galaxy") >= 0 || s.indexOf("pixel") >= 0 || s.indexOf("ipad") >= 0 || s.indexOf("hotspot") >= 0 || s.indexOf("my ") >= 0 || s.indexOf("phone") >= 0) { strcpy(tag, "Personal"); return; }
  if (isMesh) { strcpy(tag, "Mesh"); return; }
  int alphaCount = 0, digitCount = 0, specialCount = 0;
  for (unsigned int i = 0; i < strlen(ssid); i++) { if (isalpha(ssid[i])) alphaCount++; else if (isdigit(ssid[i])) digitCount++; else specialCount++; }
  float entropy = 0.0; int slen = strlen(ssid); if (slen > 0) entropy = ((float)(alphaCount + digitCount + specialCount * 3)) / slen;
  if (slen >= 8 && specialCount >= 2 && entropy > 2.5) { strcpy(tag, "Suspicious"); return; }
  if (isOpen) { strcpy(tag, "Open"); return; }
}

// ======================================================
// THREAT SCORING ENGINE
// ======================================================

int calculateThreatScore(AccessPoint* ap) {
  int score = 0;
  if (strcmp(ap->authMode, "UNK") == 0 || strcmp(ap->cipherSuite, "UNK") == 0) score += 10;
  if (strcmp(ap->authMode, "PSK") == 0) score += 5;
  if (strcmp(ap->cipherSuite, "TKIP") == 0) score += 30;
  if (ap->hasPMKID) score += 50;
  if (ap->isEvilTwin) score += 100;
  if (ap->clientCount > 20) score += 15; else if (ap->clientCount > 10) score += 10; else if (ap->clientCount > 5) score += 5;
  if (ap->rssi > -50) score += 10; else if (ap->rssi > -60) score += 5;
  if (ap->isRandomized) score -= 5;
  if (strcmp(ap->tag, "Public") == 0) score += 10;
  if (strcmp(ap->tag, "Suspicious") == 0) score += 40;
  if (strcmp(ap->tag, "IoT") == 0) score += 20;
  if (strcmp(ap->tag, "Enterprise") == 0) score += 5;
  if (ap->isWPA3Transition) score += 15; // Transition mode is risky
  if (ap->wpsPin > 0) score += 25; // Exposed WPS PIN
  if (score < 0) { score = 0; }
  if (score > 100) { score = 100; }
  return score;
}

// ======================================================
// DELTA LOGGING ENGINE
// ======================================================

bool shouldLogAP(int apIndex, int rssi, int channel) {
  unsigned long now = millis();
  if (lastLogTimeByAP[apIndex] == 0) { lastLogTimeByAP[apIndex] = now; lastRssiByAP[apIndex] = rssi; return true; }
  int rssiDelta = abs(rssi - lastRssiByAP[apIndex]);
  unsigned long timeDelta = now - lastLogTimeByAP[apIndex];
  if (rssiDelta >= DELTA_RSSI_CHANGE || timeDelta >= DELTA_MIN_INTERVAL_MS) { lastLogTimeByAP[apIndex] = now; lastRssiByAP[apIndex] = rssi; return true; }
  return false;
}

// ======================================================
// FINGERPRINT UPDATES
// ======================================================

void updateFingerprint(const uint8_t* bssid, const char* ssid, int rssi, int ch, bool wpa3, bool wifi6, bool mesh, float bw, int cc, bool rand, const char* ciph, const char* auth, int score, const char* tag, bool transition, int wpsPin, int noise, float util) {
  char oui[9]; getOui(bssid, oui);
  for (int i = 0; i < fpCount; i++) {
    char bssidHex[13];
    snprintf(bssidHex, 13, "%02X%02X%02X%02X%02X%02X", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    if (fpDB[i].active && strstr(fpDB[i].id, bssidHex) != NULL) {
      fpDB[i].avgRssi = (fpDB[i].avgRssi + rssi) / 2;
      fpDB[i].lastChannel = ch;
      strncpy(fpDB[i].ssid, ssid, 32);
      if (wpa3) fpDB[i].isWPA3 = true;
      if (wifi6) fpDB[i].isWifi6 = true;
      if (mesh) fpDB[i].isMesh = true;
      if (bw > fpDB[i].bandwidthMbps) fpDB[i].bandwidthMbps = bw;
      if (cc > fpDB[i].clientCount) fpDB[i].clientCount = cc;
      if (rand) fpDB[i].isRandomized = true;
      if (transition) fpDB[i].isWPA3Transition = true;
      if (wpsPin > 0) fpDB[i].wpsPin = wpsPin;
      if (noise < fpDB[i].noiseFloor || fpDB[i].noiseFloor == 0) fpDB[i].noiseFloor = noise;
      if (util > fpDB[i].airtimeUtil) fpDB[i].airtimeUtil = util;
      if (strcmp(ciph, "UNK") != 0) strncpy(fpDB[i].cipherSuite, ciph, 7);
      if (strcmp(auth, "UNK") != 0) strncpy(fpDB[i].authMode, auth, 7);
      fpDB[i].threatScore = score;
      strncpy(fpDB[i].tag, tag, 15);
      return;
    }
  }
  if (fpCount < MAX_FINGERPRINTS) {
    char temp[64];
    snprintf(temp, sizeof(temp), "%s-%02X%02X%02X%02X%02X%02X-%d-%d",
             oui, bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], abs(rssi/10), ch);
    strncpy(fpDB[fpCount].id, temp, 32);
    strncpy(fpDB[fpCount].oui, oui, 8);
    strncpy(fpDB[fpCount].ssid, ssid, 32);
    fpDB[fpCount].avgRssi = rssi; fpDB[fpCount].lastChannel = ch; fpDB[fpCount].handshakeCount = 0;
    fpDB[fpCount].active = true; fpDB[fpCount].isWPA3 = wpa3; fpDB[fpCount].isWifi6 = wifi6; fpDB[fpCount].isMesh = mesh;
    fpDB[fpCount].bandwidthMbps = bw; fpDB[fpCount].clientCount = cc; fpDB[fpCount].isRandomized = rand;
    fpDB[fpCount].isWPA3Transition = transition; fpDB[fpCount].wpsPin = wpsPin;
    fpDB[fpCount].noiseFloor = noise; fpDB[fpCount].airtimeUtil = util;
    strncpy(fpDB[fpCount].cipherSuite, ciph, 7); strncpy(fpDB[fpCount].authMode, auth, 7);
    fpDB[fpCount].threatScore = score; strncpy(fpDB[fpCount].tag, tag, 15);
    fpCount++;
  }
}

// ======================================================
// HANDSHAKE CAPTURE
// ======================================================

void processHandshake(const uint8_t* payload, int len, const uint8_t* bssid, int rssi) {
  if (len < 26) return;
  for (int i = 0; i < len - 2; i++) {
    if (payload[i] == 0x88 && payload[i+1] == 0x8E) {
      int idx = -1;
      for(int k=0; k<hsCount; k++) {
        if (hsTrack[k].state > 0 && macEqual(hsTrack[k].bssid, bssid)) { idx = k; break; }
      }
      if (idx == -1) {
        if (hsCount < MAX_APS) {
          memcpy(hsTrack[hsCount].bssid, bssid, 6);
          hsTrack[hsCount].state = 0; hsTrack[hsCount].captured = false; hsTrack[hsCount].exported = false;
          idx = hsCount++;
        }
      }
      if (idx != -1 && hsTrack[idx].state < 4) {
        hsTrack[idx].state++; hsTrack[idx].lastMsgTime = millis();
        if (hsTrack[idx].state == 4) {
          hsTrack[idx].captured = true;
          exportHandshake(bssid, payload, len);
          for(int k=0; k<fpCount; k++) {
             char bssidHex[13];
             snprintf(bssidHex, 13, "%02X%02X%02X%02X%02X%02X", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
             if (strstr(fpDB[k].id, bssidHex) != NULL) fpDB[k].handshakeCount++;
          }
        }
      }
      return;
    }
  }
}

void exportHandshake(const uint8_t* bssid, const uint8_t* payload, int len) {
  char filename[64]; char bssidStr[18];
  snprintf(bssidStr, 18, "%02X%02X%02X%02X%02X%02X", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
  snprintf(filename, sizeof(filename), "/HS_%s_%lu.cap", bssidStr, millis());

  File hsFile;
  for (int retry = 0; retry < 3; retry++) { hsFile = SD.open(filename, FILE_WRITE); if (hsFile) break; delay(50); }
  if (!hsFile) { Serial.println("[ERROR] Failed to open handshake file after 3 retries"); return; }

  struct PcapGlobalHeader { uint32_t magic_number; uint16_t version_major; uint16_t version_minor; int32_t thiszone; uint32_t sigfigs; uint32_t snaplen; uint32_t network; } hdr = {0xA1B2C3D4, 2, 4, 0, 0, MAX_PACKET_SIZE, 105};
  hsFile.write((uint8_t*)&hdr, sizeof(hdr));
  struct PcapPacketHeader { uint32_t ts_sec; uint32_t ts_usec; uint32_t incl_len; uint32_t orig_len; } phdr = {millis()/1000, (millis()%1000)*1000, (uint32_t)len, (uint32_t)len};
  hsFile.write((uint8_t*)&phdr, sizeof(phdr));
  hsFile.write(payload, len);
  hsFile.flush(); hsFile.close();
  Serial.printf("Exported Handshake/PMKID to %s\n", filename);
  beepHandshake();
}

