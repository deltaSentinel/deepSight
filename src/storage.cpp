// ============================================================
// src/storage.cpp
// ============================================================
#include "storage.h"

void initSD() {
  if (!SD.begin(SD_CS)) {
    Serial.println("SD FAIL: Card not detected or wiring error.");
    Serial.println("Continuing in 'No-Log' mode...");
    sdInitialized = false;
    return;
  }

  Serial.println("SD OK");
  sdInitialized = true;

  // Only load files if SD is working
  loadFilters();
  loadFingerprints();
  loadOuiDatabase();
  loadKnownDevices();
  loadVendorAliases();

  // Initialize file indices
  char tempName[32];
  while (true) {
    snprintf(tempName, sizeof(tempName), "/log_%lu.tmp", (unsigned long)currentLogIndex);
    if (!SD.exists(tempName)) break;
      currentLogIndex++;
}
  while (SD.exists("/capture_" + String(currentPcapIndex) + ".pcap")) currentPcapIndex++;
}

void rotateLogFile() {
  if (!sdInitialized) return; // DO NOTHING if SD failed

  if (logFile) logFile.close();
  char filename[32];
  snprintf(filename, sizeof(filename), "/log_%lu.tmp", (unsigned long)currentLogIndex);

  logFile = SD.open(filename, FILE_WRITE);
  if (!logFile) {
    Serial.println("[ERR] Failed to open log file");
    sdInitialized = false; // Mark as dead if we can't write
    return;
  }
  logFile.println("timestamp,type,event,data,rssi,channel,lat,lon,alt,sats,fp_id,bw_mbps,clients,cipher,auth,random,threat,tag");
}

void rotatePcapFile() {
  if (!sdInitialized) return;

  if (pcapFile) pcapFile.close();
  char filename[32];
  snprintf(filename, sizeof(filename), "/capture_%lu.pcap", (unsigned long)currentPcapIndex++);

  pcapFile = SD.open(filename, FILE_WRITE);
  if (!pcapFile) {
    Serial.println("[ERR] Failed to open pcap file");
    sdInitialized = false;
    return;
  }

  // Write PCAP header
  struct PcapGlobalHeader { uint32_t magic_number; uint16_t version_major; uint16_t version_minor; int32_t thiszone; uint32_t sigfigs; uint32_t snaplen; uint32_t network; } hdr = {0xA1B2C3D4, 2, 4, 0, 0, MAX_PACKET_SIZE, 105};
  pcapFile.write((uint8_t*)&hdr, sizeof(hdr));
  pcapFile.flush();
  Serial.println("PCAP Rotated");
}

void loadFilters() {
  if (!SD.exists(CONFIG_FILE)) return;
  configFile = SD.open(CONFIG_FILE, FILE_READ);
  if (!configFile) return;
  char line[64]; filterCount = 0; whitelistMode = false;
  if (configFile.available()) configFile.readBytesUntil('\n', line, 64);
  while (configFile.available() && filterCount < 64) {
    configFile.readBytesUntil('\n', line, 64);
    if (strlen(line) < 15) continue;
    char bssidStr[18]; char modeChar;
    if (sscanf(line, "%[^,],%c", bssidStr, &modeChar) == 2) {
      uint8_t bssid[6];
      sscanf(bssidStr, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]);
      filters[filterCount].active = true; memcpy(filters[filterCount].bssid, bssid, 6); filters[filterCount].mode = modeChar; filterCount++;
      if (modeChar == 'W') whitelistMode = true;
    }
  }
  configFile.close();
}

void loadOuiDatabase() {
  if (!SD.exists(OUI_FILE)) return;
  ouiFile = SD.open(OUI_FILE, FILE_READ);
  if (!ouiFile) return;
  char line[128]; ouiCount = 0;
  if (ouiFile.available()) ouiFile.readBytesUntil('\n', line, 128);
  while (ouiFile.available() && ouiCount < MAX_OUI_ENTRIES) {
    ouiFile.readBytesUntil('\n', line, 128);
    if (strlen(line) < 8) continue;
    char oui[9], vendor[64];
    if (sscanf(line, "%[^,],%[^,]", oui, vendor) == 2) { strncpy(ouiDatabase[ouiCount].oui, oui, 8); ouiDatabase[ouiCount].oui[8] = '\0'; strncpy(ouiDatabase[ouiCount].vendor, vendor, 63); ouiCount++; }
  }
  ouiFile.close(); ouiLoaded = true;
}

void loadKnownDevices() {
  if (!SD.exists(KNOWN_DEVICES_FILE)) return;
  knownDevFile = SD.open(KNOWN_DEVICES_FILE, FILE_READ);
  if (!knownDevFile) return;
  char line[128]; knownDeviceCount = 0;
  if (knownDevFile.available()) knownDevFile.readBytesUntil('\n', line, 128);
  while (knownDevFile.available() && knownDeviceCount < MAX_KNOWN_DEVS) {
    knownDevFile.readBytesUntil('\n', line, 128);
    if (strlen(line) < 10) continue;
    char macStr[18], type[8], nick[32];
    if (sscanf(line, "%[^,],%[^,],%[^,]", macStr, type, nick) == 3) {
      uint8_t mac[6];
      sscanf(macStr, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
      memcpy(knownDevices[knownDeviceCount].mac, mac, 6); strncpy(knownDevices[knownDeviceCount].type, type, 7); strncpy(knownDevices[knownDeviceCount].nickname, nick, 31); knownDevices[knownDeviceCount].active = true; knownDeviceCount++;
    }
  }
  knownDevFile.close();
}

void loadVendorAliases() {
  if (!SD.exists(VENDOR_ALIASES_FILE)) return;
  vendorAliasFile = SD.open(VENDOR_ALIASES_FILE, FILE_READ);
  if (!vendorAliasFile) return;
  char line[128]; aliasCount = 0;
  if (vendorAliasFile.available()) vendorAliasFile.readBytesUntil('\n', line, 128);
  while (vendorAliasFile.available() && aliasCount < 100) {
    vendorAliasFile.readBytesUntil('\n', line, 128);
    if (strlen(line) < 8) continue;
    char oui[9], alias[64];
    if (sscanf(line, "%[^,],%[^,]", oui, alias) == 2) { strncpy(vendorAliases[aliasCount].oui, oui, 8); ouiDatabase[ouiCount].oui[8] = '\0'; strncpy(vendorAliases[aliasCount].alias, alias, 63); aliasCount++; }
  }
  vendorAliasFile.close();
}

void loadFingerprints() {
  if (!SD.exists(FINGERPRINT_FILE)) return;
  fpFile = SD.open(FINGERPRINT_FILE, FILE_READ);
  if (!fpFile) return;
  char line[200]; fpCount = 0;
  if (fpFile.available()) fpFile.readBytesUntil('\n', line, 200);
  while (fpFile.available() && fpCount < MAX_FINGERPRINTS) {
    fpFile.readBytesUntil('\n', line, 200);
    if (strlen(line) < 10) continue;
    char id[33], oui[9], ssid[33];
    int rssi, ch, hs, ts, wps, nf, cc; float bw, util;
    int tRand, tTrans;
    char ciph[8] = "UNK", auth[8] = "UNK", tag[16] = "General";
    // Extended format with new fields
    if (sscanf(line, "%[^,],%[^,],%[^,],%d,%d,%d,%f,%d,%d,%d,%d,%d,%d,%f,%[^,],%[^,],%d,%[^,]",
               id, oui, ssid, &rssi, &ch, &hs, &bw, &cc, &tRand, &wps, &nf, &ts, &tTrans, &util, ciph, auth, &ts, tag) >= 16) {
    fpDB[fpCount].isRandomized = (tRand != 0);
    fpDB[fpCount].isWPA3Transition = (tTrans != 0);
    }
    else if (sscanf(line, "%[^,],%[^,],%[^,],%d,%d,%d", id, oui, ssid, &rssi, &ch, &hs) == 6) { ts = 0; wps = 0; nf = 0; tTrans = 0; util = 0; bw = 0; cc = 0; tRand = 0; }
    else continue;
    strncpy(fpDB[fpCount].id, id, 32); strncpy(fpDB[fpCount].oui, oui, 8); strncpy(fpDB[fpCount].ssid, ssid, 32);
    fpDB[fpCount].avgRssi = rssi; fpDB[fpCount].lastChannel = ch; fpDB[fpCount].handshakeCount = hs;
    fpDB[fpCount].active = true; fpDB[fpCount].isWPA3 = false; fpDB[fpCount].isWifi6 = false; fpDB[fpCount].isMesh = false;
    fpDB[fpCount].bandwidthMbps = bw; fpDB[fpCount].clientCount = cc; fpDB[fpCount].isRandomized = tRand;
    fpDB[fpCount].wpsPin = wps; fpDB[fpCount].noiseFloor = nf; fpDB[fpCount].isWPA3Transition = tTrans; fpDB[fpCount].airtimeUtil = util;
    strncpy(fpDB[fpCount].cipherSuite, ciph, 7); strncpy(fpDB[fpCount].authMode, auth, 7);
    fpDB[fpCount].threatScore = ts; strncpy(fpDB[fpCount].tag, tag, 15);
    fpCount++;
  }
  fpFile.close(); fpLoaded = true;
}

void saveFingerprints() {
  fpFile = SD.open(FINGERPRINT_FILE, FILE_WRITE);
  if (!fpFile) return;
  fpFile.println("ID,OUI,SSID,AvgRssi,LastCh,HS_Count,BW_Mbps,Clients,Random,WPS_Pin,Noise,Threat,Transition,Airtime,Cipher,Auth,Tag");
  for (int i = 0; i < fpCount; i++) {
    if (fpDB[i].active) {
      fpFile.printf("%s,%s,%s,%d,%d,%d,%.2f,%d,%d,%d,%d,%d,%d,%.2f,%s,%s,%s\n",
              fpDB[i].id, fpDB[i].oui, fpDB[i].ssid,
              fpDB[i].avgRssi, fpDB[i].lastChannel, fpDB[i].handshakeCount,
              fpDB[i].bandwidthMbps, fpDB[i].clientCount, fpDB[i].isRandomized,
              fpDB[i].wpsPin, fpDB[i].noiseFloor, fpDB[i].threatScore,
              fpDB[i].isWPA3Transition ? 1 : 0, fpDB[i].airtimeUtil,
              fpDB[i].cipherSuite, fpDB[i].authMode, fpDB[i].tag);
    }
  }
  fpFile.flush(); fpFile.close();
}
