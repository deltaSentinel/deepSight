// ============================================================
// src/sensors.cpp
// ============================================================
#include "sensors.h"
#include "helpers.h"
#include "logging.h"

// ======================================================
// CHANNEL HOPPING
// ======================================================

void updateChannelActivity() { channelActivityCount++; lastPacketTime = millis(); }

void forceHop() {
  xSemaphoreTake(channelMutex, portMAX_DELAY);
  currentChannel++;
  if (currentChannel > WIFI_CHANNEL_END) currentChannel = WIFI_CHANNEL_START;
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  channelActivityCount = 0; lastChannelSwitch = millis();
  xSemaphoreGive(channelMutex);
}

void handleChannelHopping() {
  unsigned long now = millis();
  if (now - lastChannelSwitch < currentDwellTime) return;
  if (channelActivityCount > QUIET_THRESHOLD * 2) currentDwellTime = MAX_DWELL_TIME_MS;
  else if (channelActivityCount < QUIET_THRESHOLD) currentDwellTime = MIN_DWELL_TIME_MS;
  else currentDwellTime = MIN_DWELL_TIME_MS + (channelActivityCount * 50);
  if (batterySaverMode) currentDwellTime = BATTERY_SAVER_DWELL;

  xSemaphoreTake(channelMutex, portMAX_DELAY);
  currentChannel++;
  if (currentChannel > WIFI_CHANNEL_END) currentChannel = WIFI_CHANNEL_START;
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  channelActivityCount = 0; lastChannelSwitch = millis();
  xSemaphoreGive(channelMutex);
}

// ======================================================
// GPS
// ======================================================

void initGPS() { GPSSerial.begin(GPS_BAUD, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN); }

void updateGPS() {
  unsigned long now = millis();
  static unsigned long lastGPSPoll = 0;
  unsigned long pollInterval = batterySaverMode ? BATTERY_SAVER_GPS_INTERVAL : 1000;
  if (now - lastGPSPoll < pollInterval) return;
  lastGPSPoll = now;
  while (GPSSerial.available() > 0) gps.encode(GPSSerial.read());
  xSemaphoreTake(gpsMutex, portMAX_DELAY);
  if (gps.location.isUpdated() && gps.location.isValid()) {
    currentLat = gps.location.lat(); currentLon = gps.location.lng(); gpsFixValid = true;
    if (!gpsLockAcquired) {
      gpsLockAcquired = true;
      if (!batterySaverMode) beepGPS();
      if (rtcFound && gps.date.isValid()) {
        rtc.adjust(DateTime(gps.date.year(), gps.date.month(), gps.date.day(), gps.time.hour(), gps.time.minute(), gps.time.second()));
      }
    }
  }
  if (gps.altitude.isUpdated()) currentAlt = gps.altitude.meters();
  if (gps.satellites.isUpdated()) currentSats = gps.satellites.value();
  xSemaphoreGive(gpsMutex);
}

// ======================================================
// BLE
// ======================================================

class MyScanCallbacks : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* dev) override {
    std::string addrStr = dev->getAddress().toString();
    int rssi = dev->getRSSI();
    std::string name = dev->getName();
    std::string manuf = dev->getManufacturerData();
    uint8_t mac[6];
    if (addrStr.length() == 17) { for (int i = 0; i < 6; i++) mac[i] = (uint8_t)strtol(addrStr.substr(i * 3, 2).c_str(), NULL, 16); }
    else { memset(mac, 0, 6); }
    char uuid[37] = ""; uint16_t major = 0, minor = 0; bool isRandomized = false;
    if (manuf.length() >= 25 && manuf[0] == 0x4C && manuf[1] == 0x00) {
      snprintf(uuid, 36, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
               manuf[2], manuf[3], manuf[4], manuf[5], manuf[6], manuf[7], manuf[8], manuf[9],
               manuf[10], manuf[11], manuf[12], manuf[13], manuf[14], manuf[15], manuf[16], manuf[17]);
      major = manuf[18] | (manuf[19] << 8); minor = manuf[20] | (manuf[21] << 8);
    }
    if (mac[0] & 0x02) isRandomized = true;
    int idx = -1;
    for (int i = 0; i < bleCount; i++) { if (bleCache[i].active && macEqual(bleCache[i].mac, mac)) { idx = i; break; } }
    if (idx == -1 && bleCount < 32) { idx = bleCount++; memcpy(bleCache[idx].mac, mac, 6); bleCache[idx].active = true; bleCache[idx].isRandomized = isRandomized; }
    if (idx != -1) {
      bleCache[idx].rssi = rssi; strncpy(bleCache[idx].name, name.c_str(), 31); strncpy(bleCache[idx].uuid, uuid, 36);
      bleCache[idx].major = major; bleCache[idx].minor = minor; bleCache[idx].lastSeen = millis();
      if (strlen(uuid) > 0) { char data[150]; snprintf(data, sizeof(data), "iBeacon:UUID=%s,Maj=%d,Min=%d,RSSI=%d", uuid, major, minor, rssi); enqueueLog("BLE", "IBEACON", data, rssi, 0); }
      else if (name.length() > 0) { char data[150]; snprintf(data, sizeof(data), "Name=%s,RSSI=%d,Random=%d", name.c_str(), rssi, isRandomized); enqueueLog("BLE", "BEACON", data, rssi, 0); }
    }
  }
  void onScanEnd(const NimBLEScanResults& results, int reason) override { 
	  (void)results; (void)reason;
	  bleScanning = false; }
};

void initBLE() {
  NimBLEDevice::init("ESP32-S3-WIDS");
  pBLEScan = NimBLEDevice::getScan();
  pBLEScan->setScanCallbacks(new MyScanCallbacks());
  pBLEScan->setInterval(BLE_SCAN_INTERVAL); pBLEScan->setWindow(BLE_SCAN_WINDOW); pBLEScan->setActiveScan(true);
  Serial.println("BLE INIT OK");
}

void startBLEScan() { if (bleScanning) return; bleScanning = true; pBLEScan->start(batterySaverMode ? 2000 : BLE_SCAN_DURATION, false); }

