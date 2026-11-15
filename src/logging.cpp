// ============================================================
// src/logging.cpp
// ============================================================
#include "logging.h"
#include "helpers.h"
#include "storage.h"

void enqueueLog(const char* type, const char* event, const char* data, int rssi, int channel) {
  LogMessage msg;
  float lat, lon, alt; int sats; bool valid;
  xSemaphoreTake(gpsMutex, portMAX_DELAY);
  lat = currentLat; lon = currentLon; alt = currentAlt; sats = currentSats; valid = gpsFixValid;
  xSemaphoreGive(gpsMutex);
  char gpsStr[64];
  if (valid) snprintf(gpsStr, sizeof(gpsStr), "%.6f,%.6f,%.2f,%d", lat, lon, alt, sats);
  else snprintf(gpsStr, sizeof(gpsStr), "0.000000,0.000000,0.00,0");
  char timestamp[32]; getTimestamp(timestamp, sizeof(timestamp));
  snprintf(msg.text, sizeof(msg.text), "%s,%s,%s,%s,%d,%d,%s,UNKNOWN,0.00,0,UNK,UNK,0,0,General", timestamp, type, event, data, rssi, channel, gpsStr);
  if (xQueueSend(logQueue, &msg, 0) != pdTRUE) queueOverflowCount = queueOverflowCount + 1;
}

void enqueueLogAP(const char* type, const char* event, const char* data, int rssi, int channel, float bw, int clients, const char* cipher, const char* auth, bool rand, int threat, const char* tag) {
  LogMessage msg;
  float lat, lon, alt; int sats; bool valid;
  xSemaphoreTake(gpsMutex, portMAX_DELAY);
  lat = currentLat; lon = currentLon; alt = currentAlt; sats = currentSats; valid = gpsFixValid;
  xSemaphoreGive(gpsMutex);
  char gpsStr[64];
  if (valid) snprintf(gpsStr, sizeof(gpsStr), "%.6f,%.6f,%.2f,%d", lat, lon, alt, sats);
  else snprintf(gpsStr, sizeof(gpsStr), "0.000000,0.000000,0.00,0");
  char timestamp[32]; getTimestamp(timestamp, sizeof(timestamp));
  snprintf(msg.text, sizeof(msg.text), "%s,%s,%s,%s,%d,%d,%s,%.2f,%d,%s,%s,%d,%d,%s", timestamp, type, event, data, rssi, channel, gpsStr, bw, clients, cipher, auth, rand ? 1 : 0, threat, tag);
  if (xQueueSend(logQueue, &msg, 0) != pdTRUE) queueOverflowCount = queueOverflowCount + 1;
}

void enqueuePcap(const uint8_t* payload, uint16_t length) {
  if (length > MAX_PACKET_SIZE) return;
  PcapPacket pkt;
  memcpy(pkt.payload, payload, length); pkt.length = length;
  pkt.timestampSec = millis() / 1000; pkt.timestampUSec = (millis() % 1000) * 1000;
  if (xQueueSend(pcapQueue, &pkt, 0) != pdTRUE) queueOverflowCount = queueOverflowCount + 1;
}

void generateKML() {
  if (SD.exists(KML_OUTPUT_FILE)) SD.remove(KML_OUTPUT_FILE);
  File kml = SD.open(KML_OUTPUT_FILE, FILE_WRITE);
  if (!kml) return;
  kml.println("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
  kml.println("<kml xmlns=\"http://www.opengis.net/kml/2.2\">");
  kml.println("<Document><name>ESP32 WIDS Deep Sight Results</name>");
  for (int i = 0; i < fpCount; i++) {
    if (!fpDB[i].active) continue;
    kml.print("<Placemark><name>"); kml.print(fpDB[i].ssid); kml.print("</name><description>");
    kml.print(fpDB[i].id);
    if (fpDB[i].isWPA3) kml.print(" [WPA3]");
    if (fpDB[i].isWPA3Transition) kml.print(" [TRANS]");
    if (fpDB[i].isWifi6) kml.print(" [Wi-Fi 6]");
    if (fpDB[i].isMesh) kml.print(" [Mesh]");
    if (fpDB[i].wpsPin > 0) { kml.print(" [WPS:"); kml.print(fpDB[i].wpsPin); kml.print("]"); }
    kml.print(" | Threat: "); kml.print(fpDB[i].threatScore);
    kml.print(" | Tag: "); kml.print(fpDB[i].tag);
    kml.print("</description><Point><coordinates>-122.4194,37.7749,0</coordinates></Point></Placemark>");
  }
  kml.println("</Document></kml>");
  kml.close();
  Serial.println("KML Generated: /networks.kml");
  if (!batterySaverMode) beepGPS();
}

void generateHTMLReport() {
  if (SD.exists(REPORT_OUTPUT_FILE)) SD.remove(REPORT_OUTPUT_FILE);
  File report = SD.open(REPORT_OUTPUT_FILE, FILE_WRITE);
  if (!report) { Serial.println("[ERROR] Failed to create HTML report"); return; }

  int sortedIndices[MAX_FINGERPRINTS];
  for (int i = 0; i < fpCount; i++) sortedIndices[i] = i;
  for (int i = 0; i < fpCount - 1; i++) {
    for (int j = 0; j < fpCount - i - 1; j++) {
      if (fpDB[sortedIndices[j]].threatScore < fpDB[sortedIndices[j+1]].threatScore) {
        int temp = sortedIndices[j]; sortedIndices[j] = sortedIndices[j+1]; sortedIndices[j+1] = temp;
      }
    }
  }

  report.println("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">");
  report.println("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
  report.println("<title>WIDS Deep Sight Report</title>");
  report.println("<style>body{font-family:Arial,sans-serif;margin:20px;background:#f4f4f4;}");
  report.println("h1{color:#333;}table{width:100%;border-collapse:collapse;background:white;}");
  report.println("th,td{border:1px solid #ddd;padding:8px;text-align:left;}");
  report.println("th{background-color:#4CAF50;color:white;}");
  report.println("tr:nth-child(even){background-color:#f2f2f2;}");
  report.println(".high{color:red;font-weight:bold;}");
  report.println(".med{color:orange;}");
  report.println(".low{color:green;}");
  report.println(".warn{color:blue;}");
  report.println("</style></head><body><h1>Wireless Intelligence Deep Sight Report</h1>");

  char timestamp[32];
  getTimestamp(timestamp, sizeof(timestamp));
  report.print("<p>Generated: "); report.print(timestamp); report.print(" | Total APs: "); report.print(fpCount); report.println("</p>");

  report.println("<table><thead><tr><th>Rank</th><th>SSID</th><th>BSSID</th><th>Tag</th><th>Threat</th><th>Security</th><th>Clients</th><th>WPS</th><th>Noise</th><th>RSSI</th></tr></thead><tbody>");

  for (int i = 0; i < fpCount; i++) {
    int idx = sortedIndices[i];
    if (!fpDB[idx].active) continue;

    report.print("<tr><td>"); report.print(i + 1); report.print("</td><td>"); report.print(fpDB[idx].ssid);
    report.print("</td><td>"); report.print(fpDB[idx].id);
    report.print("</td><td>"); report.print(fpDB[idx].tag);
    report.print("</td><td class=\"");
    if (fpDB[idx].threatScore >= 70) report.print("high\">");
    else if (fpDB[idx].threatScore >= 40) report.print("med\">");
    else report.print("low\">");
    report.print(fpDB[idx].threatScore);
    report.print("</td><td>");
    if (fpDB[idx].isWPA3Transition) report.print("WPA2/3 Mix");
    else if (fpDB[idx].isWPA3) report.print("WPA3");
    else report.print(fpDB[idx].authMode);
    report.print("</td><td>"); report.print(fpDB[idx].clientCount);
    report.print("</td><td>");
    if (fpDB[idx].wpsPin > 0) { report.print(fpDB[idx].wpsPin); report.print(" <span class='warn'>EXPOSED</span>"); }
    else report.print("-");
    report.print("</td><td>"); report.print(fpDB[idx].noiseFloor); report.print(" dBm");
    report.print("</td><td>"); report.print(fpDB[idx].avgRssi); report.println(" dBm</td></tr>");
  }

  report.println("</tbody></table>");
  report.println("<p><a href=\"/log_0.csv\">Download Raw CSV Log</a></p>");
  report.println("</body></html>");

  report.close();
  Serial.println("HTML Report Generated: /report.html");
  beepGPS();
}

// ======================================================
// WRITER TASKS
// ======================================================

void logWriterTask(void* param) {
  rotateLogFile();
  if (!sdInitialized) {
    Serial.println("Log Task: SD not ready. Exiting.");
    vTaskDelete(NULL);
    return;
  }
  LogMessage batch[LOG_BATCH_SIZE]; int batchCount = 0; unsigned long lastFlush = millis();
  while (true) {
    LogMessage msg;
    if (batchCount < LOG_BATCH_SIZE &&
        xQueueReceive(logQueue, &msg, pdMS_TO_TICKS(100)) == pdTRUE) {
      batch[batchCount++] = msg;
    }
    bool flushNow = (batchCount >= LOG_BATCH_SIZE) || (millis() - lastFlush > LOG_FLUSH_INTERVAL);
    if (!flushNow) continue;
    int n = batchCount;
    batchCount = 0;
    lastFlush = millis();
    if (!logFile) continue; // batch dropped, not corrupted
    for (int i = 0; i < n; i++) { logFile.println(batch[i].text); }
    logFile.flush();
    if (logFile.size() > LOG_ROTATE_SIZE) {
      logFile.close();
      String oldName = "/log_" + String(currentLogIndex) + ".tmp";
      String newName = "/log_" + String(currentLogIndex) + ".csv";
      if (SD.rename(oldName, newName)) { currentLogIndex++; rotateLogFile(); Serial.println("Log Rotated (Atomic)"); }
      else Serial.println("[ERROR] Rename failed!");
    }
  }
}

void pcapWriterTask(void* param) {
  rotatePcapFile();
  if (!sdInitialized) {
    Serial.println("PCAP Task: SD not ready. Exiting.");
    vTaskDelete(NULL);
    return;
  }
  PcapPacket batch[PCAP_BATCH_SIZE]; int batchCount = 0; unsigned long lastFlush = millis();
  while (true) {
    PcapPacket pkt;
    if (batchCount < PCAP_BATCH_SIZE &&
        xQueueReceive(pcapQueue, &pkt, pdMS_TO_TICKS(100)) == pdTRUE) {
      batch[batchCount++] = pkt;
    }
    bool flushNow = (batchCount >= PCAP_BATCH_SIZE) || (millis() - lastFlush > PCAP_FLUSH_INTERVAL);
    if (!flushNow) continue;
    int n = batchCount;
    batchCount = 0;
    lastFlush = millis();
    if (!pcapFile) continue; // batch dropped, not corrupted
    for (int i = 0; i < n; i++) {
      struct PcapPacketHeader { uint32_t ts_sec; uint32_t ts_usec; uint32_t incl_len; uint32_t orig_len; } hdr = {batch[i].timestampSec, batch[i].timestampUSec, batch[i].length, batch[i].length};
      pcapFile.write((uint8_t*)&hdr, sizeof(hdr));
      pcapFile.write(batch[i].payload, batch[i].length);
    }
    pcapFile.flush();
    if (pcapFile.size() > PCAP_ROTATE_SIZE) rotatePcapFile();
  }
}
