// ============================================================
// src/main.cpp — setup() & loop()
// ============================================================
#include "globals.h"
#include "helpers.h"
#include "storage.h"
#include "detect.h"
#include "logging.h"
#include "sensors.h"
#include "packets.h"
#include "ui.h"
#include "tasks.h"
#include <esp_task_wdt.h>

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n=== ESP32-S3 WIDS v4.0 Deep Sight ===");

  pinMode(BTN_LOG, INPUT_PULLUP);
  pinMode(BTN_HOP, INPUT_PULLUP);
  pinMode(BTN_CLEAR, INPUT_PULLUP);
  pinMode(BTN_PANIC, INPUT_PULLUP);
  pinMode(BTN_HEALTH, INPUT_PULLUP);
  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(BAT_ADC_PIN, INPUT);

  if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println("OLED Init Failed");
  } else {
    display.clearDisplay();
    display.println("Init...");
    display.display();
  }

  Wire.begin(OLED_SDA, OLED_SCL);
  if (rtc.begin()) {
    if (rtc.lostPower()) {
      rtc.adjust(DateTime(F(__DATE__), F(__TIME__)));
      Serial.println("RTC Time Set from Compile Time");
    }
    rtcFound = true;
    Serial.println("RTC Found and Initialized");
  } else {
    Serial.println("RTC ERROR: Could not find DS3231");
  }

  // --- PSRAM ALLOCATION ---
  Serial.println("Allocating PSRAM buffers...");
  packetPool = (PacketBuffer*)ps_malloc(sizeof(PacketBuffer) * PACKET_POOL_SIZE);
  aps = (AccessPoint*)ps_malloc(sizeof(AccessPoint) * MAX_APS);
  clients = (StationClient*)ps_malloc(sizeof(StationClient) * MAX_CLIENTS);
  fpDB = (FingerprintDB*)ps_malloc(sizeof(FingerprintDB) * MAX_FINGERPRINTS);
  hsTrack = (HandshakeTracker*)ps_malloc(sizeof(HandshakeTracker) * MAX_APS);
  bleCache = (BLEDeviceCache*)ps_malloc(sizeof(BLEDeviceCache) * 32);
  karmaDB = (KarmaTracker*)ps_malloc(sizeof(KarmaTracker) * 32);
  anomalyDB = (AnomalyTracker*)ps_malloc(sizeof(AnomalyTracker) * 32);

  // Client Map and Channel Stats
  clientMap = (ClientMapEntry*)ps_malloc(sizeof(ClientMapEntry) * MAX_CLIENT_MAP);
  channelStats = (ChannelStats*)ps_malloc(sizeof(ChannelStats) * 14); // Channels 1-13

  if (!packetPool || !aps || !clients || !fpDB || !hsTrack || !bleCache || !karmaDB || !anomalyDB || !clientMap || !channelStats) {
    Serial.println("FAIL: PSRAM Allocation");
    while(1);
  }
  Serial.println("OK: All buffers allocated");

  memset(lastLogTimeByAP, 0, sizeof(lastLogTimeByAP));
  memset(lastRssiByAP, 0, sizeof(lastRssiByAP));
  memset(clientMap, 0, sizeof(ClientMapEntry) * MAX_CLIENT_MAP);
  memset(channelStats, 0, sizeof(ChannelStats) * 14);

  // --- STABILITY: WDT Configuration ---
  esp_task_wdt_config_t wdt_config = {
    .timeout_ms = 10000,      // 10 seconds timeout
    .idle_core_mask = 0,      // Watch all cores (0 means all)
    .trigger_panic = true     // Trigger panic on timeout
  };
  esp_task_wdt_init(&wdt_config);
  esp_task_wdt_add(NULL); // Add current task to the watchdog

  // --- STABILITY: WiFi Optimization ---
  WiFi.disconnect(true);
  WiFi.mode(WIFI_MODE_STA);
  WiFi.config(INADDR_NONE, INADDR_NONE, INADDR_NONE);

  initGPS();
  initSD();
  initBLE();

  packetQueue = xQueueCreate(PACKET_QUEUE_SIZE, sizeof(PacketBuffer*));
  logQueue = xQueueCreate(LOG_QUEUE_SIZE, sizeof(LogMessage));
  pcapQueue = xQueueCreate(PCAP_QUEUE_SIZE, sizeof(PcapPacket));

  apMutex = xSemaphoreCreateMutex();
  clientMutex = xSemaphoreCreateMutex();
  channelMutex = xSemaphoreCreateMutex();
  gpsMutex = xSemaphoreCreateMutex();
  fpMutex = xSemaphoreCreateMutex();
  bleMutex = xSemaphoreCreateMutex();
  filterMutex = xSemaphoreCreateMutex();
  ouiMutex = xSemaphoreCreateMutex();
  knownDevMutex = xSemaphoreCreateMutex();
  karmaMutex = xSemaphoreCreateMutex();

  installPromiscuousMode();

  xTaskCreatePinnedToCore(packetProcessorTask, "proc", 8192, NULL, 3, &xProcTaskHandle, 1);
  xTaskCreatePinnedToCore(cleanupTask, "clean", 8192, NULL, 1, &xCleanupTaskHandle, 0);
  xTaskCreatePinnedToCore(logWriterTask, "log", 8192, NULL, 1, &xLogTaskHandle, 0);
  xTaskCreatePinnedToCore(pcapWriterTask, "pcap", 8192, NULL, 1, NULL, 0);
  xTaskCreatePinnedToCore(healthTask, "health", 4096, NULL, 1, NULL, 0);

  Serial.println("System Ready.");
  playTone(1000, 200); delay(200); playTone(1500, 200);
}

void loop() {
  updateGPS();
  handleChannelHopping();
  handleButtons();

  static unsigned long lastBLEScan = 0;
  unsigned long scanInterval = batterySaverMode ? BATTERY_SAVER_BLE_INTERVAL : 10000;

  if (millis() - lastBLEScan > scanInterval) {
    if (!bleScanning) {
      startBLEScan();
      lastBLEScan = millis();
    }
  }

  static unsigned long lastDisplayUpdate = 0;
  if (millis() - lastDisplayUpdate > 1000) {
    readBattery();
    updateDisplay();
    lastDisplayUpdate = millis();
  }

  yield();
  vTaskDelay(pdMS_TO_TICKS(50));
}
