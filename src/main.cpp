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

  // --- PSRAM ALLOCATION (zeroed + per-buffer diagnostics) ---
  Serial.println("Allocating PSRAM buffers...");
  auto psz = [](size_t n, size_t sz) -> void* {
    return heap_caps_calloc(n, sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  };

  bool psramOK = true;
  const char* failName = nullptr;

  auto allocCheck = [&](void* p, const char* name) {
    if (!p) { Serial.printf("FAIL: PSRAM alloc for %-12s (%u bytes)\n", name, (unsigned)0); psramOK = false; failName = name; }
  };

  packetPool = (PacketBuffer*)psz(PACKET_POOL_SIZE, sizeof(PacketBuffer));   allocCheck(packetPool, "packetPool");
  aps        = (AccessPoint*)psz(MAX_APS, sizeof(AccessPoint));              allocCheck(aps, "aps");
  clients    = (StationClient*)psz(MAX_CLIENTS, sizeof(StationClient));      allocCheck(clients, "clients");
  fpDB       = (FingerprintDB*)psz(MAX_FINGERPRINTS, sizeof(FingerprintDB)); allocCheck(fpDB, "fpDB");
  hsTrack    = (HandshakeTracker*)psz(MAX_APS, sizeof(HandshakeTracker));    allocCheck(hsTrack, "hsTrack");
  bleCache   = (BLEDeviceCache*)psz(32, sizeof(BLEDeviceCache));             allocCheck(bleCache, "bleCache");
  karmaDB    = (KarmaTracker*)psz(32, sizeof(KarmaTracker));                 allocCheck(karmaDB, "karmaDB");
  anomalyDB  = (AnomalyTracker*)psz(32, sizeof(AnomalyTracker));             allocCheck(anomalyDB, "anomalyDB");
  clientMap  = (ClientMapEntry*)psz(MAX_CLIENT_MAP, sizeof(ClientMapEntry)); allocCheck(clientMap, "clientMap");
  channelStats = (ChannelStats*)psz(14, sizeof(ChannelStats));               allocCheck(channelStats, "channelStats");

  if (!psramOK) {
    Serial.printf("FAIL: PSRAM allocation — first failure: %s\n", failName);
    while (1) delay(1000);
  }
  Serial.println("OK: All PSRAM buffers allocated and zeroed");

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
    .timeout_ms = 10000,        // 10 seconds timeout
    .idle_core_mask = 0,        // 0 = do NOT watch idle tasks (set (1<<0)|(1<<1) to watch both)
    .trigger_panic = true       // Trigger panic on timeout
  };
  esp_err_t wdt_err = esp_task_wdt_init(&wdt_config);
  if (wdt_err != ESP_OK) {
    Serial.printf("WDT init FAILED: %s — running without watchdog!\n", esp_err_to_name(wdt_err));
  } else {
    esp_err_t add_err = esp_task_wdt_add(NULL); // Subscribe loopTask
    if (add_err != ESP_OK) {
      Serial.printf("WDT subscribe FAILED: %s\n", esp_err_to_name(add_err));
    } else {
      wdtActive = true;
      Serial.println("OK: Task WDT active (loopTask subscribed, 10s)");
    }
  }

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

  auto createTask = [&](TaskFunction_t fn, const char* name, uint32_t stack,
                        UBaseType_t prio, TaskHandle_t* handle, BaseType_t core) {
    if (xTaskCreatePinnedToCore(fn, name, stack, NULL, prio, handle, core) != pdPASS) {
      Serial.printf("FATAL: task creation failed: %s\n", name);
      while (1) delay(1000);
    }
  };
  createTask(packetProcessorTask, "proc",   8192, 3, &xProcTaskHandle,    1);
  createTask(cleanupTask,         "clean",  8192, 1, &xCleanupTaskHandle, 0);
  createTask(logWriterTask,       "log",    8192, 1, &xLogTaskHandle,     0);
  createTask(pcapWriterTask,      "pcap",   8192, 1, nullptr,             0);
  createTask(healthTask,          "health", 4096, 1, nullptr,             0);

  Serial.println("System Ready.");
  playTone(1000, 200); delay(200); playTone(1500, 200);
}

void loop() {
  if (wdtActive) esp_task_wdt_reset(); //BUG [#1] resolution

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
