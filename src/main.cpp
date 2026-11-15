// ===================== main.cpp =====================
#include "globals.h"
#include "packets.h"
#include "logging.h"
#include "fingerprints.h"
#include "sensors.h"
#include "ui.h"
#include "cleanup.h"

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

  uiInit();          // display.begin + initial "Init..." splash
  sensorsInit();     // Wire, RTC, GPS, SD, BLE

  // --- PSRAM allocation (unchanged from your sketch) ---
  packetPool = (PacketBuffer*)ps_malloc(sizeof(PacketBuffer) * PACKET_POOL_SIZE);
  aps = (AccessPoint*)ps_malloc(sizeof(AccessPoint) * MAX_APS);
  clients = (StationClient*)ps_malloc(sizeof(StationClient) * MAX_CLIENTS);
  fpDB = (FingerprintDB*)ps_malloc(sizeof(FingerprintDB) * MAX_FINGERPRINTS);
  hsTrack = (HandshakeTracker*)ps_malloc(sizeof(HandshakeTracker) * MAX_APS);
  bleCache = (BLEDeviceCache*)ps_malloc(sizeof(BLEDeviceCache) * 32);
  karmaDB = (KarmaTracker*)ps_malloc(sizeof(KarmaTracker) * 32);
  anomalyDB = (AnomalyTracker*)ps_malloc(sizeof(AnomalyTracker) * 32);
  clientMap = (ClientMapEntry*)ps_malloc(sizeof(ClientMapEntry) * MAX_CLIENT_MAP);
  channelStats = (ChannelStats*)ps_malloc(sizeof(ChannelStats) * 14);
  if (!packetPool || !aps || !clients || !fpDB || !hsTrack || !bleCache ||
      !karmaDB || !anomalyDB || !clientMap || !channelStats) {
    Serial.println("FAIL: PSRAM Allocation");
    while(1);
  }
  Serial.println("OK: All buffers allocated");

  memset(lastLogTimeByAP, 0, sizeof(lastLogTimeByAP));
  memset(lastRssiByAP, 0, sizeof(lastRssiByAP));
  memset(clientMap, 0, sizeof(ClientMapEntry) * MAX_CLIENT_MAP);
  memset(channelStats, 0, sizeof(ChannelStats) * 14);

  // --- WDT ---
  esp_task_wdt_config_t wdt_config = {
    .timeout_ms = 10000,
    .idle_core_mask = 0,
    .trigger_panic = true
  };
  esp_task_wdt_init(&wdt_config);
  esp_task_wdt_add(NULL);

  // --- WiFi ---
  WiFi.disconnect(true);
  WiFi.mode(WIFI_MODE_STA);
  WiFi.config(INADDR_NONE, INADDR_NONE, INADDR_NONE);

  // --- Queues & mutexes ---
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

  fingerprintsLoad();   // load saved fingerprints from SD

  // --- Promiscuous mode (unchanged) ---
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_channel(WIFI_CHANNEL_START, WIFI_SECOND_CHAN_NONE);
  wifi_promiscuous_filter_t filter = {0};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb([](void* buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t* raw = (wifi_promiscuous_pkt_t*)buf;
    if (raw->rx_ctrl.sig_len > MAX_PACKET_SIZE) return;
    PacketBuffer* pkt = nullptr;
    for (int i = 0; i < PACKET_POOL_SIZE; i++) {
      if (!packetPool[i].used) { pkt = &packetPool[i]; break; }
    }
    if (!pkt) { packetDropCount++; return; }
    pkt->used = true;
    memcpy(pkt->payload, raw->payload, raw->rx_ctrl.sig_len);
    pkt->length = raw->rx_ctrl.sig_len;
    pkt->rssi = raw->rx_ctrl.rssi;
    pkt->channel = raw->rx_ctrl.channel;
    pkt->type = type;
    enqueuePcap(raw->payload, raw->rx_ctrl.sig_len);
    BaseType_t res = xQueueSend(packetQueue, &pkt, 0);
    if (res != pdTRUE) { pkt->used = false; packetDropCount++; }
  });
  esp_wifi_set_promiscuous(true);

  // --- Tasks ---
  xTaskCreatePinnedToCore(packetProcessorTask, "proc",   8192, NULL, 3, &xProcTaskHandle, 1);
  xTaskCreatePinnedToCore(cleanupTask,         "clean",  8192, NULL, 1, &xCleanupTaskHandle, 0);
  xTaskCreatePinnedToCore(logWriterTask,       "log",    8192, NULL, 1, &xLogTaskHandle, 0);
  xTaskCreatePinnedToCore(pcapWriterTask,      "pcap",   8192, NULL, 1, NULL, 0);
  xTaskCreatePinnedToCore(healthTask,          "health", 4096, NULL, 1, NULL, 0);

  Serial.println("System Ready.");
  playTone(1000, 200); delay(200); playTone(1500, 200);
}

void loop() {
  sensorsUpdate();     // GPS polling, battery, BLE scan scheduling
  uiUpdate();          // channel hopping, buttons, display refresh

  yield();
  vTaskDelay(pdMS_TO_TICKS(50));
}

