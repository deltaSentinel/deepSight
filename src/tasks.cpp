// ============================================================
// src/tasks.cpp
// ============================================================
#include "tasks.h"
#include "detect.h"
#include "helpers.h"

void cleanupTask(void* param) {
  xCleanupTaskHandle = xTaskGetCurrentTaskHandle();
  while (true) {
    unsigned long now = millis();
    // Clean up stale APs
    for (int i = 0; i < MAX_APS; i++) {
      if (aps[i].active && (now - aps[i].lastSeen > FORGET_TIME)) aps[i].active = false;
    }
    // Clean up stale clients
    for (int i = 0; i < MAX_CLIENTS; i++) {
      if (clients[i].active && (now - clients[i].lastSeen > FORGET_TIME)) clients[i].active = false;
    }
    // Clean up stale client map entries
    if (clientMap) {
      for (int i = 0; i < MAX_CLIENT_MAP; i++) {
        if (clientMap[i].active && (now - clientMap[i].lastSeen > FORGET_TIME * 2)) clientMap[i].active = false;
      }
    }
    checkKarmaAttack();

    unsigned long sleepTimeout = batterySaverMode ? BATTERY_SAVER_SLEEP_TIMEOUT : SLEEP_TIMEOUT;

    if (deepSleepEnabled && (now - lastPacketTime > sleepTimeout)) {
       Serial.println("No activity. Entering Deep Sleep...");
       display.clearDisplay();
       display.display();
       digitalWrite(BUZZER_PIN, LOW);
       esp_sleep_enable_ext0_wakeup((gpio_num_t)DEEP_SLEEP_WAKE_PIN, LOW);
       esp_deep_sleep_start();
    }

    vTaskDelay(pdMS_TO_TICKS(5000));
  }
}

void healthTask(void* param) {
  xLogTaskHandle = xTaskGetCurrentTaskHandle();
  while (true) {
    size_t h = ESP.getFreeHeap();
    size_t p = ESP.getFreePsram();
    if (h < MIN_FREE_HEAP || p < MIN_FREE_PSRAM) {
      char buf[64];
      snprintf(buf, sizeof(buf), "[CRITICAL] Low Memory: Heap=%zu, PSRAM=%zu. Restarting...\n", h, p);
      Serial.print(buf);
      ESP.restart();
    }

    if (xProcTaskHandle) {
      UBaseType_t stackProc = uxTaskGetStackHighWaterMark(xProcTaskHandle);
      if (stackProc < MIN_STACK_WATERMARK) Serial.printf("[WARN] Proc Stack Low: %u\n", stackProc);
    }
    if (xLogTaskHandle) {
      UBaseType_t stackLog = uxTaskGetStackHighWaterMark(xLogTaskHandle);
      if (stackLog < MIN_STACK_WATERMARK) Serial.printf("[WARN] Log Stack Low: %u\n", stackLog);
    }

    UBaseType_t logLen = uxQueueMessagesWaiting(logQueue);
    UBaseType_t pcapLen = uxQueueMessagesWaiting(pcapQueue);
    if (logLen > 200 || pcapLen > 100) {
      Serial.printf("[WARN] Queue Backlog: Log=%u, PCAP=%u\n", logLen, pcapLen);
      backlogDwellHops = BACKLOG_MAX_DWELL_HOPS;
    }

    vTaskDelay(pdMS_TO_TICKS(5000));
  }
}
