// ============================================================
// src/ui.cpp
// ============================================================
#include "ui.h"
#include "helpers.h"
#include "logging.h"
#include "storage.h"
#include "sensors.h"

void updateDisplay() {
  if (silentMode || batterySaverMode) {
    display.clearDisplay();
    display.display();
    return;
  }

  if (showHealthDashboard) {
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0, 0);
    display.println("SYSTEM HEALTH");
    display.drawLine(0, 10, 127, 10, SSD1306_WHITE);

    size_t h = ESP.getFreeHeap();
    size_t p = ESP.getFreePsram();

    display.setCursor(0, 12);
    display.print("Heap: "); display.print(h / 1024); display.println(" KB");
    display.print("PSRAM: "); display.print(p / 1024); display.println(" KB");

    UBaseType_t logLen = uxQueueMessagesWaiting(logQueue);
    UBaseType_t pcapLen = uxQueueMessagesWaiting(pcapQueue);

    display.setCursor(0, 24);
    display.print("LogQ: "); display.println(logLen);
    display.print("PCAP: "); display.println(pcapLen);

    display.setCursor(0, 36);
    display.print("Drops: "); display.println(packetDropCount);
    display.print("Pkts: "); display.println(totalPacketsProcessed);

    display.setCursor(0, 48);
    display.print("Ch: "); display.print(currentChannel);
    display.print("  Bat: "); display.print(batteryPercent, 0); display.println("%");

    display.drawLine(0, 58, 127, 58, SSD1306_WHITE);
    display.setCursor(0, 60);
    display.print("B1:Mode B2:Hop B3:Clr");

    display.display();
    return;
  }

  int topThreat = 0;
  char topTag[16] = "None";
  for(int i=0; i<fpCount; i++) {
    if(fpDB[i].active && fpDB[i].threatScore > topThreat) {
      topThreat = fpDB[i].threatScore;
      strncpy(topTag, fpDB[i].tag, 15);
    }
  }

  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);
  display.println("ESP32-S3 WIDS v4");
  display.drawLine(0, 10, 127, 10, SSD1306_WHITE);

  display.setCursor(0, 12);
  display.print("Ch: "); display.print(currentChannel);
  display.print("  APs: "); display.print(fpCount);
  display.print("  HS: ");
  int completed = 0;
  for(int i=0; i<hsCount; i++) if(hsTrack[i].captured) completed++;
  display.println(completed);

  display.setCursor(0, 22);
  display.print("GPS: ");
  if (gpsFixValid) {
    display.print(currentLat, 4); display.print(","); display.print(currentLon, 4);
    display.print(" ("); display.print(currentSats); display.println("s)");
  } else {
    display.println("SEARCHING...");
  }

  display.setCursor(0, 32);
  display.print("Bat: "); display.print(batteryPercent, 0); display.println("%");
  display.print("Log: "); display.println(loggingEnabled ? "ON" : "OFF");

  display.setCursor(0, 40);
  display.print("Top Threat: "); display.print(topThreat);
  display.print(" ("); display.print(topTag); display.println(")");

  display.setCursor(0, 48);
  display.print("BLE: "); display.println(bleScanning ? "SCAN" : "IDLE");
  display.print("Saver: "); display.println(batterySaverMode ? "ON" : "OFF");

  display.drawLine(0, 58, 127, 58, SSD1306_WHITE);
  display.setCursor(0, 60);
  display.print("B1:Log B2:Hop B3:Rep B4:Hlth");

  display.display();
}

void handleButtons() {
  static unsigned long lastDebounceTime = 0;
  static bool lastBtn1State = HIGH;
  static bool lastBtn2State = HIGH;
  static bool lastBtn3State = HIGH;
  static bool lastBtnPanicState = HIGH;
  static bool lastBtnHealthState = HIGH;
  static unsigned long btn3PressStart = 0;
  static unsigned long btnPanicPressStart = 0;
  const unsigned long debounceDelay = 200;
  const unsigned long GRACEFUL_SHUTDOWN_TIME = 3000;
  const unsigned long BATTERY_SAVER_TRIGGER_TIME = 5000;

  bool btn1 = digitalRead(BTN_LOG);
  bool btn2 = digitalRead(BTN_HOP);
  bool btn3 = digitalRead(BTN_CLEAR);
  bool btnPanic = digitalRead(BTN_PANIC);
  bool btnHealth = digitalRead(BTN_HEALTH);

  unsigned long currentTime = millis();

  if (btn1 != lastBtn1State) lastDebounceTime = currentTime;
  if ((currentTime - lastDebounceTime) > debounceDelay) {
    if (btn1 == LOW && lastBtn1State == HIGH) {
      loggingEnabled = !loggingEnabled;
      playTone(loggingEnabled ? 1500 : 800, 100);
      Serial.println(loggingEnabled ? "Logging ON" : "Logging OFF");
    }
  }
  lastBtn1State = btn1;

  if (btn2 != lastBtn2State) lastDebounceTime = currentTime;
  if ((currentTime - lastDebounceTime) > debounceDelay) {
    if (btn2 == LOW && lastBtn2State == HIGH) {
      forceHop();
      playTone(1200, 50);
    }
  }
  lastBtn2State = btn2;

  if (btn3 != lastBtn3State) lastDebounceTime = currentTime;
  if ((currentTime - lastDebounceTime) > debounceDelay) {
    if (btn3 == LOW && lastBtn3State == HIGH) {
      btn3PressStart = currentTime;
    } else if (btn3 == HIGH && lastBtn3State == LOW) {
      unsigned long pressDuration = currentTime - btn3PressStart;

      if (pressDuration > 8000) {
        Serial.println("GRACEFUL SHUTDOWN: Flushing files...");
        if (logFile) { logFile.flush(); }
        if (pcapFile) { pcapFile.flush(); }
        saveFingerprints();
        delay(1000);
        ESP.restart();
      } else if (pressDuration > BATTERY_SAVER_TRIGGER_TIME) {
        batterySaverMode = !batterySaverMode;
        if (batterySaverMode) {
          Serial.println("BATTERY SAVER: ON");
          silentMode = true;
          display.clearDisplay();
          display.display();
          currentDwellTime = BATTERY_SAVER_DWELL;
        } else {
          Serial.println("BATTERY SAVER: OFF");
          silentMode = false;
          currentDwellTime = MIN_DWELL_TIME_MS;
        }
        playTone(batterySaverMode ? 2000 : 1000, 300);
      } else {
        generateHTMLReport();
        playTone(1800, 200); delay(200); playTone(1800, 200);
        Serial.println("HTML Report Generated");
      }
    }
  }
  lastBtn3State = btn3;

  if (btnPanic != lastBtnPanicState) lastDebounceTime = currentTime;
  if ((currentTime - lastDebounceTime) > debounceDelay) {
    if (btnPanic == LOW && lastBtnPanicState == HIGH) {
      btnPanicPressStart = currentTime;
    } else if (btnPanic == HIGH && lastBtnPanicState == LOW) {
      if (currentTime - btnPanicPressStart > GRACEFUL_SHUTDOWN_TIME) {
        Serial.println("GRACEFUL SHUTDOWN: Flushing files...");
        if (logFile) { logFile.flush(); }
        if (pcapFile) { pcapFile.flush(); }
        saveFingerprints();
        delay(1000);
        ESP.restart();
      } else {
        Serial.println("PANIC: Wiping SD...");
        File root = SD.open("/");
        File file = root.openNextFile();
        while(file){
          String name = file.name();
          file.close();
          SD.remove(name.c_str());
          file = root.openNextFile();
        }
        root.close();
        playTone(4000, 500);
        delay(1000);
        ESP.restart();
      }
    }
  }
  lastBtnPanicState = btnPanic;

  if (btnHealth != lastBtnHealthState) lastDebounceTime = currentTime;
  if ((currentTime - lastDebounceTime) > debounceDelay) {
    if (btnHealth == LOW && lastBtnHealthState == HIGH) {
      showHealthDashboard = !showHealthDashboard;
      playTone(showHealthDashboard ? 2500 : 1000, 100);
      Serial.println(showHealthDashboard ? "Health Dashboard ON" : "Health Dashboard OFF");
    }
  }
  lastBtnHealthState = btnHealth;
}
