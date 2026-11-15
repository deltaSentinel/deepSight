// ===================== globals.h =====================
#pragma once
#include "config.h"
#include <SD.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <RTClib.h>
#include <TinyGPS++.h>
#include <NimBLEDevice.h>

// ---- FreeRTOS objects ----
extern QueueHandle_t packetQueue;
extern QueueHandle_t logQueue;
extern QueueHandle_t pcapQueue;

extern TaskHandle_t xProcTaskHandle;
extern TaskHandle_t xLogTaskHandle;
extern TaskHandle_t xPcapTaskHandle;
extern TaskHandle_t xCleanupTaskHandle;

extern SemaphoreHandle_t apMutex;
extern SemaphoreHandle_t clientMutex;
extern SemaphoreHandle_t channelMutex;
extern SemaphoreHandle_t gpsMutex;
extern SemaphoreHandle_t fpMutex;
extern SemaphoreHandle_t bleMutex;
extern SemaphoreHandle_t filterMutex;
extern SemaphoreHandle_t ouiMutex;
extern SemaphoreHandle_t knownDevMutex;
extern SemaphoreHandle_t karmaMutex;

// ---- Files ----
extern File logFile;
extern File pcapFile;
extern File fpFile;
extern File configFile;
extern File ouiFile;
extern File knownDevFile;
extern File vendorAliasFile;

extern uint32_t currentLogIndex;
extern uint32_t currentPcapIndex;

// ---- Counters & runtime state ----
extern volatile uint32_t packetDropCount;
extern volatile uint32_t queueOverflowCount;
extern volatile uint32_t totalPacketsProcessed;
extern volatile uint32_t lastPacketTime;

extern volatile int currentChannel;
extern unsigned long lastChannelSwitch;
extern volatile int channelActivityCount;
extern volatile int currentDwellTime;

extern bool sdInitialized;
extern bool loggingEnabled;
extern bool silentMode;
extern bool deepSleepEnabled;
extern bool gpsLockAcquired;
extern bool showHealthDashboard;
extern bool batterySaverMode;
extern float batteryVoltage;
extern float batteryPercent;

extern unsigned long lastLogTimeByAP[MAX_APS];
extern int lastRssiByAP[MAX_APS];

// ---- Databases & lookup tables ----
extern FilterEntry filters[64];
extern int filterCount;
extern bool whitelistMode;
extern OuiEntry ouiDatabase[MAX_OUI_ENTRIES];
extern int ouiCount;
extern bool ouiLoaded;
extern KnownDevice knownDevices[MAX_KNOWN_DEVS];
extern int knownDeviceCount;
extern VendorAlias vendorAliases[100];
extern int aliasCount;
extern KarmaTracker* karmaDB;
extern AnomalyTracker* anomalyDB;
extern ClientMapEntry* clientMap;
extern ChannelStats* channelStats;

// ---- Sensors & peripherals ----
extern TinyGPSPlus gps;
extern HardwareSerial GPSSerial;
extern float currentLat, currentLon, currentAlt;
extern int currentSats;
extern bool gpsFixValid;
extern RTC_DS3231 rtc;
extern bool rtcFound;
extern bool bleScanning;
extern NimBLEScan* pBLEScan;
extern Adafruit_SSD1306 display;

// ---- Core data structures (PSRAM-allocated) ----
extern FingerprintDB* fpDB;
extern int fpCount;
extern bool fpLoaded;
extern HandshakeTracker* hsTrack;
extern int hsCount;
extern BLEDeviceCache* bleCache;
extern int bleCount;
extern AccessPoint* aps;
extern StationClient* clients;
extern PacketBuffer* packetPool;

