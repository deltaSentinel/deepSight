// ===================== globals.h =====================
#pragma once
#include "config.h"

// ---- Structs (copy your full definitions here) ----
struct PacketBuffer {
  bool used;
  uint16_t length;
  int8_t rssi;
  uint8_t channel;
  uint8_t type;
  uint8_t payload[MAX_PACKET_SIZE];
};

struct AccessPoint { /* ...your fields... */ bool active; uint8_t bssid[6]; char ssid[33]; unsigned long lastSeen; int threatScore; };
struct StationClient { bool active; uint8_t mac[6]; int8_t rssi; unsigned long lastSeen; };
struct FingerprintDB { bool active; char id[16]; char ssid[33]; char tag[16]; int threatScore; };
struct HandshakeTracker { bool captured; uint8_t bssid[6]; };
struct BLEDeviceCache { bool active; uint8_t mac[6]; unsigned long lastSeen; };
struct KarmaTracker { bool active; uint8_t mac[6]; unsigned long lastSeen; int requestCount; };
struct AnomalyTracker { bool active; uint8_t mac[6]; int rssiMin, rssiMax; };
struct ClientMapEntry { bool active; uint8_t mac[6]; uint8_t bssid[6]; int8_t rssi; unsigned long lastSeen; };
struct ChannelStats { uint32_t packetCount; };
struct LogMessage { char subsystem[8]; char event[12]; char msg[144]; int8_t rssi; uint8_t channel; };
struct PcapPacket { uint16_t length; int8_t rssi; uint32_t ts_sec, ts_usec; uint8_t payload[MAX_PACKET_SIZE]; };

// ---- Shared data (allocated in PSRAM in setup) ----
extern PacketBuffer* packetPool;
extern AccessPoint*  aps;
extern StationClient* clients;
extern FingerprintDB* fpDB;
extern HandshakeTracker* hsTrack;
extern BLEDeviceCache* bleCache;
extern KarmaTracker* karmaDB;
extern AnomalyTracker* anomalyDB;
extern ClientMapEntry* clientMap;
extern ChannelStats* channelStats;

extern int fpCount;
extern int hsCount;

// ---- Runtime state ----
extern volatile bool loggingEnabled;
extern volatile bool silentMode;
extern volatile bool batterySaverMode;
extern volatile bool deepSleepEnabled;
extern volatile bool showHealthDashboard;
extern volatile bool bleScanning;
extern volatile bool gpsFixValid;
extern float currentLat, currentLon;
extern int currentSats;
extern int currentChannel;
extern unsigned long currentDwellTime;
extern unsigned long lastPacketTime;
extern uint32_t totalPacketsProcessed;
extern uint32_t packetDropCount;
extern int batteryPercent;
extern bool rtcFound;
extern unsigned long lastLogTimeByAP[];
extern int lastRssiByAP[];

// ---- FreeRTOS objects (created once in setup()) ----
extern QueueHandle_t packetQueue;
extern QueueHandle_t logQueue;
extern QueueHandle_t pcapQueue;
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

extern TaskHandle_t xProcTaskHandle;
extern TaskHandle_t xCleanupTaskHandle;
extern TaskHandle_t xLogTaskHandle;

// ---- Hardware objects ----
extern Adafruit_SSD1306 display;
extern RTC_DS3231 rtc;
extern File logFile;
extern File pcapFile;

