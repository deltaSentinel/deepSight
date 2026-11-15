// ===================== config.h =====================
// All constants, pins, and struct definitions for Deep Sight WIDS v4.0
#pragma once
#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"

// ======================================================
// CONFIGURATION (verbatim from original sketch)
// ======================================================

#define MAX_PACKET_SIZE                 256
#define WIFI_CHANNEL_START              1
#define WIFI_CHANNEL_END                13
#define MIN_DWELL_TIME_MS               500
#define MAX_DWELL_TIME_MS               3000
#define QUIET_THRESHOLD                 5
#define SLEEP_TIMEOUT                   300000
#define DEEP_SLEEP_WAKE_PIN             5   // Was 47, NOW WORKS (RTC GPIO)

#define SD_CS                           10

#define PACKET_POOL_SIZE                64
#define PACKET_QUEUE_SIZE               128
#define LOG_QUEUE_SIZE                  256
#define PCAP_QUEUE_SIZE                 128
#define LOG_BATCH_SIZE                  16
#define PCAP_BATCH_SIZE                 8
#define LOG_FLUSH_INTERVAL              10000
#define PCAP_FLUSH_INTERVAL             10000
#define LOG_ROTATE_SIZE                 524288
#define PCAP_ROTATE_SIZE                2097152
#define MAX_APS                         64
#define MAX_CLIENTS                      64
#define MAX_CLIENT_MAP                  128
#define FORGET_TIME                     30000
#define RSSI_THRESHOLD                  -85
#define CONFIG_FILE                     "/config.csv"
#define OUI_FILE                        "/ouilist.csv"
#define KNOWN_DEVICES_FILE              "/known_devices.csv"
#define FINGERPRINT_FILE                "/fingerprints.csv"
#define VENDOR_ALIASES_FILE             "/vendor_aliases.csv"
#define KML_OUTPUT_FILE                 "/networks.kml"
#define REPORT_OUTPUT_FILE              "/report.html"
#define MAX_OUI_ENTRIES                 500
#define MAX_KNOWN_DEVS                  100
#define MAX_FINGERPRINTS                100

#define GPS_BAUD                        9600
#define GPS_RX_PIN                      1
#define GPS_TX_PIN                      3   // Was 7

#define BLE_SCAN_DURATION               5000
#define BLE_SCAN_INTERVAL                100
#define BLE_SCAN_WINDOW                 100

#define OLED_SDA                        16  // Was 21, shifted for wiring management
#define OLED_SCL                        17  // Was 22, 22 unavailable on board
#define BTN_LOG                         5   // Was 47, now RTC-safe for deep sleep wake
#define BTN_HOP                         6   // Was 48, moved off JTAG
#define BTN_CLEAR                       7   // Was 46->5, avoid strapping
#define BTN_PANIC                       8   // Was 43, moved off UART0 TX
#define BTN_HEALTH                      9   // Was 44, moved off UART0 RX
#define BUZZER_PIN                      4   // Was 42, moved off JTAG
#define BAT_ADC_PIN                     2

// STABILITY THRESHOLDS
#define MIN_FREE_HEAP                   20000
#define MIN_FREE_PSRAM                  50000
#define MIN_STACK_WATERMARK             2048

// DELTA LOGGING THRESHOLDS
#define DELTA_RSSI_CHANGE               5
#define DELTA_MIN_INTERVAL_MS           30000

// BATTERY SAVER THRESHOLDS
#define BATTERY_SAVER_DWELL             5000
#define BATTERY_SAVER_BLE_INTERVAL      60000
#define BATTERY_SAVER_GPS_INTERVAL      60000
#define BATTERY_SAVER_SLEEP_TIMEOUT     120000

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64

// ======================================================
// STRUCT DEFINITIONS (verbatim)
// ======================================================

struct ClientMapEntry {
  uint8_t clientMac[6];
  uint8_t apBssid[6];
  char ssid[33];
  int rssi;
  unsigned long lastSeen;
  bool active;
};

struct ChannelStats {
  int totalPackets;
  int noiseFloor;
  unsigned long busyTime;
  unsigned long totalTime;
  float utilizationPercent;
};

struct FilterEntry { uint8_t bssid[6]; char mode; bool active; };
struct OuiEntry { char oui[8]; char vendor[64]; };
struct KnownDevice { uint8_t mac[6]; char type[8]; char nickname[32]; bool active; };
struct VendorAlias { char oui[8]; char alias[64]; };
struct KarmaTracker { uint8_t bssid[6]; unsigned long lastProbeReq; unsigned long lastProbeResp; int reqCount; int respCount; bool active; };
struct AnomalyTracker { uint8_t bssid[6]; float avgRssi; int avgPacketsPerSec; unsigned long lastUpdate; bool active; };

struct FingerprintDB {
  char id[33]; char oui[9]; char ssid[33]; int avgRssi; int lastChannel; int handshakeCount;
  bool active; bool isWPA3; bool isWifi6; bool isMesh; float bandwidthMbps; int clientCount;
  bool isRandomized; char cipherSuite[8]; char authMode[8]; int threatScore; char tag[16];
  bool isWPA3Transition;
  int wpsPin;
  int noiseFloor;
  float airtimeUtil;
};

struct HandshakeTracker { uint8_t bssid[6]; uint8_t state; unsigned long lastMsgTime; bool captured; bool exported; };
struct BLEDeviceCache { uint8_t mac[6]; int rssi; uint16_t manufId; char name[32]; char vendor[64]; char uuid[37]; uint16_t major; uint16_t minor; bool isRandomized; unsigned long lastSeen; bool active; };

struct AccessPoint {
  char ssid[33]; uint8_t bssid[6]; int rssi; int channel; bool active; unsigned long lastSeen;
  int packetCount; bool isEvilTwin; bool hasPMKID; bool isWPA3; bool isWifi6; bool isMesh;
  uint64_t bytesReceived; unsigned long lastByteUpdate; float bandwidthMbps; int clientCount;
  bool isRandomized; char cipherSuite[8]; char authMode[8]; uint8_t trackedClients[16][6];
  int trackedClientCount; int threatScore; char tag[16];
  bool isWPA3Transition;
  int wpsPin;
  int noiseFloor;
  float airtimeUtil;
};

struct StationClient { uint8_t mac[6]; int rssi; bool active; unsigned long lastSeen; };
struct PacketBuffer { uint8_t payload[MAX_PACKET_SIZE]; uint16_t length; int8_t rssi; uint8_t channel; wifi_promiscuous_pkt_type_t type; bool used; };
struct LogMessage { char text[350]; };
struct PcapPacket { uint8_t payload[MAX_PACKET_SIZE]; uint16_t length; uint32_t timestampSec; uint32_t timestampUSec; };

