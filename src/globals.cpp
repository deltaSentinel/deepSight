// ===================== globals.cpp =====================
#include "globals.h"

// Structs live as extern pointers, allocated in PSRAM during setup()
PacketBuffer* packetPool = nullptr;
AccessPoint*  aps = nullptr;
StationClient* clients = nullptr;
FingerprintDB* fpDB = nullptr;
HandshakeTracker* hsTrack = nullptr;
BLEDeviceCache* bleCache = nullptr;
KarmaTracker* karmaDB = nullptr;
AnomalyTracker* anomalyDB = nullptr;
ClientMapEntry* clientMap = nullptr;
ChannelStats* channelStats = nullptr;

int fpCount = 0;
int hsCount = 0;

volatile bool loggingEnabled = false;
volatile bool silentMode = false;
volatile bool batterySaverMode = false;
volatile bool deepSleepEnabled = false;
volatile bool showHealthDashboard = false;
volatile bool bleScanning = false;
volatile bool gpsFixValid = false;
float currentLat = 0.0f, currentLon = 0.0f;
int currentSats = 0;
int currentChannel = WIFI_CHANNEL_START;
unsigned long currentDwellTime = MIN_DWELL_TIME_MS;
unsigned long lastPacketTime = 0;
uint32_t totalPacketsProcessed = 0;
uint32_t packetDropCount = 0;
int batteryPercent = 0;
bool rtcFound = false;

// Fill in your actual array sizes; lastLogTimeByAP/lastRssiByAP sized by MAX_APS
unsigned long lastLogTimeByAP[MAX_APS];
int lastRssiByAP[MAX_APS];

QueueHandle_t packetQueue = nullptr;
QueueHandle_t logQueue = nullptr;
QueueHandle_t pcapQueue = nullptr;

SemaphoreHandle_t apMutex = nullptr;
SemaphoreHandle_t clientMutex = nullptr;
SemaphoreHandle_t channelMutex = nullptr;
SemaphoreHandle_t gpsMutex = nullptr;
SemaphoreHandle_t fpMutex = nullptr;
SemaphoreHandle_t bleMutex = nullptr;
SemaphoreHandle_t filterMutex = nullptr;
SemaphoreHandle_t ouiMutex = nullptr;
SemaphoreHandle_t knownDevMutex = nullptr;
SemaphoreHandle_t karmaMutex = nullptr;

TaskHandle_t xProcTaskHandle = nullptr;
TaskHandle_t xCleanupTaskHandle = nullptr;
TaskHandle_t xLogTaskHandle = nullptr;

Adafruit_SSD1306 display(128, 64, &Wire, -1);  // match your constructor
RTC_DS3231 rtc;
File logFile;
File pcapFile;

