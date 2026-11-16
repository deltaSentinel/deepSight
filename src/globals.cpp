// ===================== globals.cpp =====================
#include "globals.h"

// ---- FreeRTOS objects ----
QueueHandle_t packetQueue = nullptr;
QueueHandle_t logQueue = nullptr;
QueueHandle_t pcapQueue = nullptr;

TaskHandle_t xProcTaskHandle = nullptr;
TaskHandle_t xLogTaskHandle = nullptr;
TaskHandle_t xPcapTaskHandle = nullptr;
TaskHandle_t xCleanupTaskHandle = nullptr;

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

// ---- Files ----
File logFile;
File pcapFile;
File fpFile;
File configFile;
File ouiFile;
File knownDevFile;
File vendorAliasFile;

uint32_t currentLogIndex = 0;
uint32_t currentPcapIndex = 0;

// ---- Counters & runtime state ----
volatile uint32_t packetDropCount = 0;
volatile uint32_t queueOverflowCount = 0;
volatile uint32_t totalPacketsProcessed = 0;
volatile uint32_t lastPacketTime = 0;

volatile int currentChannel = WIFI_CHANNEL_START;
unsigned long lastChannelSwitch = 0;
volatile int channelActivityCount = 0;
volatile int currentDwellTime = MIN_DWELL_TIME_MS;
volatile int backlogDwellHops = 0;

volatile bool wdtActive = false;
bool sdInitialized = false;
bool loggingEnabled = true;
bool silentMode = false;
bool deepSleepEnabled = true;
bool gpsLockAcquired = false;
bool showHealthDashboard = false;
bool batterySaverMode = false;
float batteryVoltage = 0.0;
float batteryPercent = 0.0;

unsigned long lastLogTimeByAP[MAX_APS];
int lastRssiByAP[MAX_APS];

// ---- Databases & lookup tables ----
FilterEntry filters[64];
int filterCount = 0;
bool whitelistMode = false;
OuiEntry ouiDatabase[MAX_OUI_ENTRIES];
int ouiCount = 0;
bool ouiLoaded = false;
KnownDevice knownDevices[MAX_KNOWN_DEVS];
int knownDeviceCount = 0;
VendorAlias vendorAliases[100];
int aliasCount = 0;
KarmaTracker* karmaDB = nullptr;
AnomalyTracker* anomalyDB = nullptr;
ClientMapEntry* clientMap = nullptr;
ChannelStats* channelStats = nullptr;

// ---- Sensors & peripherals ----
TinyGPSPlus gps;
HardwareSerial GPSSerial(1);
float currentLat = 0.0, currentLon = 0.0, currentAlt = 0.0;
int currentSats = 0;
bool gpsFixValid = false;
RTC_DS3231 rtc;
bool rtcFound = false;
bool bleScanning = false;
NimBLEScan* pBLEScan = nullptr;
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, -1);

// ---- Core data structures (PSRAM-allocated) ----
FingerprintDB* fpDB = nullptr;
int fpCount = 0;
bool fpLoaded = false;
HandshakeTracker* hsTrack = nullptr;
int hsCount = 0;
BLEDeviceCache* bleCache = nullptr;
int bleCount = 0;
AccessPoint* aps = nullptr;
StationClient* clients = nullptr;
PacketBuffer* packetPool = nullptr;

