// ============================================================
// src/detect.h — Lookups, protocol parsing, detection engines
// ============================================================
#pragma once
#include "globals.h"

// Lookups
const char* getVendorFromOui(const uint8_t* mac);
int getDeviceStatus(const uint8_t* mac);

// Protocol parsing
bool checkPMKID(const uint8_t* payload, int len);
int extractWPSPin(const uint8_t* payload, int len);
bool checkWPA3Transition(const uint8_t* payload, int len);
void decodeAdvancedFeatures(const uint8_t* payload, int len, bool& isWPA3, bool& isWifi6, bool& isMesh);
void parseSecurity(const uint8_t* payload, int len, char* cipher, char* auth);

// Detection engines
bool checkEvilTwin(const uint8_t* bssid, const char* ssid);
void extractAndSavePMKID(const uint8_t* bssid, const uint8_t* payload, int len, const char* ssid);
void processHandshake(const uint8_t* payload, int len, const uint8_t* bssid, int rssi);
void exportHandshake(const uint8_t* bssid, const uint8_t* payload, int len);
void updateKarmaTracking(const uint8_t* bssid, bool isRequest);
void checkKarmaAttack();
void updateAnomalyTracking(const uint8_t* bssid, int rssi);
bool checkRandomized(const uint8_t* mac);

// Tracking & stats
void updateChannelStats(int channel, int rssi);
void updateClientMap(const uint8_t* clientMac, const uint8_t* apBssid, int rssi);
void updateBandwidth(AccessPoint* ap, uint16_t len);
bool addClientToAP(AccessPoint* ap, const uint8_t* mac);

// Scoring & tagging
void autoTag(const char* ssid, bool isOpen, bool isMesh, int clientCount, char* tag);
int calculateThreatScore(AccessPoint* ap);
bool shouldLogAP(int apIndex, int rssi, int channel);
void updateFingerprint(const uint8_t* bssid, const char* ssid, int rssi, int ch,
                       bool wpa3, bool wifi6, bool mesh, float bw, int cc, bool rand,
                       const char* ciph, const char* auth, int score, const char* tag,
                       bool transition, int wpsPin, int noise, float util);
