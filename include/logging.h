// ============================================================
// src/logging.h — Log/pcap queues, writer tasks, reports
// ============================================================
#pragma once
#include "globals.h"

void enqueueLog(const char* type, const char* event, const char* data, int rssi, int channel);
void enqueueLogAP(const char* type, const char* event, const char* data, int rssi, int channel,
                  float bw, int clients, const char* cipher, const char* auth,
                  bool rand, int threat, const char* tag);
void enqueuePcap(const uint8_t* payload, uint16_t length);
void logWriterTask(void* param);
void pcapWriterTask(void* param);
void generateHTMLReport();
void generateKML();
