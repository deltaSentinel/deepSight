// ===================== helpers.h =====================
#pragma once
#include "globals.h"

bool macEqual(const uint8_t* a, const uint8_t* b);
bool isBroadcast(const uint8_t* mac);
bool isMulticast(const uint8_t* mac);
void getOui(const uint8_t* mac, char* ouiStr);
void getTimestamp(char* buffer, size_t size);
void readBattery();
void playTone(int freq, int duration);
void beepHandshake();
void beepDeauth();
void beepGPS();
void beepAlert();
PacketBuffer* allocPacketBuffer();
void freePacketBuffer(PacketBuffer* pkt);

