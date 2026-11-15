// ===================== helpers.h =====================
#pragma once
#include "globals.h"
#include "pure_utils.h"

void getTimestamp(char* buffer, size_t size);
void readBattery();
void playTone(int freq, int duration);
void beepHandshake();
void beepDeauth();
void beepGPS();
void beepAlert();
PacketBuffer* allocPacketBuffer();
void freePacketBuffer(PacketBuffer* pkt);

