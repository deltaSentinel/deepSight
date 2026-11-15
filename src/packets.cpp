// ============================================================
// src/packets.cpp
// ============================================================
#include "packets.h"
#include "helpers.h"
#include "detect.h"
#include "logging.h"
#include "storage.h"
#include "sensors.h"

// Called from setup(): configures and enables promiscuous mode + RX callback.
void installPromiscuousMode() {
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_channel(WIFI_CHANNEL_START, WIFI_SECOND_CHAN_NONE);

  wifi_promiscuous_filter_t filter = {0};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&filter);

  esp_wifi_set_promiscuous_rx_cb([](void* buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t* raw = (wifi_promiscuous_pkt_t*)buf;
    if (raw->rx_ctrl.sig_len > MAX_PACKET_SIZE) return;

    PacketBuffer* pkt = nullptr;
    for (int i = 0; i < PACKET_POOL_SIZE; i++) {
      if (!packetPool[i].used) {
        pkt = &packetPool[i];
        break;
      }
    }

    if (!pkt) {
      packetDropCount = packetDropCount + 1;
      return;
    }

    pkt->used = true;
    memcpy(pkt->payload, raw->payload, raw->rx_ctrl.sig_len);
    pkt->length = raw->rx_ctrl.sig_len;
    pkt->rssi = raw->rx_ctrl.rssi;
    pkt->channel = raw->rx_ctrl.channel;
    pkt->type = type;

    enqueuePcap(raw->payload, raw->rx_ctrl.sig_len);

    BaseType_t res = xQueueSend(packetQueue, &pkt, 0);
    if (res != pdTRUE) {
      pkt->used = false;
      packetDropCount = packetDropCount + 1;
    }
  });

  esp_wifi_set_promiscuous(true);
}

void packetProcessorTask(void* param) {
  xProcTaskHandle = xTaskGetCurrentTaskHandle();
  PacketBuffer* pkt;
  while (true) {
    if (xQueueReceive(packetQueue, &pkt, portMAX_DELAY) == pdTRUE) {
      if (!pkt) continue;
      updateChannelActivity();

      // Update channel utilization stats
      updateChannelStats(pkt->channel, pkt->rssi);

      if (pkt->length < 10) { freePacketBuffer(pkt); continue; }

      const uint8_t* payload = pkt->payload;
      uint8_t type = (payload[0] & 0x0C) >> 2;
      uint8_t subtype = (payload[0] & 0xF0) >> 4;

      const uint8_t* src = nullptr;
      const uint8_t* dst = nullptr;
      const uint8_t* bssid = nullptr;

      if (type == 0) {
        if (pkt->length < 26) { freePacketBuffer(pkt); continue; }
        dst = payload + 4; src = payload + 10; bssid = payload + 16;
      } else if (type == 2) {
        if (pkt->length < 26) { freePacketBuffer(pkt); continue; }
        dst = payload + 4; src = payload + 10; bssid = payload + 16;
      }

      bool isWPA3 = false, isWifi6 = false, isMesh = false;
      char cipher[8] = "UNK";
      char auth[8] = "UNK";

      // --- BEACON FRAME PROCESSING ---
      if (pkt->type == WIFI_PKT_MGMT && subtype == 8) {
        decodeAdvancedFeatures(payload, pkt->length, isWPA3, isWifi6, isMesh);
        parseSecurity(payload, pkt->length, cipher, auth);

        // Check WPA3 Transition Mode
        bool isTransition = checkWPA3Transition(payload, pkt->length);

        // Extract WPS PIN
        int wpsPin = extractWPSPin(payload, pkt->length);

        int pos = 36;
        if (pkt->length >= pos + 2) {
          int len = payload[pos + 1];
          if (len <= 32) {
            char ssid[33];
            bool wasHidden = false;
            if (len == 0) { strcpy(ssid, "<hidden>"); wasHidden = true; }
            else { memcpy(ssid, &payload[pos + 2], len); ssid[len] = '\0'; }

            bool hasPMKID = checkPMKID(payload, pkt->length);
            bool isOpen = (strcmp(auth, "UNK") == 0 || strcmp(auth, "") == 0);

            int idx = -1;
            for(int i=0; i<MAX_APS; i++) {
               if (aps[i].active && macEqual(aps[i].bssid, bssid)) { idx = i; break; }
               if (!aps[i].active) { idx = i; break; }
               if (i % 10 == 0) yield();
            }
            if (idx != -1) {
               aps[idx].active = true;
               memcpy(aps[idx].bssid, bssid, 6);

               // Reveal hidden SSID if we previously saw <hidden> but now have the real name
               if (wasHidden && strcmp(aps[idx].ssid, "<hidden>") == 0) {
                 strcpy(aps[idx].ssid, "<hidden>");
               } else if (!wasHidden) {
                 strncpy(aps[idx].ssid, ssid, 32);
               }

               aps[idx].rssi = pkt->rssi;
               aps[idx].channel = pkt->channel;
               aps[idx].lastSeen = millis();
               aps[idx].packetCount++;
               if (hasPMKID) aps[idx].hasPMKID = true;
               if (isWPA3) aps[idx].isWPA3 = true;
               if (isWifi6) aps[idx].isWifi6 = true;
               if (isMesh) aps[idx].isMesh = true;
               if (isTransition) aps[idx].isWPA3Transition = true;
               if (wpsPin > 0) aps[idx].wpsPin = wpsPin;
               if (strcmp(cipher, "UNK") != 0) strncpy(aps[idx].cipherSuite, cipher, 7);
               if (strcmp(auth, "UNK") != 0) strncpy(aps[idx].authMode, auth, 7);

               updateBandwidth(&aps[idx], pkt->length);
               autoTag(aps[idx].ssid, isOpen, isMesh, aps[idx].clientCount, aps[idx].tag);
               aps[idx].threatScore = calculateThreatScore(&aps[idx]);

               // Log WPS exposure
               if (wpsPin > 0 && aps[idx].wpsPin != -1) {
                 char wpsMsg[64];
                 snprintf(wpsMsg, sizeof(wpsMsg), "WPS_EXPOSED: %s PIN=%d", ssid, wpsPin);
                 enqueueLog("WiFi", "WPS", wpsMsg, pkt->rssi, pkt->channel);
                 aps[idx].wpsPin = -1; // Mark as logged (avoid spam)
               }

               // Log WPA3 Transition Mode
               if (isTransition) {
                 char transMsg[64];
                 snprintf(transMsg, sizeof(transMsg), "WPA3_TRANSITION: %s", ssid);
                 enqueueLog("WiFi", "TRANSITION", transMsg, pkt->rssi, pkt->channel);
               }

               if (checkEvilTwin(bssid, ssid)) {
                 aps[idx].isEvilTwin = true;
                 aps[idx].threatScore = 100;
                 char msg[64];
                 snprintf(msg, sizeof(msg), "EVIL_TWIN: %s", ssid);
                 enqueueLog("WiFi", "ALERT", msg, pkt->rssi, pkt->channel);
                 if (!batterySaverMode) beepAlert();
               }

               if (hasPMKID && !aps[idx].hasPMKID) {
                  aps[idx].hasPMKID = true;
                  aps[idx].threatScore += 50;
                  char msg[64];
                  snprintf(msg, sizeof(msg), "PMKID_FOUND: %s", ssid);
                  enqueueLog("WiFi", "PMKID", msg, pkt->rssi, pkt->channel);
                  extractAndSavePMKID(bssid, payload, pkt->length, ssid);
               }

               if (loggingEnabled && shouldLogAP(idx, pkt->rssi, pkt->channel)) {
                 enqueueLogAP("WiFi", "BEACON", aps[idx].ssid, pkt->rssi, pkt->channel,
                              aps[idx].bandwidthMbps, aps[idx].clientCount,
                              aps[idx].cipherSuite, aps[idx].authMode,
                              aps[idx].isRandomized, aps[idx].threatScore, aps[idx].tag);
               }
            }

            // Get channel noise for this fingerprint
            int chNoise = 0;
            float chUtil = 0.0;
            if (channelStats && pkt->channel >= 1 && pkt->channel <= 13) {
              chNoise = channelStats[pkt->channel].noiseFloor;
              chUtil = channelStats[pkt->channel].utilizationPercent;
            }

            updateFingerprint(bssid, aps[idx].ssid, pkt->rssi, pkt->channel, isWPA3, isWifi6, isMesh,
                              aps[idx].bandwidthMbps, aps[idx].clientCount,
                              checkRandomized(src), aps[idx].cipherSuite, aps[idx].authMode,
                              aps[idx].threatScore, aps[idx].tag, isTransition, wpsPin, chNoise, chUtil);
          }
        }
      }
      // --- PROBE RESPONSE: Reveal Hidden SSIDs ---
      else if (pkt->type == WIFI_PKT_MGMT && subtype == 5) {
        // Probe Responses contain the real SSID even for "hidden" networks
        int pos = 36;
        if (pkt->length >= pos + 2) {
          int len = payload[pos + 1];
          if (len > 0 && len <= 32) {
            char revealedSsid[33];
            memcpy(revealedSsid, &payload[pos + 2], len);
            revealedSsid[len] = '\0';

            // Find the AP with this BSSID and update its SSID if it was hidden
            if (bssid) {
              for (int i = 0; i < MAX_APS; i++) {
                if (aps[i].active && macEqual(aps[i].bssid, bssid)) {
                  if (strcmp(aps[i].ssid, "<hidden>") == 0) {
                    strncpy(aps[i].ssid, revealedSsid, 32);
                    char msg[64];
                    snprintf(msg, sizeof(msg), "HIDDEN_REVEALED: %s", revealedSsid);
                    enqueueLog("WiFi", "REVEAL", msg, pkt->rssi, pkt->channel);

                    // Update fingerprint too
                    for (int k = 0; k < fpCount; k++) {
                      char bssidHex[13];
                      snprintf(bssidHex, 13, "%02X%02X%02X%02X%02X%02X", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
                      if (strstr(fpDB[k].id, bssidHex) != NULL) {
                        strncpy(fpDB[k].ssid, revealedSsid, 32);
                      }
                    }
                  }
                  break;
                }
                if (i % 10 == 0) yield();
              }
            }
          }
        }
        updateKarmaTracking(bssid, false);
      }
      // --- PROBE REQUEST: Track karma ---
      else if (pkt->type == WIFI_PKT_MGMT && subtype == 4) {
        updateKarmaTracking(src, true);
      }
      // --- DATA FRAME: Track clients ---
      else if (pkt->type == WIFI_PKT_DATA) {
        if (src && !isBroadcast(src) && !isMulticast(src)) {
           int idx = -1;
           for(int i=0; i<MAX_APS; i++) {
              if (aps[i].active && macEqual(aps[i].bssid, bssid)) { idx = i; break; }
              if (i % 10 == 0) yield();
           }
           if (idx != -1) {
              addClientToAP(&aps[idx], src);
              aps[idx].threatScore = calculateThreatScore(&aps[idx]);

              // Update client-to-AP map
              updateClientMap(src, bssid, pkt->rssi);
           }

           int cIdx = -1;
           for(int i=0; i<MAX_CLIENTS; i++) {
              if (clients[i].active && macEqual(clients[i].mac, src)) { cIdx = i; break; }
              if (!clients[i].active) { cIdx = i; break; }
              if (i % 10 == 0) yield();
           }
           if (cIdx != -1) {
              clients[cIdx].active = true;
              memcpy(clients[cIdx].mac, src, 6);
              clients[cIdx].rssi = pkt->rssi;
              clients[cIdx].lastSeen = millis();
              updateAnomalyTracking(src, pkt->rssi);

              int status = getDeviceStatus(src);
              if (status == 2) {
                 char msg[64];
                 snprintf(msg, sizeof(msg), "KNOWN_BAD: %s", getVendorFromOui(src));
                 enqueueLog("WiFi", "ALERT", msg, pkt->rssi, pkt->channel);
                 if (!batterySaverMode) beepAlert();
              }
           }
           processHandshake(payload, pkt->length, bssid, pkt->rssi);
        }
      }
      // --- DEAUTH / DISASSOCIATION: Forensic Logging ---
      else if (pkt->type == WIFI_PKT_MGMT && (subtype == 10 || subtype == 11)) {
        char reason[32];
        uint16_t rc = 0;
        if (pkt->length >= 26) rc = payload[24] | (payload[25] << 8);
        snprintf(reason, sizeof(reason), "Reason:%u", rc);

        int status = getDeviceStatus(bssid);
        if (status == 1) { freePacketBuffer(pkt); continue; }

        // Build detailed forensic log with source and destination
        char srcStr[18] = "UNK", dstStr[18] = "UNK";
        if (src) snprintf(srcStr, 18, "%02X:%02X:%02X:%02X:%02X:%02X", src[0], src[1], src[2], src[3], src[4], src[5]);
        if (dst) snprintf(dstStr, 18, "%02X:%02X:%02X:%02X:%02X:%02X", dst[0], dst[1], dst[2], dst[3], dst[4], dst[5]);

        char forensics[128];
        snprintf(forensics, sizeof(forensics), "%s Src=%s Dst=%s", reason, srcStr, dstStr);

        if(loggingEnabled) {
          enqueueLog("WiFi", subtype == 10 ? "DEAUTH" : "DISASSOC", forensics, pkt->rssi, pkt->channel);
        }
        if (!batterySaverMode) beepDeauth();
      }

      freePacketBuffer(pkt);
      totalPacketsProcessed = totalPacketsProcessed + 1;
    }
  }
}
