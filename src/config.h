// ===================== config.h =====================
#pragma once
#include <Arduino.h>

// --- Pins ---
#define BTN_LOG            4
#define BTN_HOP            5
#define BTN_CLEAR          6
#define BTN_PANIC          7
#define BTN_HEALTH         15
#define BUZZER_PIN         8
#define BAT_ADC_PIN        9
#define OLED_SDA           21
#define OLED_SCL           22
#define DEEP_SLEEP_WAKE_PIN  GPIO_NUM_34   // adjust to your build

// --- Tuning constants (move all your #defines here) ---
#define MAX_APS              64
#define MAX_CLIENTS          64
#define MAX_FINGERPRINTS     128
#define MAX_CLIENT_MAP       64
#define PACKET_POOL_SIZE     64
#define MAX_PACKET_SIZE      1024
#define PACKET_QUEUE_SIZE    64
#define LOG_QUEUE_SIZE       256
#define PCAP_QUEUE_SIZE      128
#define FORGET_TIME          300000UL
#define SLEEP_TIMEOUT        600000UL
#define BATTERY_SAVER_SLEEP_TIMEOUT 300000UL
#define MIN_FREE_HEAP        51200
#define MIN_FREE_PSRAM       65536
#define MIN_STACK_WATERMARK  512
#define MAX_DWELL_TIME_MS    2000
#define MIN_DWELL_TIME_MS    200
#define BATTERY_SAVER_DWELL  1000
#define BATTERY_SAVER_BLE_INTERVAL 60000UL
#define WIFI_CHANNEL_START   1

