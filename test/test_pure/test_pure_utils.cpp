#include <unity.h>
#include "pure_utils.h"

void setUp() {}
void tearDown() {}

void test_macequal_same_bytes(void) {
  uint8_t a[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
  uint8_t b[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
  TEST_ASSERT_TRUE(macEqual(a, b));
}

void test_macequal_different_bytes(void) {
  uint8_t a[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
  uint8_t b[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x02};
  TEST_ASSERT_FALSE(macEqual(a, b));
}

void test_isbroadcast_all_ff(void) {
  uint8_t b[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  TEST_ASSERT_TRUE(isBroadcast(b));
}

void test_isbroadcast_not_all_ff(void) {
  uint8_t m[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE};
  TEST_ASSERT_FALSE(isBroadcast(m));
}

void test_ismulticast_odd_first_octet(void) {
  uint8_t m[6] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
  TEST_ASSERT_TRUE(isMulticast(m));
}

void test_ismulticast_even_first_octet(void) {
  uint8_t m[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00};
  TEST_ASSERT_FALSE(isMulticast(m));
}

void test_getoui_formats_hex_colon_separated(void) {
  uint8_t m[6] = {0xAB, 0xCD, 0xEF, 0x00, 0x11, 0x22};
  char buf[9];
  getOui(m, buf);
  TEST_ASSERT_EQUAL_STRING("AB:CD:EF", buf);
}

void test_getoui_zero_padded(void) {
  uint8_t m[6] = {0x01, 0x02, 0x03, 0x00, 0x00, 0x00};
  char buf[9];
  getOui(m, buf);
  TEST_ASSERT_EQUAL_STRING("01:02:03", buf);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_macequal_same_bytes);
  RUN_TEST(test_macequal_different_bytes);
  RUN_TEST(test_isbroadcast_all_ff);
  RUN_TEST(test_isbroadcast_not_all_ff);
  RUN_TEST(test_ismulticast_odd_first_octet);
  RUN_TEST(test_ismulticast_even_first_octet);
  RUN_TEST(test_getoui_formats_hex_colon_separated);
  RUN_TEST(test_getoui_zero_padded);
  return UNITY_END();
}
