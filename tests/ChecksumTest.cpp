//===- ChecksumTest.cpp - Checksum Test Routine -----------------*- C++ -*-===//
//
/// \file
/// Test the correctness of checksum.
//
// Author:  zxh
// Date:    2021/11/09 22:59:36
//===----------------------------------------------------------------------===//

#include "Test.h"

#include <vxproxy/Packet.h>

#include <initializer_list>

using namespace vxproxy;

static uint16_t checkPodData(const std::initializer_list<uint8_t> &l) {
  return checksum(l.begin(), l.size());
}

void Test_checksum() {
  TEST_INT_EQ(65535, checkPodData({0}));
  TEST_INT_EQ(65279, checkPodData({1}));
  TEST_INT_EQ(65024, checkPodData({1, 255}));
  TEST_INT_EQ(65279, checkPodData({1, 255, 255}));
  TEST_INT_EQ(65024, checkPodData({1, 255, 255, 255}));
  TEST_INT_EQ(0, checkPodData({255, 255, 255, 255}));
  TEST_INT_EQ(255, checkPodData({255, 255, 255, 255, 255}));
  TEST_INT_EQ(0, checkPodData({255, 255, 255, 255, 255, 255}));
  TEST_INT_EQ(59115, checkPodData({1, 2, 3, 4, 5, 6, 7, 8, 9}));
  TEST_INT_EQ(19231, checkPodData({12, 23, 34, 45, 56, 67, 78, 89}));
}

int main() {
  Test_checksum();
  PRINT_PASS_RATE();
}