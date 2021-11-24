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
  TEST_NUM_EQ(65535, checkPodData({0}));
  TEST_NUM_EQ(65279, checkPodData({1}));
  TEST_NUM_EQ(65024, checkPodData({1, 255}));
  TEST_NUM_EQ(65279, checkPodData({1, 255, 255}));
  TEST_NUM_EQ(65024, checkPodData({1, 255, 255, 255}));
  TEST_NUM_EQ(0, checkPodData({255, 255, 255, 255}));
  TEST_NUM_EQ(255, checkPodData({255, 255, 255, 255, 255}));
  TEST_NUM_EQ(0, checkPodData({255, 255, 255, 255, 255, 255}));
  TEST_NUM_EQ(59115, checkPodData({1, 2, 3, 4, 5, 6, 7, 8, 9}));
  TEST_NUM_EQ(19231, checkPodData({12, 23, 34, 45, 56, 67, 78, 89}));
}

static uint16_t checkTCP(const std::string &sip, const std::string dip,
                         uint16_t sport, uint16_t dport, std::string payload) {

  // timestamp data
  size_t                         opts_len = 12; // Use a fixed options.
  std::initializer_list<uint8_t> ts_data  = {0x7f, 0x04, 0xcf, 0x07,
                                            0xef, 0xb7, 0x9d, 0x24};

  size_t  totoal_len = sizeof(struct tcphdr) + opts_len + payload.length();
  uint8_t buf[1024];

  uint8_t *options = buf + sizeof(struct tcphdr);
  *options++       = 1; // NOP
  *options++       = 1; // NOP
                        // Timestamp options
  *options++ = 8;       // Type
  *options++ = 10;      // Length
  memcpy(options, ts_data.begin(), ts_data.size());
  options += ts_data.size();

  struct tcphdr *tcp = (struct tcphdr *)buf;
  memset(tcp, 0, sizeof(tcphdr));

  tcp->dest    = htons(dport);
  tcp->source  = htons(sport);
  tcp->seq     = htonl(2664371546);
  tcp->ack_seq = htonl(3160578114);
  tcp->psh     = 1;
  tcp->ack     = 1;
  tcp->window  = htons(507);
  tcp->th_off  = 8;

  uint8_t *pl = options;
  memcpy(pl, payload.data(), payload.length());

  uint32_t saddr;
  uint32_t daddr;
  inet_pton(AF_INET, sip.data(), &saddr);
  inet_pton(AF_INET, dip.data(), &daddr);

  return checksumTCP(buf, totoal_len, &saddr, &daddr);
}

void Test_checksum_tcp() {
  TEST_NUM_EQ(0x1f63,
              checkTCP("10.0.0.3", "10.0.0.2", 43562, 8000, "zengxianhui\n"));
  TEST_NUM_EQ(0x3e53,
              checkTCP("10.0.0.3", "10.0.0.2", 43562, 80, "zengxianhui\n"));
  TEST_NUM_EQ(0xf93f, checkTCP("10.0.0.3", "10.0.0.2", 41202, 80, "zxh"));
  TEST_NUM_EQ(0xf93f, checkTCP("10.0.0.3", "10.0.0.2", 41202, 80, "zxh"));
  TEST_NUM_EQ(0x2463, checkTCP("192.168.30.55", "10.0.0.2", 41202, 80, "zxh"));
  TEST_NUM_EQ(0xb3c0, checkTCP("192.168.30.55", "10.0.0.2", 41202, 8086,
                               "the checksum test routine."));
}

int main() {
  Test_checksum();
  Test_checksum_tcp();
  PRINT_PASS_RATE();
}