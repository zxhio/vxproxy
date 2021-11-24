//===- ChecksumTest.cpp - TCP IP Option Test  -------------------*- C++ -*-===//
//
/// \file
/// Test the correctness of checksum.
//
// Author:  zxh
// Date:    2021/11/23 21:23:12
//===----------------------------------------------------------------------===//

#include "Test.h"

#include <vxproxy/Packet.h>

#include <initializer_list>

using namespace vxproxy;

using PodData = std::initializer_list<uint8_t>;

void Test_TCPIPOption_Decode() {
  PodData data{
      0x02, 0x04, 0x05, 0x82, 0x04, 0x02, 0x08, 0x0a, 0xc9, 0xf9,
      0x1d, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
  };

  std::vector<TCPIPOption> opt_list =
      decodeTCPIPOptions((const char *)data.begin(), data.size());

  TEST_NUM_EQ(5, opt_list.size());

  TCPIPOption opt = opt_list[0];
  TEST_NUM_EQ((uint8_t)TCPIPOptionKind::OK_Mss, opt.kind);
  TEST_NUM_EQ(4, opt.length);
  TEST_NUM_EQ(1410, ntohs(*(uint16_t *)opt.value.data()));

  opt = opt_list[1];
  TEST_NUM_EQ((uint8_t)TCPIPOptionKind::OK_SACKPermitted, opt.kind);
  TEST_NUM_EQ(2, opt.length);

  opt = opt_list[2];
  TEST_NUM_EQ((uint8_t)TCPIPOptionKind::OK_Timestamps, opt.kind);
  TEST_NUM_EQ(10, opt.length);
  TEST_NUM_EQ(3388546366, ntohl(*(uint32_t *)opt.value.data()));
  TEST_NUM_EQ(0, ntohl(*(uint32_t *)(opt.value.data() + 4)));

  opt = opt_list[3];
  TEST_NUM_EQ((uint8_t)TCPIPOptionKind::OK_Nop, opt.kind);
  TEST_NUM_EQ(1, opt.length);

  opt = opt_list[4];
  TEST_NUM_EQ((uint8_t)TCPIPOptionKind::OK_WindowScale, opt.kind);
  TEST_NUM_EQ(3, opt.length);
  TEST_NUM_EQ(7, *(uint8_t *)opt.value.data());
}

void Test_TCPIPOption_Encode() {
  PodData data{
      0x02, 0x04, 0x05, 0x82, 0x04, 0x02, 0x08, 0x0a, 0xc9, 0xf9,
      0x1d, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
  };

  std::vector<TCPIPOption> opt_list =
      decodeTCPIPOptions((const char *)data.begin(), data.size());

  char buf[data.size()];
  std::fill(buf, buf + sizeof(buf), 0);
  encodeTCPIPOptions(opt_list, buf);

  TEST_STRING_EQ((const char *)data.begin(), buf);
}

int main() {
  Test_TCPIPOption_Decode();
  Test_TCPIPOption_Encode();

  PRINT_PASS_RATE();
}