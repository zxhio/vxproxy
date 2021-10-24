//===- Packet.cpp - Packet Encode/Decode ------------------------*- C++ -*-===//
//
/// \file
/// Encode/Decode TCP/IP layer packet.
//
// Author:  zxh
// Date:    2021/10/24 21:19:24
//===----------------------------------------------------------------------===//

#include <vxproxy/Packet.h>
#include <vxproxy/Route.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

using namespace vxproxy;

void readTun(int fd) {
  char buf[256];
  memset(buf, 0, sizeof(buf));

  ssize_t n = read(fd, buf, sizeof(buf));
  if (n < 0) {
    fprintf(stderr, "Fail to read: %s\n", strerror(errno));
    return;
  }

  IPv4 ip(buf, n);
  ip.decode();
  struct iphdr h = ip.header();

  DataView pl = ip.payload();
  TCP      tcp(pl.data, pl.len);
  tcp.decode();

  inet_ntop(AF_INET, &h.saddr, buf, sizeof(buf));
  fprintf(stderr, "src: <%s: %d> ", buf, tcp.header().source);
  inet_ntop(AF_INET, &h.daddr, buf, sizeof(buf));
  fprintf(stderr, "dst: <%s: %d>\n", buf, tcp.header().dest);
}

int main() {
  vxproxy::Route route("test_foo");
  if (!route.ok()) {
    fprintf(stderr, "Fail to new route: %s\n", strerror(errno));
    return -1;
  }

  int ret = route.addNet("172.23.19.0", "255.255.255.0");
  if (ret < 0) {
    fprintf(stderr, "Fail to add route 172.23.19.0: %s\n", strerror(errno));
    return -1;
  }

  route.setTunRecvHandler(readTun);
  route.loop();
}