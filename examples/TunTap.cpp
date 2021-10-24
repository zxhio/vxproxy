//===- TunTap.cpp - Tun/Tap test routine ------------------------*- C++ -*-===//
//
/// \file
/// Show usage for tun/tap device opration.
//
// Author:  zxh
// Date:    2021/10/23 17:30:53
//===----------------------------------------------------------------------===//

#include <sys/socket.h>
#include <vxproxy/Poll.h>
#include <vxproxy/TunTap.h>

#include <chrono>
#include <thread>

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

const char *ifname = "foo";

using namespace vxproxy;

void readFromTunTap(int fd) {
  char buf[2048];
  int  n = read(fd, buf, sizeof(buf));
  fprintf(stderr, "Read %d byte data from tuntap(%d)\n", n, fd);
}

int main() {
  int fd = vxproxy::createTunTap(IFF_TUN, ifname);
  if (fd < 0) {
    fprintf(stderr, "Fail to add tun/tap: %s\n", strerror(errno));
    return -1;
  }

  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sockfd < 0) {
    fprintf(stderr, "Fail to socket DGRAM: %s\n", strerror(errno));
    return -1;
  }

  int ret = vxproxy::setupTunTap(sockfd, ifname);
  if (ret < 0) {
    fprintf(stderr, "Fail to setup tun/tap: %s\n", strerror(errno));
    return -1;
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port   = 0;
  inet_pton(AF_INET, "172.23.19.0", &addr.sin_addr);

  ret = vxproxy::addAddrTunTap(sockfd, ifname, &addr);
  if (ret < 0) {
    fprintf(stderr, "Fail to add addr for tun/tap: %s\n", strerror(errno));
    return -1;
  }

  struct sockaddr_in mask;
  mask.sin_family = AF_INET;
  mask.sin_port   = 0;
  inet_pton(AF_INET, "255.255.255.0", &mask.sin_addr);

  // Readd addr to tuntap (OK, no problem)
  ret = vxproxy::addAddrNetmaskTunTap(sockfd, ifname, &addr, &mask);
  if (ret < 0) {
    fprintf(stderr, "Fail to add mask for tun/tap: %s\n", strerror(errno));
    return -1;
  }

  // Add host route
  addr.sin_family = AF_INET;
  addr.sin_port   = 0;
  inet_pton(AF_INET, "10.17.19.23", &addr.sin_addr);
  ret = vxproxy::addHostRouteTunTap(sockfd, ifname, &addr);
  if (ret < 0) {
    fprintf(stderr, "Fail to set host route for tun/tap: %s\n",
            strerror(errno));
    return -1;
  }

  addr.sin_family = AF_INET;
  addr.sin_port   = 0;
  inet_pton(AF_INET, "10.179.19.0", &addr.sin_addr);
  ret = vxproxy::addNetRouteTunTap(sockfd, ifname, &addr, &mask);
  if (ret < 0) {
    fprintf(stderr, "Fail to set net route for tun/tap: %s\n", strerror(errno));
    return -1;
  }

  Poll p;
  p.addReadableEvent(fd, readFromTunTap);
  p.loop();

  // std::this_thread::sleep_for(std::chrono::seconds(100));

  close(fd);
  close(sockfd);

  fprintf(stderr, "Done\n");
}