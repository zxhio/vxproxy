//===- TunTap.cpp - Tun/Tap test routine ------------------------*- C++ -*-===//
//
/// \file
///
//
// Author:  zxh
// Date:    2021/10/23 17:30:53
//===----------------------------------------------------------------------===//

#include <vxproxy/TunTap.h>

#include <chrono>
#include <thread>

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

using namespace vxproxy;

int main() {
  int fd = vxproxy::createTunTap(IFF_TUN, "foo");
  if (fd < 0) {
    fprintf(stderr, "Fail to add tun/tap: %s\n", strerror(errno));
    return -1;
  }

  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sockfd < 0) {
    fprintf(stderr, "Fail to socket DGRAM: %s\n", strerror(errno));
    return -1;
  }

  int                ret = -1;
  struct sockaddr_in addr;

  addr.sin_family      = AF_INET;
  addr.sin_port        = 0;
  addr.sin_addr.s_addr = inet_addr("172.23.19.1");

  // ret = vxproxy::addAddrTunTap(sockfd, &addr);
  // if (ret < 0) {
  //   fprintf(stderr, "Fail to add addr for tun/tap: %s\n", strerror(errno));
  //   return -1;
  // }

  struct sockaddr_in mask;
  mask.sin_family      = AF_INET;
  mask.sin_port        = 0;
  mask.sin_addr.s_addr = inet_addr("255.255.255.0");

  ret = vxproxy::addRouteTunTap(sockfd, &addr, &mask);
  if (ret < 0) {
    fprintf(stderr, "Fail to add mask for tun/tap: %s\n", strerror(errno));
    return -1;
  }

  ret = vxproxy::setupTunTap(sockfd, "foo");
  if (ret < 0) {
    fprintf(stderr, "Fail to setup tun/tap: %s\n", strerror(errno));
    return -1;
  }

  std::this_thread::sleep_for(std::chrono::seconds(10));

  close(fd);
  close(sockfd);

  fprintf(stderr, "Done\n");
}