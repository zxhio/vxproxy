//===- TunTap.h - Tun/Tap Device --------------------------------*- C++ -*-===//
//
/// \file
/// IP address route opration with netlink and tun/tap device.
//
// Author:  zxh
// Date:    2021/10/23 16:58:59
//===----------------------------------------------------------------------===//

#pragma once

#include <fcntl.h>
#include <linux/if_tun.h> // TUNSETIFF
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace vxproxy {

static int createTunTap(int mode, const char *name) {
  int fd = open("/dev/net/tun", O_RDWR);
  if (fd < 0)
    return -1;

  struct ifreq ifr;
  ifr.ifr_flags = mode | IFF_NO_PI;
  memcpy(ifr.ifr_name, name, IFNAMSIZ);

  if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
    close(fd);
    return -1;
  }

  return fd;
}

static int setupTunTap(int sockfd, const char *name) {
  struct ifreq ifr;

  memcpy(ifr.ifr_name, name, IFNAMSIZ);
  if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0)
    return -1;

  memcpy(ifr.ifr_name, name, IFNAMSIZ);
  ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
  return ioctl(sockfd, SIOCSIFFLAGS, &ifr);
}

static int addAddrTunTap(int sockfd, struct sockaddr_in *addr) {
  struct ifreq ifr;
  memcpy(&ifr.ifr_addr, addr, sizeof(struct sockaddr));
  return ioctl(sockfd, SIOCSIFADDR, &ifr);
}

static int addRouteTunTap(int sockfd, struct sockaddr_in *addr,
                          struct sockaddr_in *mask) {
  int ret = addAddrTunTap(sockfd, addr);
  if (ret < 0)
    return -1;

  struct ifreq ifr;
  memcpy(&ifr.ifr_netmask, mask, sizeof(struct sockaddr));
  return ioctl(sockfd, SIOCSIFNETMASK, ifr);
}

} // namespace vxproxy