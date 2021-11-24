//===- TunTap.h - Tun/Tap Device --------------------------------*- C++ -*-===//
//
/// \file
/// IP address route opration with netlink and tun/tap device.
//
// Author:  zxh
// Date:    2021/10/23 16:58:59
//===----------------------------------------------------------------------===//

#pragma once

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace vxproxy {

static inline int createTunTap(int mode, const char *name) {
  int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
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

static inline int setupTunTap(int sockfd, const char *name) {
  struct ifreq ifr;

  memcpy(ifr.ifr_name, name, IFNAMSIZ);
  if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0)
    return -1;

  memcpy(ifr.ifr_name, name, IFNAMSIZ);
  ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
  return ioctl(sockfd, SIOCSIFFLAGS, &ifr);
}

static inline int createAndSetupTunTap(int mode, const char *name) {
  int fd = createTunTap(mode, name);
  if (fd < 0)
    return -1;

  int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sockfd < 0) {
    close(fd);
    return -1;
  }

  if (setupTunTap(sockfd, name) < 0) {
    close(fd);
    close(sockfd);
    return -1;
  }

  return fd;
}

static inline int addAddrTunTap(int sockfd, const char *name,
                                struct sockaddr_in *addr) {
  struct ifreq ifr;
  memcpy(&ifr.ifr_addr, addr, sizeof(struct sockaddr));
  memcpy(&ifr.ifr_name, name, IFNAMSIZ);
  return ioctl(sockfd, SIOCSIFADDR, &ifr);
}

// Add address to tun/tap and set routes.
static inline int addAddrNetmaskTunTap(int sockfd, const char *name,
                                       struct sockaddr_in *addr,
                                       struct sockaddr_in *mask) {
  int ret = addAddrTunTap(sockfd, name, addr);
  if (ret < 0)
    return -1;

  struct ifreq ifr;
  memcpy(&ifr.ifr_name, name, IFNAMSIZ);
  memcpy(&ifr.ifr_netmask, mask, sizeof(struct sockaddr));
  return ioctl(sockfd, SIOCSIFNETMASK, &ifr);
}

static inline int addRouteTunTap(int sockfd, const char *name,
                                 struct sockaddr_in *addr,
                                 struct sockaddr_in *mask,
                                 unsigned short      flags) {
  struct rtentry rte;

  memset(&rte, 0, sizeof(struct rtentry));
  rte.rt_dev   = (char *)name;
  rte.rt_flags = RTF_UP | flags;

  memcpy(&rte.rt_dst, addr, sizeof(struct sockaddr));
  memcpy(&rte.rt_genmask, mask, sizeof(struct sockaddr));

  return ioctl(sockfd, SIOCADDRT, &rte);
}

// Add net routes for tun/tap device.
// Note: device must aleady up.
static inline int addNetRouteTunTap(int sockfd, const char *name,
                                    struct sockaddr_in *addr,
                                    struct sockaddr_in *mask) {
  return addRouteTunTap(sockfd, name, addr, mask, 0);
}

// Add host routes for tun/tap device name.
// Note: device must aleady up.
static inline int addHostRouteTunTap(int sockfd, const char *name,
                                     struct sockaddr_in *addr) {
  struct sockaddr_in mask;
  mask.sin_family = AF_INET;
  mask.sin_port   = 0;
  inet_pton(AF_INET, "255.255.255.255", &mask.sin_addr);

  return addRouteTunTap(sockfd, name, addr, &mask, RTF_HOST);
}

} // namespace vxproxy