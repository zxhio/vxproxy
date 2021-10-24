//===- Route.h - IPv4 Route Operation ----------------------------*- C++
//-*-===//
//
/// \file
/// IPv4 address and route operation.
//
// Author:  zxh
// Date:    2021/10/24 13:48:06
//===----------------------------------------------------------------------===//

#pragma once

#include "Poll.h"
#include "TunTap.h"

#include <string>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace vxproxy {

class Route {
public:
  Route()              = delete;
  Route(const Route &) = delete;
  Route &operator=(const Route &) = delete;

  explicit Route(const char *ifname)
      : sockfd_(-1), tuntapfd_(-1), ifname_(ifname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd < 0)
      return;
    sockfd_ = fd;

    fd = createTunTap(IFF_TUN, ifname_.data());
    if (fd < 0)
      return;
    tuntapfd_ = fd;

    if (setupTunTap(sockfd_, ifname_.data()) < 0)
      finit();
  }

  ~Route() { finit(); }

  bool ok() const { return sockfd_ > 0 && tuntapfd_ > 0; }

  int addHost(const std::string &addr) {
    struct sockaddr_in s;
    toAddr(addr, &s);
    return addHostRouteTunTap(sockfd_, ifname_.data(), &s);
  }

  // TODO, convert addr to form as '192.168.110.0'
  int addNet(const std::string &addr, const std::string &mask) {
    struct sockaddr_in s;
    struct sockaddr_in m;

    if (toAddr(addr, &s) < 0)
      return -1;
    if (toAddr(mask, &m) < 0)
      return -1;
    return addNetRouteTunTap(sockfd_, ifname_.data(), &s, &m);
  }

  void setTunRecvHandler(EventHandleFunc cb) {
    poll_.addReadableEvent(tuntapfd_, cb);
  }

  void loop() {
    if (!ok())
      return;
    poll_.loop();
  }

private:
  int toAddr(const std::string &addr, struct sockaddr_in *s) const {
    s->sin_family = AF_INET;
    s->sin_port   = 0;
    return inet_pton(AF_INET, addr.data(), &s->sin_addr);
  }

  void finit() {
    if (sockfd_ > 0)
      close(sockfd_);

    if (tuntapfd_ > 0)
      close(tuntapfd_);

    sockfd_   = -1;
    tuntapfd_ = -1;
  }

  int         sockfd_;
  int         tuntapfd_;
  std::string ifname_;
  Poll        poll_;
};

} // namespace vxproxy