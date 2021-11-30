//===- Proxy.h - Manage Proxy Action ----------------------------*- C++ -*-===//
//
/// \file
/// Manage all proxy direction and proxy rules.
//
// Author:  zxh
// Date:    2021/10/27 21:53:46
//===----------------------------------------------------------------------===//

#pragma once

#include "DataView.h"
#include "Packet.h"
#include "Poll.h"
#include "TunTap.h"
#include "Vxlan.h"

#include <map>

#include <assert.h>

namespace vxproxy {

struct TCPConnTuple {
  uint16_t sport;
  uint16_t dport;
  uint32_t sip;
  uint32_t dip;
};

struct TCPCmp {
  bool operator()(const TCPConnTuple &l, const TCPConnTuple &r) const {
    if (l.dip < r.dip)
      return true;
    if (l.sip < r.sip)
      return true;
    if (l.sport < r.sport)
      return true;
    if (l.dport < r.dport)
      return true;
    return false;
  }
};

struct TCPSession {
  uint8_t      smac[ETH_ALEN];
  uint8_t      dmac[ETH_ALEN];
  uint16_t     vxlanPort;
  uint32_t     vxlanIP;
  uint32_t     vxlanID;
  TCPConnTuple oriConn;
};

using TCPSessions = std::map<TCPConnTuple, TCPSession, TCPCmp>;

void printHex(const u_char *data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    fprintf(stderr, "%02x", data[i]);

    if (i == len - 1)
      fprintf(stderr, "\n");
    else
      fprintf(stderr, " ");
  }
}

void printTCPConnTuple(const TCPConnTuple &t) {
  char srcIP[32];
  char dstIP[32];
  inet_ntop(AF_INET, &t.sip, srcIP, sizeof(srcIP));
  inet_ntop(AF_INET, &t.dip, dstIP, sizeof(dstIP));

  fprintf(stderr, "  TCP Conn - (%s:%d) -> (%s:%d)\n", srcIP, t.sport, dstIP,
          t.dport);
}

void printTCPSession(const TCPSession &sess) {
  fprintf(stderr, "TCP Session - \n");
  fprintf(stderr, "  src_mac=");
  printHex(sess.smac, sizeof(sess.smac));
  fprintf(stderr, "  dst_mac=");
  printHex(sess.dmac, sizeof(sess.dmac));

  printTCPConnTuple(sess.oriConn);
}

void sendToTCPIP(int rawFd, uint32_t ip, uint16_t port, const u_char *data,
                 size_t n) {
  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family      = AF_INET;
  sin.sin_addr.s_addr = ip;
  sin.sin_port        = htons(port);

  if (sendto(rawFd, data, n, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    fprintf(stderr, "Fail to sendto raw socket: %s\n", strerror(errno));
    return;
  }
}

void toBackendARP(struct sockaddr_in *addr, struct vxlanhdr *vxlan,
                  struct ether_header *eth, const u_char *hwaddr,
                  const u_char *data, size_t len) {
  assert(len >= sizeof(struct ether_arp));

  fprintf(stderr, "ARP request\n");

  size_t n = 0;

  struct ether_arp arp;
  decodeARP(&arp, data);
  n += sizeof(struct ether_arp);

  if (arp.ea_hdr.ar_pro != ETHERTYPE_IP)
    return;

  u_char buf[ETH_FRAME_LEN];

  encodeVxlan(vxlan, buf);
  n = lenVxlanHdr();

  struct ether_header reth;
  reth.ether_type = ETHERTYPE_ARP;
  memcpy(reth.ether_shost, hwaddr, ETH_ALEN);
  memcpy(reth.ether_dhost, eth->ether_shost, ETH_ALEN);
  encodeEthernet(&reth, buf + n);
  n += lenEthernetHdr();

  struct ether_arp rarp;
  rarp.ea_hdr       = arp.ea_hdr;
  rarp.ea_hdr.ar_op = ARPOP_REPLY;
  memcpy(rarp.arp_sha, hwaddr, ETH_ALEN);
  memcpy(rarp.arp_tha, arp.arp_sha, ETH_ALEN);
  memcpy(rarp.arp_spa, arp.arp_tpa, 4);
  memcpy(rarp.arp_tpa, arp.arp_spa, 4);
  encodeARP(&rarp, buf + n);
  n += lenARP();

  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    fprintf(stderr, "Fail to socket: %s\n", strerror(errno));
    return;
  }

  addr->sin_port = htons(4789);
  sendto(sockfd, buf, n, 0, (struct sockaddr *)addr, sizeof(struct sockaddr));
  close(sockfd);
}

void setTCPMss(DataView &opts, u_char *buf) {
  std::vector<TCPIPOption> options =
      decodeTCPIPOptions(opts.data(), opts.size());

  TCPIPOption opt = getTCPIPOption(options, TCPIPOptionKind::OK_Mss);
  if (opt.kind != TCPIPOptionKind::OK_Mss)
    return;

  uint16_t mss = ntohs(*(uint16_t *)opt.value.data());
  if (mss <= 1380)
    return;
  else
    mss = htons(1380);
  opt.value = DataView((u_char *)&mss, sizeof(uint16_t));

  setTCPIPOption(options, opt);
  encodeTCPIPOptions(options, buf);
}

void toBackendTCP(int rawFd, TCPConnTuple &t, struct iphdr *ipv4,
                  const u_char *data, size_t len) {
  assert(len >= sizeof(struct tcphdr));

  fprintf(stderr, "TCP request\n");

  size_t n = 0;

  struct tcphdr tcp;
  decodeTCP(&tcp, data);
  n += sizeof(struct tcphdr);
  DataView opts(data + n, lenTCPOptions(&tcp));
  n += lenTCPOptions(&tcp);
  DataView payload(data + n, len - n);

  n = 0;
  u_char buf[ETH_FRAME_LEN];

  struct iphdr ripv4 = *ipv4;
  /// TODO. Apply rule map address.
  inet_pton(AF_INET, "192.168.30.30", &ripv4.daddr);
  encodeIPv4(&ripv4, buf, lenIPv4Hdr(&ripv4));
  n += lenIPv4Hdr(&ripv4);

  n += sizeof(struct tcphdr);
  // memcpy(buf + n, opts.data(), opts.size());
  setTCPMss(opts, buf + n);
  n += opts.size();
  memcpy(buf + n, payload.data(), payload.size());
  n += payload.size();
  encodeTCP(&tcp, &ripv4.saddr, &ripv4.daddr, buf + lenIPv4Hdr(&ripv4),
            n - lenIPv4Hdr(&ripv4));

  sendToTCPIP(rawFd, ripv4.daddr, tcp.dest, buf, n);

  t.dip   = ripv4.daddr;
  t.sip   = ripv4.saddr;
  t.dport = tcp.dest;
  t.sport = tcp.source;
}

void toBackendICMP(const u_char *data, size_t len) {
  size_t n = 0;

  assert(len >= sizeof(struct icmphdr));
  struct icmphdr icmp;
  decodeICMP(&icmp, data);
  n += lenICMPHdr();

  (void)n;
}

void toBackendIPv4(int rawFd, TCPConnTuple &k, TCPConnTuple &v,
                   const u_char *data, size_t len) {
  assert(len >= sizeof(struct iphdr));

  size_t n = 0;

  struct iphdr ipv4;
  decodeIPv4(&ipv4, data);
  if (validIPv4(&ipv4))
    return;
  n += lenIPv4Hdr(&ipv4);

  assert(ipv4.tot_len == len);
  DataView payload(data + n, ipv4.tot_len - n);

  switch (ipv4.protocol) {
  case IPPROTO_ICMP:
    toBackendICMP(payload.data(), payload.size());
    break;
  case IPPROTO_TCP:
    toBackendTCP(rawFd, k, &ipv4, payload.data(), payload.size());
    v     = k;
    v.dip = ipv4.daddr;
    v.sip = ipv4.saddr;
    break;
  default:
      /* do nothing. */;
  }
}

void toBackend(int rawFd, TCPSessions &sessions, struct sockaddr_in *addr,
               const u_char *data, size_t len) {
  size_t n = 0;

  assert(len >= sizeof(struct vxlanhdr));
  struct vxlanhdr vxlan;
  decodeVxlan(&vxlan, data);
  n += lenVxlanHdr();

  assert((len - n) >= sizeof(struct ether_header));
  struct ether_header eth;
  decodeEthernet(&eth, data + n);
  n += lenEthernetHdr();

  DataView payload(data + n, len - n);

  u_char hwaddr[ETH_ALEN] = {52, 54, 0, 4, 65, 14};

  switch (eth.ether_type) {
  case ETHERTYPE_ARP:
    toBackendARP(addr, &vxlan, &eth, hwaddr, payload.data(), payload.size());
    break;
  case ETHERTYPE_IP:
    TCPSession   sess;
    TCPConnTuple k;
    TCPConnTuple v;
    memcpy(&sess.dmac, hwaddr, ETH_ALEN);
    memcpy(&sess.smac, eth.ether_shost, ETH_ALEN);
    sess.vxlanIP   = addr->sin_addr.s_addr;
    sess.vxlanPort = addr->sin_port;
    toBackendIPv4(rawFd, k, v, payload.data(), payload.size());
    sess.oriConn = v;
    sessions[k]  = sess;
    break;
  default:
      /* do nothing. */;
  }
}

void toFrontendTCP(TCPSessions &sessions, int vxlanfd, struct iphdr *ipv4,
                   const u_char *data, size_t len) {
  assert(len >= sizeof(struct tcphdr));

  u_char buf[ETH_FRAME_LEN];
  size_t n = 0;

  struct tcphdr tcp;
  decodeTCP(&tcp, data);
  n += sizeof(struct tcphdr);
  DataView opts(data + n, lenTCPOptions(&tcp));
  n += lenTCPOptions(&tcp);
  DataView payload(data + n, len - n);

  TCPConnTuple t;
  t.dip           = ipv4->saddr;
  t.sip           = ipv4->daddr;
  t.dport         = tcp.source;
  t.sport         = tcp.dest;
  TCPSession sess = sessions[t];

  n = 0;

  struct vxlanhdr rvxlan;
  rvxlan.flags = 0x08;
  rvxlan.vni   = 3;
  encodeVxlan(&rvxlan, buf);
  n += sizeof(struct vxlanhdr);

  struct ether_header reth;
  memcpy(&reth.ether_shost, &sess.dmac, ETH_ALEN);
  memcpy(&reth.ether_dhost, &sess.smac, ETH_ALEN);
  reth.ether_type = ETHERTYPE_IP;
  encodeEthernet(&reth, buf + n);
  n += sizeof(struct ether_header);

  struct iphdr ripv4 = *ipv4;
  ripv4.daddr        = sess.oriConn.sip;
  ripv4.saddr        = sess.oriConn.dip;
  encodeIPv4(&ripv4, buf + n, lenIPv4Hdr(&ripv4));
  n += lenIPv4Hdr(&ripv4);

  n += sizeof(struct tcphdr);
  // memcpy(buf + n, opts.data(), opts.size());
  setTCPMss(opts, buf + n);
  n += opts.size();
  memcpy(buf + n, payload.data(), payload.size());
  n += payload.size();
  size_t lenTCP = sizeof(struct tcphdr) + opts.size() + payload.size();
  encodeTCP(&tcp, &ripv4.saddr, &ripv4.daddr, buf + n - lenTCP, lenTCP);

  struct sockaddr_in addr;
  addr.sin_addr.s_addr = sess.vxlanIP;
  addr.sin_port        = htons(4789);
  if (sendto(vxlanfd, buf, n, 0, (struct sockaddr *)&addr,
             sizeof(struct sockaddr)) < 0) {
    fprintf(stderr, "fuck err=%s\n", strerror(errno));
    return;
  }
}

void toFrontend(TCPSessions &sessions, int vxlanfd, const u_char *data,
                size_t len) {
  assert(len >= sizeof(struct iphdr));

  size_t n = 0;

  struct iphdr ipv4;
  decodeIPv4(&ipv4, data);
  if (validIPv4(&ipv4))
    return;
  n += lenIPv4Hdr(&ipv4);

  assert(ipv4.tot_len == len);
  DataView payload(data + n, ipv4.tot_len - n);

  switch (ipv4.protocol) {
  case IPPROTO_ICMP:
    break;
  case IPPROTO_TCP:
    toFrontendTCP(sessions, vxlanfd, &ipv4, payload.data(), payload.size());
    break;
  default:
      /* do nothing */;
  }
}

class Proxy {
public:
  Proxy(const char *ifname) : ifname_(ifname) {
    rawFd_ = socket(AF_INET, SOCK_RAW, htons(ETH_P_IP));
    if (rawFd_ < 0) {
      fprintf(stderr, "Fail to socket raw: %s\n", strerror(errno));
      return;
    }

    int val = 1;
    if (setsockopt(rawFd_, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) < 0) {
      fprintf(stderr, "Fail to setsockopt: %s\n", strerror(errno));
      return;
    }

    tuntapfd_ = createAndSetupTunTap(IFF_TUN, ifname);
    if (tuntapfd_ < 0) {
      fprintf(stderr, "Fail to createAndSetupTunTap: %s\n", strerror(errno));
      return;
    }

    sockfd_ = socket(AF_INET, SOCK_DGRAM | O_NONBLOCK, 0);
    if (sockfd_ < 0) {
      fprintf(stderr, "Fail to socket: %s\n", strerror(errno));
      return;
    }

    struct sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(4789);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd_, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      fprintf(stderr, "Fail to bind: %s\n", strerror(errno));
      return;
    }

    vxlanFd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (vxlanFd_ < 0) {
      fprintf(stderr, "Fail to socket vxlan: %s\n", strerror(errno));
      return;
    }
  }

  ~Proxy() {
    if (rawFd_ > 0)
      close(rawFd_);
    if (tuntapfd_ > 0)
      close(tuntapfd_);
    if (sockfd_ > 0)
      close(sockfd_);
    if (vxlanFd_ > 0)
      close(vxlanFd_);
  }

  void loop() {
    poller_.addReadableEvent(sockfd_, [=](int fd) { handleVxlan(fd); });
    poller_.addReadableEvent(tuntapfd_, [=](int fd) { handleTunTap(fd); });
    return poller_.loop();
  }

  int addHost(const std::string &addr) {
    struct sockaddr_in s;
    toAddr(addr, &s);
    return addHostRouteTunTap(sockfd_, ifname_.data(), &s);
  }

  int addNet(const std::string &addr, const std::string &mask) {
    struct sockaddr_in s;
    struct sockaddr_in m;

    if (toAddr(addr, &s) < 0)
      return -1;
    if (toAddr(mask, &m) < 0)
      return -1;
    return addNetRouteTunTap(sockfd_, ifname_.data(), &s, &m);
  }

private:
  int toAddr(const std::string &addr, struct sockaddr_in *s) const {
    s->sin_family = AF_INET;
    s->sin_port   = 0;
    return inet_pton(AF_INET, addr.data(), &s->sin_addr);
  }

  void handleVxlan(int fd) {
    u_char buf[ETH_FRAME_LEN];

    struct sockaddr_in raddr;
    socklen_t          len = sizeof(raddr);
    ssize_t            n =
        recvfrom(sockfd_, buf, sizeof(buf), 0, (struct sockaddr *)&raddr, &len);
    if (n < 0) {
      if (errno == EAGAIN)
        return;
      fprintf(stderr, "Fail to recvfrom: (%d)%s\n", errno, strerror(errno));
      return;
    }

    char showaddr[32];
    inet_ntop(AF_INET, &raddr.sin_addr, showaddr, sizeof(raddr));
    fprintf(stderr, "New Vxlan connection addr=%s\n", showaddr);

    toBackend(rawFd_, sessions_, &raddr, buf, n);
  }

  void handleTunTap(int fd) {
    u_char buf[ETH_FRAME_LEN];

    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < 0) {
      if (errno == EAGAIN)
        return;

      fprintf(stderr, "Fail to recvfrom: %s\n", strerror(errno));
      return;
    }

    toFrontend(sessions_, vxlanFd_, buf, n);
  }

  std::string ifname_;
  int         sockfd_;
  int         rawFd_;
  int         tuntapfd_;
  int         vxlanFd_;
  Poll        poller_;
  TCPSessions sessions_;
};

} // namespace vxproxy