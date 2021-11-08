//===- Packet.h - Packet Encode/Decode Interface ----------------*- C++ -*-===//
//
/// \file
/// Encode/Decode Packet to TCP/IP Layer struct.
//
// Author:  zxh
// Date:    2021/10/24 19:35:03
//===----------------------------------------------------------------------===//

#pragma once

#include <string>
#include <vector>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <string.h>

namespace vxproxy {

static inline uint32_t sum(const void *data, size_t n, uint32_t csum) {
  const uint8_t *p = (const uint8_t *)data;

  while (n > 1) {
    csum += *p++ << 8;
    csum += *p++;
    n -= 2;
  }

  if (n)
    csum += *(const uint8_t *)p;

  while (csum >> 16)
    csum = (csum & 0xFFFF) + (csum >> 16);

  return csum;
}

static inline uint16_t checksum(const void *data, size_t n, uint32_t csum) {
  return (uint16_t)~sum(data, n, csum);
}

static inline uint16_t checksum(const void *data, size_t n) {
  return checksum(data, n, 0);
}

static inline uint16_t checksumTCP(const void *tcph, size_t n,
                                   const uint32_t *saddr,
                                   const uint32_t *daddr) {
  char pseudo[12];

  memcpy(pseudo, saddr, 4);
  memcpy(pseudo + 4, daddr, 4);
  pseudo[8]  = 0;
  pseudo[9]  = IPPROTO_TCP;
  pseudo[10] = (n >> 8) & 0xFF;
  pseudo[11] = (n & 0xFF);

  return checksum(tcph, n, sum(pseudo, sizeof(pseudo), 0));
}

static inline void decodeEthernet(struct ether_header *eth, const char *data) {
  struct ether_header *h = (struct ether_header *)data;
  memcpy(eth->ether_dhost, h->ether_dhost, ETH_ALEN);
  memcpy(eth->ether_shost, h->ether_shost, ETH_ALEN);
  eth->ether_type = ntohs(h->ether_type);
}

static inline void encodeEthernet(const struct ether_header *eth, char *data) {
  struct ether_header *h = (struct ether_header *)data;
  memcpy(h->ether_dhost, eth->ether_dhost, ETH_ALEN);
  memcpy(h->ether_shost, eth->ether_shost, ETH_ALEN);
  h->ether_type = htons(eth->ether_type);
}

static inline constexpr size_t lenEthernetHdr() {
  return sizeof(struct ether_header);
}

static inline void decodeARP(struct ether_arp *arp, const char *data) {
  struct ether_arp *h = (struct ether_arp *)data;
  memcpy(arp, h, sizeof(struct ether_arp));
  arp->ea_hdr.ar_hrd = ntohs(h->ea_hdr.ar_hrd);
  arp->ea_hdr.ar_pro = ntohs(h->ea_hdr.ar_pro);
  arp->ea_hdr.ar_op  = ntohs(h->ea_hdr.ar_op);
}

static inline void encodeARP(const struct ether_arp *arp, char *data) {
  struct ether_arp *h = (struct ether_arp *)data;
  memcpy(h, arp, sizeof(struct ether_arp));
  h->ea_hdr.ar_hrd = htons(arp->ea_hdr.ar_hrd);
  h->ea_hdr.ar_pro = htons(arp->ea_hdr.ar_pro);
  h->ea_hdr.ar_op  = htons(arp->ea_hdr.ar_op);
}

static inline constexpr size_t lenARP() { return sizeof(struct ether_arp); }

static inline void decodeIPv4(struct iphdr *ip, const char *data) {
  struct iphdr *h = (struct iphdr *)data;
  memcpy(ip, h, sizeof(struct iphdr));
  ip->tot_len  = ntohs(h->tot_len);
  ip->id       = ntohs(h->id);
  ip->frag_off = ntohs(h->frag_off);
  ip->check    = ntohs(h->check);
}

static inline void encodeIPv4(const struct iphdr *ip, char *data, size_t n) {
  struct iphdr *h = (struct iphdr *)data;
  memcpy(h, ip, sizeof(struct iphdr));
  h->tot_len  = htons(ip->tot_len);
  h->id       = htons(ip->id);
  h->frag_off = htons(ip->frag_off);
  h->check    = 0;
  h->check    = htons(checksum(h, n));
}

static inline constexpr size_t lenIPv4Hdr(const struct iphdr *ip) {
  return ip->ihl * 4;
}

static inline int validIPv4(const struct iphdr *ip) {
  if (lenIPv4Hdr(ip) < sizeof(struct iphdr))
    return -1;
  else if (ip->tot_len < sizeof(struct iphdr))
    return -1;
  else if (ip->tot_len < lenIPv4Hdr(ip))
    return -1;
  return 0;
}

static inline void decodeTCP(struct tcphdr *tcp, const char *data) {
  struct tcphdr *h = (struct tcphdr *)data;
  memcpy(tcp, h, sizeof(struct tcphdr));
  tcp->source  = ntohs(h->source);
  tcp->dest    = ntohs(h->dest);
  tcp->seq     = ntohl(h->seq);
  tcp->ack_seq = ntohl(h->ack_seq);
  tcp->window  = ntohs(h->window);
  tcp->check   = ntohs(h->check);
  tcp->urg_ptr = ntohs(h->urg_ptr);
}

static inline void encodeTCP(const struct tcphdr *tcp, const uint32_t *saddr,
                             const uint32_t *daddr, char *data, size_t n) {
  struct tcphdr *h = (struct tcphdr *)data;
  memcpy(h, tcp, sizeof(struct tcphdr));
  h->source  = htons(tcp->source);
  h->dest    = htons(tcp->dest);
  h->seq     = htonl(tcp->seq);
  h->ack_seq = htonl(tcp->ack_seq);
  h->window  = htons(tcp->window);
  h->urg_ptr = htons(tcp->urg_ptr);
  h->check   = 0;
  h->check   = htons(checksumTCP(tcp, n, saddr, daddr));
}

static inline size_t lenTCPHdr(const struct tcphdr *tcp) {
  return tcp->doff * 4;
}

static inline void decodeICMP(struct icmphdr *icmp, const char *data) {
  struct icmphdr *h      = (struct icmphdr *)data;
  icmp->type             = h->type;
  icmp->code             = h->code;
  icmp->checksum         = ntohs(h->checksum);
  icmp->un.echo.id       = ntohs(h->un.echo.id);
  icmp->un.echo.sequence = ntohs(h->un.echo.sequence);
}

static inline void encodeICMP(const struct icmphdr *icmp, const char *data,
                              size_t n) {
  struct icmphdr *h   = (struct icmphdr *)data;
  h->type             = icmp->type;
  h->code             = icmp->code;
  h->un.echo.id       = htons(icmp->un.echo.id);
  h->un.echo.sequence = htons(icmp->un.echo.sequence);
  h->checksum         = 0;
  h->checksum         = htons(checksum(h, n));
}

static inline constexpr size_t lenICMPHdr() { return sizeof(struct icmphdr); }

struct DataView {
  DataView() : DataView(NULL, 0) {}
  DataView(const char *data, size_t n) : data(data), len(n) {}

  const char *data;
  size_t      len;
};

enum OptionKind : uint8_t { EndOfList = 0, NoOperation };

struct TCPIPOption {
  TCPIPOption(uint8_t k, uint8_t l) : kind(k), length(l) {}

  uint8_t  kind;
  uint8_t  length;
  DataView data;
};

static inline std::vector<TCPIPOption> decodeTCPIPOptions(const char *data,
                                                          size_t      n) {
  std::vector<TCPIPOption> options;
  if (n == 0)
    return std::vector<TCPIPOption>();

  const char *p = data;

  bool nol = false;
  while (p != data + n && !nol) {
    options.push_back(TCPIPOption(*(uint8_t *)p, 1));
    auto &opt = options.back();
    switch (opt.kind) {
    case OptionKind::EndOfList:
      nol = true;
      break;
    case OptionKind::NoOperation:
      break;
    default:
      opt.length = *(uint8_t *)(p + 1);
      opt.data   = DataView(p + 2, opt.length - 2);
    }
    p += opt.length;
  }

  return options;
}

// Basic packet interface.
// TODO, define packer encode/decode error code.
struct Packet {
  Packet(const char *data, size_t n) : content(data, n), payload(NULL, 0) {}

  virtual int    encode(char *to, size_t len) const = 0;
  virtual int    decode()                           = 0;
  virtual size_t headerLen() const                  = 0;

  const char *data() const { return content.data; }
  size_t      len() const { return content.len; }

  // DataView payload() const { return payload; }

  DataView content;
  DataView payload;
};

class EthernetPacket : public Packet {
public:
  EthernetPacket(const char *data, size_t n) : Packet(data, n) {}

  virtual int encode(char *to, size_t len) const {
    if (len < sizeof(struct ether_header))
      return -1;

    encodeEthernet(&eth_, to);

    return 0;
  };

  virtual int decode() {
    if (len() < sizeof(struct ether_header))
      return -1;

    decodeEthernet(&eth_, data());

    payload = DataView(data() + headerLen(), len() - headerLen());

    return 0;
  }

  virtual size_t headerLen() const { return lenEthernetHdr(); }

  struct ether_header header() const {
    return eth_;
  }

private:
  struct ether_header eth_;
};

class IPv4Packet : public Packet {
public:
  IPv4Packet(const char *data, size_t n) : Packet(data, n) {}

  virtual int encode(char *to, size_t len) const {
    encodeIPv4(&ip_, to, len);
    return 0;
  }

  virtual int decode() {
    if (len() < sizeof(struct iphdr))
      return -1;

    // TODO, check len
    decodeIPv4(&ip_, data());

    int vaild = validIPv4(&ip_);
    if (vaild < 0)
      return vaild;

    options_ = decodeTCPIPOptions(data() + 20, headerLen() - 20);
    payload  = DataView(data() + headerLen(), len() - headerLen());

    return 0;
  }

  virtual size_t headerLen() const { return lenIPv4Hdr(&ip_); }

  struct iphdr header() const {
    return ip_;
  }

  const std::vector<TCPIPOption> &options() const { return options_; }

private:
  struct iphdr             ip_;
  std::vector<TCPIPOption> options_;
};

class TCPPacket : public Packet {
public:
  TCPPacket(const char *data, size_t n, const uint32_t *saddr,
            const uint32_t *daddr)
      : Packet(data, n), saddr_(saddr), daddr_(daddr) {}

  virtual int encode(char *to, size_t len) const {
    encodeTCP(&tcp_, saddr_, daddr_, to, len);
    return 0;
  }

  virtual int decode() {
    if (len() < sizeof(struct tcphdr))
      return -1;

    // TODO, check len
    decodeTCP(&tcp_, data());

    options_ = decodeTCPIPOptions(data() + 20, headerLen() - 20);
    payload  = DataView(data() + headerLen(), len() - headerLen());

    return 0;
  }

  virtual size_t headerLen() const { return lenTCPHdr(&tcp_); }

  struct tcphdr header() const {
    return tcp_;
  }

  const std::vector<TCPIPOption> &options() const { return options_; }

private:
  const uint32_t *         saddr_;
  const uint32_t *         daddr_;
  struct tcphdr            tcp_;
  std::vector<TCPIPOption> options_;
};

class ICMPPacket : public Packet {
public:
  ICMPPacket(const char *data, size_t n) : Packet(data, n) {}

  virtual int encode(char *to, size_t n) const {
    if (n < 8)
      return -1;

    encodeICMP(&icmp_, to, n);

    return 0;
  }

  virtual int decode() {
    if (len() < 8)
      return -1;

    // TODO, check len
    decodeICMP(&icmp_, data());

    payload = DataView(data() + headerLen(), len() - headerLen());

    return 0;
  }

  struct icmphdr header() const {
    return icmp_;
  }

  virtual size_t headerLen() const { return lenICMPHdr(); }

private:
  struct icmphdr icmp_;
};

} // namespace vxproxy