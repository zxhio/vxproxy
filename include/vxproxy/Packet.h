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

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>

namespace vxproxy {

struct DataView {
  DataView() : DataView(NULL, 0) {}
  DataView(const char *data, size_t n) : data(data), len(n) {}

  const char *data;
  size_t      len;
};

// Basic packet interface.
// TODO, define packer encode/decode error code.
class Packet {
public:
  Packet(const char *data, size_t n) : content_(data, n), payload_(NULL, 0) {}

  virtual int encode(char *to, size_t len) const = 0;
  virtual int decode()                           = 0;

  DataView payload() const { return payload_; }

  DataView content_;
  DataView payload_;
};

class Ethernet : public Packet {
public:
  Ethernet(const char *data, size_t n) : Packet(data, n) {}

  virtual int encode(char *to, size_t len) const {
    if (len < 14)
      return -1;

    char *p = to;
    memcpy(p, h_.ether_dhost, ETH_ALEN);
    p += ETH_ALEN;
    memcpy(p, h_.ether_shost, ETH_ALEN);
    p += ETH_ALEN;
    *(uint16_t *)p = htons(h_.ether_type);

    return 0;
  };

  virtual int decode() {
    if (content_.len < 14)
      return -1;

    const char *p = content_.data;
    memcpy(h_.ether_dhost, p, ETH_ALEN);
    p += ETH_ALEN;
    memcpy(h_.ether_shost, p + ETH_ALEN, ETH_ALEN);
    p += ETH_ALEN;
    h_.ether_type = ntohs(*(uint16_t *)p);
    p += 2;

    payload_.data = p;
    payload_.len  = content_.data + content_.len - p;

    return 0;
  }

  struct ether_header header() const {
    return h_;
  }

private:
  struct ether_header h_;
};

class IPv4 : public Packet {
public:
  IPv4(const char *data, size_t n) : Packet(data, n) {}

  virtual int encode(char *to, size_t len) const { return 0; }

  virtual int decode() {
    if (content_.len < 20)
      return -1;

    const char *p = content_.data;

    h_.version  = *(uint8_t *)p >> 4;
    h_.ihl      = *(uint8_t *)p & 0x0F;
    h_.tos      = *(uint8_t *)(p + 1);
    h_.tot_len  = ntohs(*(uint16_t *)(p + 2));
    h_.id       = ntohs(*(uint16_t *)(p + 4));
    h_.frag_off = ntohs(*(uint16_t *)(p + 6)) & 0x1FFF;
    h_.ttl      = *(uint8_t *)(p + 8);
    h_.protocol = *(uint8_t *)(p + 9);
    h_.check    = ntohs(*(uint16_t *)(p + 10));
    h_.saddr    = *(uint32_t *)(p + 12);
    h_.daddr    = *(uint32_t *)(p + 16);

    if (h_.tot_len < 20)
      return -1;
    else if (h_.ihl < 5)
      return -1;
    else if (h_.ihl * 4 > h_.tot_len)
      return -1;

    // TODO, decode options into structure.
    options_.data = p + 20;
    options_.len  = h_.ihl * 4 - 20;

    payload_.data = p + h_.ihl * 4;
    payload_.len  = h_.tot_len - h_.ihl;

    return 0;
  }

  struct iphdr header() const {
    return h_;
  }

private:
  struct iphdr h_;
  DataView     options_;
};

class TCP : public Packet {
public:
  TCP(const char *data, size_t n) : Packet(data, n) {}

  virtual int encode(char *to, size_t len) const { return 0; }

  virtual int decode() {
    if (content_.len < 20)
      return -1;

    const char *p = content_.data;

    h_.source  = ntohs(*(uint16_t *)p);
    h_.dest    = ntohs(*(uint16_t *)(p + 2));
    h_.seq     = ntohl(*(uint32_t *)(p + 4));
    h_.ack_seq = ntohl(*(uint32_t *)(p + 8));
    h_.doff    = *(uint8_t *)(p + 12) >> 4;
    h_.fin     = *(uint8_t *)(p + 13) & 0x01;
    h_.syn     = *(uint8_t *)(p + 13) & 0x02;
    h_.rst     = *(uint8_t *)(p + 13) & 0x04;
    h_.psh     = *(uint8_t *)(p + 13) & 0x08;
    h_.ack     = *(uint8_t *)(p + 13) & 0x10;
    h_.urg     = *(uint8_t *)(p + 13) & 0x20;
    h_.window  = ntohs(*(uint16_t *)(p + 14));
    h_.check   = ntohs(*(uint16_t *)(p + 16));
    h_.urg_ptr = ntohs(*(uint16_t *)(p + 18));

    options_.data = p + 20;
    options_.len  = h_.doff * 4 - 20;

    payload_.data = p + h_.doff * 4;
    payload_.len  = content_.len - h_.doff;

    return 0;
  }

  struct tcphdr header() const {
    return h_;
  }

private:
  struct tcphdr h_;
  DataView      options_;
};

} // namespace vxproxy