//===- Vxlan.h - Vxlan Protocol ---------------------------------*- C++ -*-===//
//
/// \file
/// Separate processing of Vxlan protocol.
//
// Author:  zxh
// Date:    2021/10/27 22:14:24
//===----------------------------------------------------------------------===//

#pragma once

#include <arpa/inet.h>
#include <stdint.h>

namespace vxproxy {

/*
 * VXLAN protocol (RFC 7348) header:
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |R|R|R|R|I|R|R|R|               Reserved                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                VXLAN Network Identifier (VNI) |   Reserved    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * I = VXLAN Network Identifier (VNI) present.
 */

struct vxlanhdr {
  uint32_t flags : 8;
  uint32_t reserved1 : 24;
  uint32_t vni : 24;
  uint32_t reserved2 : 8;
};

static inline void decodeVxlan(struct vxlanhdr *vxlan, const u_char *data) {
  u_char id[4] = {0, data[4], data[5], data[6]};
  vxlan->flags = *(uint8_t *)data;
  vxlan->vni   = ntohl(*(uint32_t *)id);
}

static inline void encodeVxlan(const struct vxlanhdr *vxlan, u_char *data) {
  uint8_t id[4];
  *(uint32_t *)id = htonl(vxlan->vni);

  *(uint64_t *)data = 0;
  *data             = vxlan->flags;
  *(data + 4)       = id[1];
  *(data + 5)       = id[2];
  *(data + 6)       = id[3];
}

static inline size_t lenVxlanHdr() { return sizeof(vxlanhdr); }

} // namespace vxproxy