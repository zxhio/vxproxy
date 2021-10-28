//===- Vxlan.cpp - Vxlan Protocol Routine -----------------------*- C++ -*-===//
//
/// \file
/// Processing vxlan data.
//
// Author:  zxh
// Date:    2021/10/28 21:33:19
//===----------------------------------------------------------------------===//

#include <vxproxy/Packet.h>
#include <vxproxy/Poll.h>
#include <vxproxy/Vxlan.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace vxproxy;

enum LayerDepth {
  LD_VXLAN = 0,
  LD_ETH   = 1,
  LD_ARP   = 2,
  LD_IP    = 2,
  LD_TCP   = 3,
  LD_ICMP  = 3
};

char hwAddr[ETH_ALEN] = {52, 54, 0, 4, 65, 14};

void printIndent(int w) {
  for (int i = 0; i < w; i++)
    fprintf(stderr, "  ");
}

void printEthernet(const struct ether_header *eth) {
  printIndent(LD_ETH);
  fprintf(stderr, "=== Ethernet Layer\n");
  printIndent(LD_ETH + 1);
  fprintf(stderr, "type=%d, src_mac=", eth->ether_type);
  for (int i = 0; i < ETH_ALEN; ++i)
    fprintf(stderr, "%x ", eth->ether_shost[i]);
  fprintf(stderr, ", dst_mac=");
  for (int i = 0; i < ETH_ALEN; ++i)
    fprintf(stderr, "%x ", eth->ether_dhost[i]);

  fprintf(stderr, "\n");
}

void printVxlan(const struct vxlanhdr *vxlan) {
  printIndent(LD_VXLAN);
  fprintf(stderr, "=== Vxlan Layer\n");
  printIndent(LD_VXLAN + 1);
  fprintf(stderr, "id=%u, flags=%d", vxlan->vni, vxlan->flags);
  fprintf(stderr, "\n");
}

void printARP(const struct ether_arp *arp) {
  printIndent(LD_ARP);
  fprintf(stderr, "=== ARP Layer\n");
  printIndent(LD_ARP + 1);
  fprintf(stderr,
          "addr_type=%d, protocol=%d, addr_size=%d, proto_size=%d, op=%d\n",
          arp->ea_hdr.ar_hrd, arp->ea_hdr.ar_pro, arp->ea_hdr.ar_hln,
          arp->ea_hdr.ar_pln, arp->ea_hdr.ar_op);
  printIndent(LD_ARP + 1);
  fprintf(stderr, "src_mac=");
  for (int i = 0; i < ETH_ALEN; ++i)
    fprintf(stderr, "%x ", arp->arp_sha[i]);
  fprintf(stderr, ", src_ip=");
  for (int i = 0; i < 4; ++i)
    fprintf(stderr, "%d.", arp->arp_spa[i]);
  fprintf(stderr, ", dst_mac=");
  for (int i = 0; i < ETH_ALEN; ++i)
    fprintf(stderr, "%x ", arp->arp_tha[i]);
  fprintf(stderr, ", dst_ip=");
  for (int i = 0; i < 4; ++i)
    fprintf(stderr, "%d.", arp->arp_tpa[i]);
}

void printIP(const struct iphdr *ip) {
  printIndent(LD_IP);
  fprintf(stderr, "=== IP Layer\n");
  printIndent(LD_IP + 1);

  char srcIP[32];
  char dstIP[32];
  inet_ntop(AF_INET, &ip->saddr, srcIP, sizeof(srcIP));
  inet_ntop(AF_INET, &ip->daddr, dstIP, sizeof(dstIP));

  fprintf(stderr,
          "protocol=%d, src_ip=%s, dst_ip=%s, headerlen=%zu, checksum=0x%x",
          ip->protocol, srcIP, dstIP, lengthIPv4Header(ip), ip->check);
  fprintf(stderr, "\n");
}

void printICMP(const struct icmphdr *icmp) {
  printIndent(LD_ICMP);
  fprintf(stderr, "=== ICMP Layer:\n");
  printIndent(LD_ICMP + 1);
  fprintf(stderr, "type=%d, code=%d, id=%d, seq=%d, checksum=0x%x", icmp->type,
          icmp->code, icmp->un.echo.id, icmp->un.echo.sequence, icmp->checksum);
  fprintf(stderr, "\n");
}

void replyARP(struct sockaddr_in *addr, const struct vxlanhdr *vxlan,
              const struct ether_header *eth, const struct ether_arp *arp) {
  char replyBuf[1500];

  struct vxlanhdr vxlan1 = *vxlan;
  encodeVxlan(&vxlan1, replyBuf);

  struct ether_header eth1;
  eth1.ether_type = ETHERTYPE_ARP;
  memcpy(eth1.ether_shost, hwAddr, ETH_ALEN);
  memcpy(eth1.ether_dhost, eth->ether_shost, ETH_ALEN);
  encodeEthernet(&eth1, replyBuf + sizeof(vxlan1));

  struct ether_arp arp1 = *arp;
  arp1.ea_hdr.ar_op     = ARPOP_REPLY;
  memcpy(arp1.arp_sha, hwAddr, ETH_ALEN);
  memcpy(arp1.arp_tha, arp->arp_sha, ETH_ALEN);
  memcpy(arp1.arp_spa, arp->arp_tpa, 4);
  memcpy(arp1.arp_tpa, arp->arp_spa, 4);
  encodeARP(&arp1, replyBuf + sizeof(vxlan1) + sizeof(eth1));

  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    fprintf(stderr, "Fail to socket: %s\n", strerror(errno));
    return;
  }

  addr->sin_port = htons(4789);
  sendto(sockfd, replyBuf, sizeof(vxlan1) + sizeof(eth1) + sizeof(arp1), 0,
         (struct sockaddr *)addr, sizeof(struct sockaddr));
}

void replyICMP(struct sockaddr_in *addr, const struct vxlanhdr *vxlan,
               const struct ether_header *eth, const struct iphdr *ip,
               const struct icmphdr *icmp, DataView payload) {
  char replyBuf[1500];

  struct vxlanhdr vxlan1 = *vxlan;
  encodeVxlan(&vxlan1, replyBuf);

  struct ether_header eth1;
  eth1.ether_type = ETHERTYPE_IP;
  memcpy(eth1.ether_shost, hwAddr, ETH_ALEN);
  memcpy(eth1.ether_dhost, eth->ether_shost, ETH_ALEN);
  encodeEthernet(&eth1, replyBuf + sizeof(vxlan1));

  struct iphdr ip1 = *ip;
  ip1.daddr        = ip->saddr;
  ip1.saddr        = ip->daddr;
  encodeIPv4(&ip1, replyBuf + sizeof(vxlan1) + sizeof(eth1),
             lengthIPv4Header(&ip1));

  memcpy(replyBuf + sizeof(vxlan1) + sizeof(eth1) + lengthIPv4Header(&ip1) +
             lengthICMPv4Header(),
         payload.data, payload.len);
  struct icmphdr icmp1 = *icmp;
  icmp1.type           = ICMP_ECHOREPLY;
  // fprintf(stderr, "icmp code: %d, %zu\n", icmp1.code,
  // lengthIPv4Header(&ip1));
  encodeICMP(&icmp1,
             replyBuf + sizeof(vxlan1) + sizeof(eth1) + lengthIPv4Header(&ip1),
             sizeof(vxlan1) + sizeof(eth1) + lengthIPv4Header(&ip1) +
                 lengthICMPv4Header() + payload.len);

  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    fprintf(stderr, "Fail to socket: %s\n", strerror(errno));
    return;
  }

  addr->sin_port = htons(4789);
  sendto(sockfd, replyBuf,
         sizeof(vxlan1) + sizeof(eth1) + lengthIPv4Header(&ip1) +
             lengthICMPv4Header() + payload.len,
         0, (struct sockaddr *)addr, sizeof(struct sockaddr));
}

void handleVxlan(int fd) {
  char               buf[1500];
  struct sockaddr_in raddr;
  socklen_t          len = sizeof(raddr);
  ssize_t            n =
      recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&raddr, &len);
  if (n < 0) {
    fprintf(stderr, "Fail to recvfrom: %s\n", strerror(errno));
    return;
  }

  char showaddr[32];
  inet_ntop(AF_INET, &raddr.sin_addr, showaddr, sizeof(raddr));

  fprintf(stderr, "New connection addr=%s\n", showaddr);

  struct vxlanhdr vxlan;
  decodeVxlan(&vxlan, buf);
  printVxlan(&vxlan);

  struct ether_header eth;
  decodeEthernet(&eth, buf + sizeof(vxlan));
  printEthernet(&eth);

  if (eth.ether_type == ETHERTYPE_ARP) {
    struct ether_arp arp;
    decodeARP(&arp, buf + sizeof(vxlan) + sizeof(eth));
    printARP(&arp);

    replyARP(&raddr, &vxlan, &eth, &arp);
  } else if (eth.ether_type == ETHERTYPE_IP) {
    struct iphdr ip;
    decodeIPv4(&ip, buf + sizeof(vxlan) + sizeof(eth));
    printIP(&ip);

    if (ip.protocol == IPPROTO_ICMP) {
      struct icmphdr icmp;
      decodeICMP(&icmp,
                 buf + sizeof(vxlan) + sizeof(eth) + lengthIPv4Header(&ip));
      printICMP(&icmp);
      replyICMP(&raddr, &vxlan, &eth, &ip, &icmp,
                DataView(buf + sizeof(vxlan) + sizeof(eth) +
                             lengthIPv4Header(&ip) + lengthICMPv4Header(),
                         n - (sizeof(vxlan) + sizeof(eth) +
                              lengthIPv4Header(&ip) + lengthICMPv4Header())));
    }
  }

  fprintf(stderr, "\n");
}

int main() {

  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    fprintf(stderr, "Fail to socket: %s\n", strerror(errno));
    return -1;
  }

  struct sockaddr_in addr;
  addr.sin_family      = AF_INET;
  addr.sin_port        = htons(4789);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    fprintf(stderr, "Fail to bind: %s\n", strerror(errno));
    return -1;
  }

  Poll p;
  p.addReadableEvent(sockfd, handleVxlan);
  p.loop();

  return 0;
}