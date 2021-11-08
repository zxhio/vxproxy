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
#include <vxproxy/Route.h>
#include <vxproxy/Vxlan.h>

#include <map>
#include <thread>

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace vxproxy;

int rawFd = -1;

enum LayerDepth {
  LD_VXLAN = 0,
  LD_ETH   = 1,
  LD_ARP   = 2,
  LD_IP    = 2,
  LD_TCP   = 3,
  LD_ICMP  = 3
};

char hwAddr[ETH_ALEN] = {52, 54, 0, 4, 65, 14};

struct TcpSession {
  char     smac[ETH_ALEN];
  char     dmac[ETH_ALEN];
  uint16_t sport;
  uint16_t dport;
  uint32_t sip;
  uint32_t dip;
  uint16_t vxlan_port;
  uint32_t vxlan_ip;
};

struct TcpTuple {
  uint16_t sport;
  uint16_t dport;
  uint32_t sip;
  uint32_t dip;
};

struct TCPCmp {
  bool operator()(const TcpTuple &lhs, const TcpTuple &rhs) const {
    if (lhs.dip < rhs.dip)
      return true;
    if (lhs.sip < rhs.sip)
      return true;
    if (lhs.sport < rhs.sport)
      return true;
    if (lhs.dport < rhs.dport)
      return true;
    return false;
  }
};

std::map<TcpTuple, TcpSession, TCPCmp> sessions;

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
          "protocol=%d, src_ip=%s, dst_ip=%s, headerlen=%zu, total_len=%d "
          "checksum=0x%x",
          ip->protocol, srcIP, dstIP, lenIPv4Hdr(ip), ip->tot_len, ip->check);
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

void printTCP(const struct tcphdr *tcp) {
  printIndent(LD_TCP);
  fprintf(stderr, "=== TCP Layer:\n");
  printIndent(LD_TCP + 1);
  fprintf(stderr,
          "src_port=%d, dst_port=%d, seq=%u, ack_seq=%u, headerlen=%zu, "
          "syn=%d, ack=%d, fin=%d, rst=%d, psh=%d, check=%0x\n",
          tcp->source, tcp->dest, tcp->seq, tcp->ack_seq, lenTCPHdr(tcp),
          tcp->syn, tcp->ack, tcp->fin, tcp->rst, tcp->psh, tcp->check);
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
  char   replyBuf[1500];
  size_t len = 0;

  struct vxlanhdr vxlan1 = *vxlan;
  encodeVxlan(&vxlan1, replyBuf);
  len += lenVxlanHdr();

  struct ether_header eth1;
  eth1.ether_type = ETHERTYPE_IP;
  memcpy(eth1.ether_shost, hwAddr, ETH_ALEN);
  memcpy(eth1.ether_dhost, eth->ether_shost, ETH_ALEN);
  encodeEthernet(&eth1, replyBuf + len);
  len += lenEthernetHdr();

  struct iphdr ip1 = *ip;
  ip1.daddr        = ip->saddr;
  ip1.saddr        = ip->daddr;
  encodeIPv4(&ip1, replyBuf + len, lenIPv4Hdr(ip));
  len += lenIPv4Hdr(ip);

  struct icmphdr icmp1 = *icmp;
  icmp1.type           = ICMP_ECHOREPLY;
  memcpy(replyBuf + len + sizeof(icmp1), payload.data, payload.len);
  encodeICMP(&icmp1, replyBuf + len, lenICMPHdr() + payload.len);
  len += lenICMPHdr() + payload.len;

  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    fprintf(stderr, "Fail to socket: %s\n", strerror(errno));
    return;
  }

  addr->sin_port = htons(4789);
  sendto(sockfd, replyBuf, len, 0, (struct sockaddr *)addr,
         sizeof(struct sockaddr));
}

void set_tcp_mss(struct tcphdr *tcph, uint32_t pkt_max) {
  uint32_t optlen, i;
  uint8_t *op;
  uint16_t newmss;

  if (!tcph->syn) {
    return;
  }

  optlen = lenTCPHdr(tcph) - sizeof(struct tcphdr);
  if (!optlen || (optlen > pkt_max - sizeof(struct tcphdr))) {
    return;
  }

  op = ((uint8_t *)tcph + sizeof(struct tcphdr));
  for (i = 0; i < optlen;) {
    if ((op[i] == 2) && ((optlen - i) >= 4) && (op[i + 1] == 4) &&
        (i + 3 < pkt_max - sizeof(struct tcphdr))) {
      uint16_t mssval;

      mssval = (op[i + 2] << 8) | op[i + 3];

      if (mssval > 1380)
        newmss = htons(1380);
      else
        return;

      op[i + 2] = newmss & 0xFF;
      op[i + 3] = (newmss & 0xFF00) >> 8;

      return;
    }

    if (op[i] < 2) {
      i++;
    } else {
      i += op[i + 1] ?: 1;
    }
  }

  return;
}

void forwardTCP(TcpSession *sess, struct sockaddr_in *addr,
                const struct iphdr *ip, const struct tcphdr *tcp,
                DataView payload) {

  char   replyBuf[1600];
  size_t len = 0;

  struct iphdr ip1 = *ip;
  // 10.0.0.3, source address.
  // inet_pton(AF_INET, "172.13.11.2", &ip1.saddr);

  // 172.17.0.2:80, nginx server address.
  inet_pton(AF_INET, "192.168.31.55", &ip1.daddr);
  encodeIPv4(&ip1, replyBuf, lenIPv4Hdr(&ip1));
  len += lenIPv4Hdr(&ip1);

  struct tcphdr *tcp1 = (struct tcphdr *)(replyBuf + len);
  *tcp1               = *tcp;
  memcpy(replyBuf + len + sizeof(struct tcphdr), payload.data, payload.len);
  set_tcp_mss(tcp1, sizeof(struct tcphdr) + payload.len);
  encodeTCP(tcp1, &ip1.saddr, &ip1.daddr, replyBuf + len,
            sizeof(struct tcphdr) + payload.len);
  len += sizeof(struct tcphdr) + payload.len;

  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family      = AF_INET;
  sin.sin_addr.s_addr = ip1.daddr;
  sin.sin_port        = tcp1->dest;

  if (sendto(rawFd, replyBuf, len, 0, (struct sockaddr *)&sin, sizeof(sin)) <
      0) {
    fprintf(stderr, "Fail to sendto raw socket: %s\n", strerror(errno));
    return;
  }

  TcpTuple tp;
  tp.dip   = ip1.daddr;
  tp.sip   = ip1.saddr;
  tp.dport = tcp->dest;
  tp.sport = tcp->source;

  // char srcIP[32];
  // char dstIP[32];
  // inet_ntop(AF_INET, &tp.sip, srcIP, sizeof(srcIP));
  // inet_ntop(AF_INET, &tp.dip, dstIP, sizeof(dstIP));
  // fprintf(stderr, "dip=%s dport=%d sip=%s sport=%d\n", dstIP, tp.dport,
  // srcIP,
  //         tp.sport);

  sessions[tp] = *sess;
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

  size_t          l = 0;
  struct vxlanhdr vxlan;
  decodeVxlan(&vxlan, buf);
  l += lenVxlanHdr();
  // printVxlan(&vxlan);

  struct ether_header eth;
  decodeEthernet(&eth, buf + sizeof(vxlan));
  l += lenEthernetHdr();
  // printEthernet(&eth);

  if (eth.ether_type == ETHERTYPE_ARP) {
    struct ether_arp arp;
    decodeARP(&arp, buf + sizeof(vxlan) + sizeof(eth));
    l += lenARP();
    // printARP(&arp);

    replyARP(&raddr, &vxlan, &eth, &arp);
  } else if (eth.ether_type == ETHERTYPE_IP) {
    struct iphdr ip;
    decodeIPv4(&ip, buf + sizeof(vxlan) + sizeof(eth));
    l += lenIPv4Hdr(&ip);
    // printIP(&ip);

    if (ip.protocol == IPPROTO_ICMP) {
      struct icmphdr icmp;
      decodeICMP(&icmp, buf + l);
      l += lenICMPHdr();
      // printICMP(&icmp);
      replyICMP(&raddr, &vxlan, &eth, &ip, &icmp, DataView(buf + l, n - l));
    } else if (ip.protocol == IPPROTO_TCP) {
      struct tcphdr tcp;
      decodeTCP(&tcp, buf + l);
      l += sizeof(tcp);
      // printTCP(&tcp);

      TcpSession sess;
      memcpy(&sess.dmac, hwAddr, ETH_ALEN);
      memcpy(&sess.smac, eth.ether_shost, ETH_ALEN);
      sess.dip        = ip.daddr;
      sess.sip        = ip.saddr;
      sess.dport      = tcp.dest;
      sess.sport      = tcp.source;
      sess.vxlan_port = raddr.sin_port;
      sess.vxlan_ip   = raddr.sin_addr.s_addr;

      forwardTCP(&sess, &raddr, &ip, &tcp, DataView(buf + l, n - l));
    }
  }

  fprintf(stderr, "\n");
}

void backwardTCP(int fd) {
  char    buf[1600];
  ssize_t n = read(fd, buf, sizeof(buf));
  if (n < 0) {
    fprintf(stderr, "Fail to recvfrom: %s\n", strerror(errno));
    return;
  }

  fprintf(stderr, "recv %ld bytes\n", n);

  struct iphdr ip;
  size_t       l = 0;
  decodeIPv4(&ip, buf);
  if (validIPv4(&ip) < 0)
    return;
  l += lenIPv4Hdr(&ip);
  printIP(&ip);

  struct tcphdr tcp;
  decodeTCP(&tcp, buf + l);
  printTCP(&tcp);

  l = 0;
  char            backwardBuf[1600];
  struct vxlanhdr vxlan;
  vxlan.flags = 0x8;
  vxlan.vni   = 3;
  encodeVxlan(&vxlan, backwardBuf);
  l += sizeof(struct vxlanhdr);

  TcpTuple tp;
  tp.dip          = ip.saddr;
  tp.sip          = ip.daddr;
  tp.dport        = tcp.source;
  tp.sport        = tcp.dest;
  TcpSession sess = sessions[tp];

  struct ether_header eth;
  memcpy(&eth.ether_shost, &sess.dmac, ETH_ALEN);
  memcpy(&eth.ether_dhost, &sess.smac, ETH_ALEN);
  eth.ether_type = ETHERTYPE_IP;
  encodeEthernet(&eth, backwardBuf + l);
  l += sizeof(struct ether_header);
  printEthernet(&eth);

  ip.daddr = sess.sip;
  ip.saddr = sess.dip;
  encodeIPv4(&ip, backwardBuf + l, lenIPv4Hdr(&ip));
  l += lenIPv4Hdr(&ip);
  printIP(&ip);

  struct tcphdr *th = (struct tcphdr *)(backwardBuf + l);
  memcpy(backwardBuf + l, buf + lenIPv4Hdr(&ip), n - lenIPv4Hdr(&ip));
  *th = tcp;
  encodeTCP(th, &ip.saddr, &ip.daddr, backwardBuf + l, n - lenIPv4Hdr(&ip));
  l += (n - lenIPv4Hdr(&ip));

  printTCP(&tcp);
  printTCP(th);

  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    fprintf(stderr, "Fail to socket: %s\n", strerror(errno));
    return;
  }

  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family      = AF_INET;
  sin.sin_addr.s_addr = sess.vxlan_ip;
  sin.sin_port        = htons(4789);

  if (sendto(sockfd, backwardBuf, l, 0, (struct sockaddr *)&sin, sizeof(sin)) <
      0) {
    fprintf(stderr, "Fail to sendto vxlan socket: %s\n", strerror(errno));
    return;
  }
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

  rawFd = socket(AF_INET, SOCK_RAW, htons(ETH_P_IP));
  if (rawFd < 0) {
    fprintf(stderr, "Fail to socket raw: %s\n", strerror(errno));
    return -1;
  }

  int val = 1;
  if (setsockopt(rawFd, IPPROTO_IP, IP_HDRINCL, &val, sizeof(val)) < 0) {
    fprintf(stderr, "Fail to setsockopt: %s\n", strerror(errno));
    return -1;
  }

  vxproxy::Route route("test_vxproxy");
  if (!route.ok()) {
    fprintf(stderr, "Fail to new route: %s\n", strerror(errno));
    return -1;
  }

  route.addHost("10.0.0.3");
  route.setTunRecvHandler(backwardTCP);

  std::thread t([&]() { route.loop(); });

  Poll p;
  p.addReadableEvent(sockfd, handleVxlan);
  p.loop();

  t.join();

  return 0;
}