//===- Packet.cpp - Packet Encode/Decode ------------------------*- C++ -*-===//
//
/// \file
/// Encode/Decode TCP/IP layer packet.
//
// Author:  zxh
// Date:    2021/10/24 21:19:24
//===----------------------------------------------------------------------===//

#include <vxproxy/Packet.h>
#include <vxproxy/Route.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

using namespace vxproxy;

enum LayerDepth { LD_IP = 2, LD_TCP = 3, LD_ICMP = 3 };

void printIndent(int w) {
  for (int i = 1; i < w; i++)
    fprintf(stderr, "  ");
}

void handleTCP(const char *tcpdata, size_t tcplen, const uint32_t *saddr,
               const uint32_t *daddr) {
  TCPPacket tcp(tcpdata, tcplen, saddr, daddr);
  if (tcp.decode() < 0)
    return;

  struct tcphdr th = tcp.header();

  char           checkbuf[80];
  struct tcphdr *checktcp = (struct tcphdr *)checkbuf;
  memcpy(checktcp, tcpdata, tcplen);
  checktcp->check = 0;

  printIndent(LD_TCP);
  fprintf(stderr, "=== TCP Layer:\n");
  printIndent(LD_TCP + 1);
  fprintf(stderr,
          "sport=%d, dport=%d, seq=%u, ack_seq=%u, checksum origin="
          "0x%x recacl=0x%x, payload_len=%zu",
          th.source, th.dest, th.seq, th.ack_seq, th.check,
          checksumTCP(checktcp, tcplen, saddr, daddr), tcp.payload.len);
  for (const auto &opt : tcp.options()) {
    fprintf(stderr, "\n");
    printIndent(LD_TCP + 1);
    fprintf(stderr, "kind=%d, length=%d", opt.kind, opt.length);
  }
  fprintf(stderr, "\n");
}

void handleICMP(const char *icmpdata, size_t icmplen) {
  ICMPPacket icmp(icmpdata, icmplen);
  icmp.decode();

  struct icmphdr ih = icmp.header();

  char            checkbuf[80];
  struct icmphdr *checkicmp = (struct icmphdr *)checkbuf;
  memcpy(checkicmp, icmpdata, icmplen);
  checkicmp->checksum = 0;

  printIndent(LD_ICMP);
  fprintf(stderr, "=== ICMP Layer:\n");
  printIndent(LD_ICMP + 1);
  fprintf(stderr, "id=%d, seq=%d, checksum origin=0x%x recacl=0x%x",
          ih.un.echo.id, ih.un.echo.sequence, ih.checksum,
          checksum(checkicmp, icmplen));
  fprintf(stderr, "\n");
}

void reply(int fd, char *data, size_t n) {
  char         replyBuf[1500];
  struct iphdr iph;
  decodeIPv4(&iph, data);

  uint32_t saddr = iph.saddr;
  uint32_t daddr = iph.daddr;
  iph.daddr      = saddr;
  iph.saddr      = daddr;
  encodeIPv4(&iph, replyBuf, sizeof(iph));
  memcpy(replyBuf + sizeof(iph), data + sizeof(iph),
         lenIPv4Hdr(&iph) - sizeof(iph));

  struct icmphdr icmp;
  decodeICMP(&icmp, data + lenIPv4Hdr(&iph));
  icmp.type = ICMP_ECHOREPLY;
  encodeICMP(&icmp, replyBuf + lenIPv4Hdr(&iph), sizeof(icmp));
  memcpy(replyBuf + lenIPv4Hdr(&iph) + sizeof(icmp),
         data + lenIPv4Hdr(&iph) + sizeof(icmp),
         n - lenIPv4Hdr(&iph) - sizeof(icmp));

  write(fd, replyBuf, n);
}

void readTun(int fd) {
  char buf[256];
  memset(buf, 0, sizeof(buf));

  ssize_t n = read(fd, buf, sizeof(buf));
  if (n < 0) {
    fprintf(stderr, "Fail to read: %s\n", strerror(errno));
    return;
  }

  IPv4Packet ip(buf, n);
  if (ip.decode() < 0)
    return;

  char srcIP[32];
  char dstIP[32];

  struct iphdr iph = ip.header();
  inet_ntop(AF_INET, &iph.saddr, srcIP, sizeof(buf));
  inet_ntop(AF_INET, &iph.daddr, dstIP, sizeof(buf));

  char          checkbuf[100];
  struct iphdr *checkip = (struct iphdr *)checkbuf;
  memcpy(checkip, buf, n);
  checkip->check = 0;

  printIndent(2);
  fprintf(stderr, "=== IP Layer\n");
  printIndent(3);
  fprintf(stderr,
          "protocol=%d, src_ip=%s, dst_ip=%s, headerlen=%zu, checksum "
          "origin=0x%x recacl=0x%x",
          iph.protocol, srcIP, dstIP, lenIPv4Hdr(checkip), iph.check,
          checksum(checkip, lenIPv4Hdr(checkip)));
  fprintf(stderr, "\n");

  switch (iph.protocol) {
  case IPPROTO_TCP:
    handleTCP(ip.payload.data, ip.payload.len, &iph.saddr, &iph.daddr);
    break;
  case IPPROTO_ICMP:
    handleICMP(ip.payload.data, ip.payload.len);
    reply(fd, buf, n);
    break;
  default:;
  }
}

int main() {
  vxproxy::Route route("test_foo");
  if (!route.ok()) {
    fprintf(stderr, "Fail to new route: %s\n", strerror(errno));
    return -1;
  }

  int ret = route.addNet("172.23.19.0", "255.255.255.0");
  if (ret < 0) {
    fprintf(stderr, "Fail to add route 172.23.19.0: %s\n", strerror(errno));
    return -1;
  }

  route.setTunRecvHandler(readTun);
  route.loop();
}