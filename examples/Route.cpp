//===- Route.cpp - Route Address Operate routine ----------------*- C++ -*-===//
//
/// \file
/// Route sample.
//
// Author:  zxh
// Date:    2021/10/24 14:15:57
//===----------------------------------------------------------------------===//

#include <vxproxy/Route.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

void readFile(int fd) {
  char buf[256];
  memset(buf, 0, sizeof(buf));
  ssize_t n = read(fd, buf, sizeof(buf));
  fprintf(stderr, "read file(fd = %d) %ld bytes\n", fd, n);
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

  ret = route.addHost("192.168.110.200");
  if (ret < 0) {
    fprintf(stderr, "Fail to add route 172.23.110.200: %s\n", strerror(errno));
    return -1;
  }

  route.setTunRecvHandler(readFile);
  route.loop();
}