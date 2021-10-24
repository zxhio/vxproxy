//===- Poll.cpp - Poll sample -----------------------------------*- C++ -*-===//
//
/// \file
/// Show usage for Poll
//
// Author:  zxh
// Date:    2021/10/24 12:29:32
//===----------------------------------------------------------------------===//

#include <vxproxy/Poll.h>

#include <string.h>
#include <unistd.h>

using namespace vxproxy;

void readFile(int fd) {
  char buf[256];
  memset(buf, 0, sizeof(buf));
  ssize_t n = read(fd, buf, sizeof(buf));
  fprintf(stderr, "read file(fd = %d) %ld bytes: %s\n", fd, n, buf);
}
void writeFile(int fd) { fprintf(stderr, "write file\n"); }

int main() {
  Poll p;
  p.addReadableEvent(1, readFile);
  //   p.addWritableEvent(fd, writeFile);
  p.loop();
}