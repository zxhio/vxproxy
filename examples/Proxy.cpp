//===- Rroxy.h - Proxy Main Routine --------------------------------------*- C++
//-*-===//
//
/// \file
/// Main manager proxy routine.
//
// Author:  zxh
// Date:    2021/11/21 15:26:06
//===----------------------------------------------------------------------===//

#include <vxproxy/Proxy.h>

using namespace vxproxy;

int main() {
  Proxy p("vxproxy");
  p.addHost("10.0.2.3");
  p.addNet("10.0.0.0", "255.255.255.0");

  p.loop();
}