#include <vxproxy/TunTap.h>

#include <chrono>
#include <thread>

using namespace vxproxy;

int main() {
  // vxproxy::TunTap<vxproxy::TunTapType::Tun> tt("fuck_tun");
  vxproxy::TunDevice tt("fuck_tun");
  vxproxy::TapDevice tp("fuck_tap");

  std::this_thread::sleep_for(std::chrono::seconds(10));
}