#pragma once

#include <string>

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace vxproxy {

int tuntapAlloc(const char *name, int flags) {
  struct ifreq ifr;

  int fd = open("/dev/net/tun", O_RDWR);
  if (fd < 0)
    return fd;

  ifr.ifr_flags = flags;
  std::copy(name, name + IFNAMSIZ, ifr.ifr_name);

  int err = ioctl(fd, TUNSETIFF, (void *)&ifr);
  if (err < 0) {
    close(fd);
    return err;
  }

  return fd;
}

enum TunTapType { Tun = IFF_TUN, Tap = IFF_TAP };

template <TunTapType t> class TunTap {
public:
  TunTap(const char *name) : fd_(-1), type_(t), name_(name) {}

  int alloc() {
    struct ifreq ifr;

    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
      return fd;

    ifr.ifr_flags = type_ | IFF_NO_PI;
    std::copy(name_.data(), name_.data() + IFNAMSIZ, ifr.ifr_name);

    int err = ioctl(fd, TUNSETIFF, (void *)&ifr);
    if (err < 0) {
      close(fd);
      return err;
    }

    fd_ = fd;
    return fd;
  }

  bool up() const { return true; }

  bool down() const { return false; }

private:
  int         fd_;
  TunTapType  type_;
  std::string name_;
};

using TunDevice = TunTap<TunTapType::Tun>;
using TapDevice = TunTap<TunTapType::Tap>;

} // namespace vxproxy