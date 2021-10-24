//===- Poll.h - Simple Event driver -----------------------------*- C++ -*-===//
//
/// \file
/// Very simple eventloop handle routine as a transitional use.
//
// Author:  zxh
// Date:    2021/10/24 00:35:52
//===----------------------------------------------------------------------===//

#pragma once

#include <map>
#include <sys/poll.h>
#include <vector>

#include <poll.h>

namespace vxproxy {

using EventHandleFunc = void (*)(int);

struct Event {
  struct pollfd   pfd;
  EventHandleFunc readFunc;
  EventHandleFunc writeFunc;
};

class Poll {
public:
  void addReadableEvent(int fd, EventHandleFunc f) {
    addEvent(fd, POLLIN, f, NULL);
  }

  void delReadableEvent(int fd) { delEvent(fd, POLLIN); }

  void addWritableEvent(int fd, EventHandleFunc f) {
    addEvent(fd, POLLOUT, NULL, f);
  }

  void delWritableEvent(int fd) { delEvent(fd, POLLOUT); }

  void delAllEvent(int fd) { eventMap_.erase(fd); }

  void loop() {
    int timeout = 3000; // ms

    while (1) {
      std::vector<struct pollfd> fds = shapePollFdList();

      int n = poll(fds.data(), fds.size(), timeout);
      if (n > 0) {
        for (auto &pfd : fds)
          handleCallback(pfd);
      }
    }
  }

private:
  void addEvent(int fd, int events, EventHandleFunc rf, EventHandleFunc wf) {
    if (fd < 0)
      return;

    Event ev;
    ev.pfd.fd     = fd;
    ev.pfd.events = events;
    ev.readFunc   = NULL;
    ev.writeFunc  = NULL;

    if (eventMap_.find(fd) != eventMap_.end())
      ev = eventMap_[fd];
    if (events & POLLIN)
      ev.readFunc = rf;
    if (events & POLLOUT)
      ev.writeFunc = wf;
    ev.pfd.revents |= events;

    eventMap_[fd] = ev;
  }

  void delEvent(int fd, int events) {
    if (fd < 0)
      return;

    if (eventMap_.find(fd) == eventMap_.end())
      return;

    Event ev = eventMap_[fd];
    ev.pfd.events &= ~events;
    if (events & POLLIN)
      ev.readFunc = NULL;
    if (events & POLLOUT)
      ev.writeFunc = NULL;
    eventMap_[fd] = ev;
  }

  std::vector<struct pollfd> shapePollFdList() const {
    std::vector<struct pollfd> pfdList;
    for (const auto &ev : eventMap_)
      pfdList.push_back(ev.second.pfd);
    return pfdList;
  }

  void handleCallback(struct pollfd &pfd) {
    if (eventMap_.find(pfd.fd) == eventMap_.end())
      return;

    Event ev = eventMap_[pfd.fd];
    if (ev.pfd.revents & POLLIN && ev.readFunc)
      ev.readFunc(ev.pfd.fd);
    if (ev.pfd.revents & POLLOUT && ev.writeFunc)
      ev.writeFunc(ev.pfd.fd);
  }

  std::map<int, Event> eventMap_;
}; // namespace vxproxy

} // namespace vxproxy