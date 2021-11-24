//===- DataView.h - Pod Data View -------------------------------*- C++ -*-===//
//
/// \file
/// Similar to std::string_view, only includes data and length, and some common
/// methods.
//
// Author:  zxh
// Date:    2021/11/21 17:16:19
//===----------------------------------------------------------------------===//

#pragma once

#include <stddef.h>
#include <sys/types.h>

namespace vxproxy {

class DataView {
public:
  DataView() : DataView(nullptr, 0) {}
  DataView(const DataView &dv) { *this = DataView(dv.data_, dv.len_); }
  DataView &operator=(const DataView &dv) {
    this->data_ = dv.data_;
    this->len_  = dv.len_;
    return *this;
  }
  DataView(const u_char *data, size_t n) : data_(data), len_(n) {}

  size_t size() const { return len_; }

  const u_char *data() const { return data_; }

private:
  const u_char *data_;
  size_t        len_;
};

} // namespace vxproxy