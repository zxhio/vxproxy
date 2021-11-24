//===- Test.h - Test Common Header ------------------------------*- C++ -*-===//
//
/// \file
/// Common test helper macro.
//
// Author:  zxh
// Date:    2020/07/09 23:18:23
//===----------------------------------------------------------------------===//

#pragma once

#include <iostream>
#include <string>

static int test_count = 0;
static int test_pass  = 0;

template <typename T, typename U,
          typename std::enable_if<std::is_integral<T>::value ||
                                      std::is_floating_point<T>::value ||
                                      std::is_convertible<T, U>::value,
                                  T>::type = 0>
static inline void eq_num(const std::string &file, int line, bool equality,
                          T expect, U actual) {
  test_count++;
  if (equality)
    test_pass++;
  else
    std::cerr << file << ":" << line << ": expect: '" << expect << "' actual: '"
              << actual << std::endl;
}

template <typename T,
          typename std::enable_if<std::is_convertible<T, std::string>::value,
                                  T>::type = nullptr>
static inline void eq_char(const std::string &file, int line, bool equality,
                           T expect, T actual) {
  test_count++;
  if (equality)
    test_pass++;
  else
    std::cerr << file << ":" << line << ": expect: '" << expect << "' actual: '"
              << actual << std::endl;
}

#define TEST_NUM_EQ(expect, actual)                                            \
  eq_num(__FILE__, __LINE__, expect == actual, expect, actual)

#define TEST_STRING_EQ(expect, actual)                                         \
  do {                                                                         \
    std::string e(expect);                                                     \
    std::string a(actual);                                                     \
    eq_char(__FILE__, __LINE__, a.compare(e) == 0, expect, actual);            \
  } while (0)

#define PRINT_PASS_RATE()                                                      \
  do {                                                                         \
    fprintf(stderr, "[%.2f%%] all test: %d, pass: %d.\n",                      \
            test_count == 0                                                    \
                ? 0                                                            \
                : static_cast<float>(test_pass * 100) / test_count,            \
            test_count, test_pass);                                            \
  } while (0)

#define ALL_TEST_PASS() (test_count == test_pass)