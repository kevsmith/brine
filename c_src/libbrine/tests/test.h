#ifndef BRINE_TEST_H
#define BRINE_TEST_H

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

// Terminal codes
#define BRIGHT 1
#define RED 31
#define GREEN 32
#define WHITE 37
#define BLACK 40
#define RESET_COLORS 

#define FAILED_TEST 5


#define failure(...)\
  printf("%c[%d;%dm", 0x1B, 1, 31);\
  printf(__VA_ARGS__);\
  printf("\e[m")

#define success(...)\
  printf("%c[%d;%dm", 0x1B, 1, 32);\
  printf(__VA_ARGS__);\
  printf("\e[m")

typedef void (*test_func)(void);
typedef bool(*setup_func)(void);
typedef void(*teardown_func)(void);

#define MAX_TESTS() 1000
#define ASSERT_(COND) printf("  Assert %s...", #COND); \
  if (!(COND)) {\
    suite_status_ = 5;\
    failure("fail (%s:%d)\n", __FILE__, __LINE__);\
  }\
  else {\
    success("ok\n");\
  }
#define PASSED() success("%s passed\n", current_test);

#define SUITE(NAME) int main(int argc, char **argv) {\
  int suite_status_ = 0;\
  const char *suite_name_ = #NAME;\
  test_func tests_[MAX_TESTS()];\
  memset(tests_, 0, sizeof(test_func) * MAX_TESTS());\
  setup_func suite_setup_ = NULL;\
  teardown_func suite_teardown_ = NULL;

#define SUITE_END() if (suite_setup_ != NULL) (suite_setup_)();\
  printf("Starting suite %s\n", suite_name_);\
  for(int i = 0; i < MAX_TESTS(); i++) {\
    if (tests_[i] == NULL) {\
      if (suite_status_ == 0) {\
        success("Suite %s passed\n", suite_name_);\
      }\
      break;\
    }\
  (tests_[i])();\
  }\
  if (suite_teardown_ != NULL) (suite_teardown_)();\
  return suite_status_; }

#define SETUP(BODY)\
  bool suite_setup()\
  BODY;\
  suite_setup_ = suite_setup;

#define TEARDOWN(BODY)\
  void suite_teardown()\
  BODY;\
  suite_teardown_ = suite_teardown;

#define TEST(NAME, BODY)\
  void test_ ## NAME () {\
  printf(" Test: %s\n", #NAME);\
  const char *test_name_ = #NAME;\
  BODY\
  }\
  tests_[__COUNTER__] = test_ ## NAME

#endif
