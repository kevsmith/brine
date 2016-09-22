# -------------------------------------------------------------------
#
# Copyright (c) 2013 Kevin A. Smith    All Rights Reserved
#
# This file is provided to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file
# except in compliance with the License.  You may obtain
# a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#
# -------------------------------------------------------------------

PROJECT(brine)
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

# Build options
OPTION(TARGET_ARCH   "Target architecture"                 OFF)
OPTION(OPTIMIZE      "Enable aggressive optimizations"     ON)
OPTION(ENABLE_SHARED "Build shared library"                OFF)
OPTION(ENABLE_STATIC "Build static library"                ON)
OPTION(ENABLE_TESTS  "Build test suite"                    ON)
OPTION(LIB_BASE_NAME "Base library file name"             "brine")

# Set compiler flags
# GCC
IF(CMAKE_C_COMPILER_ID STREQUAL "GNU")
  SET(BRINE_C_FLAGS "-std=gnu99 -fPIC")
  IF(TARGET_ARCH)
    SET(BRINE_C_FLAGS "${BRINE_C_FLAGS} -march=${TARGET_ARCH}")
  ELSE()
    SET(BRINE_C_FLAGS "${BRINE_C_FLAGS} -march=opteron")
  ENDIF()
  IF(OPTIMIZE)
    SET(BRINE_C_FLAGS "${BRINE_C_FLAGS} -O3")
  ELSE()
    SET(BRINE_C_FLAGS "${BRINE_C_FLAGS} -O0 -g")
  ENDIF()
  IF(ENABLE_SHARED)
    SET(BRINE_C_FLAGS "${BRINE_C_FLAGS} -fPIC")
  ENDIF()
ENDIF()

SET(BRINE_LIB_FLAGS "${BRINE_C_FLAGS} -Wall -Werror")
SET(BRINE_TEST_FLAGS "${BRINE_C_FLAGS} -Wall -Wno-unused-but-set-variable -Wno-unused-variable")

# Source files and include dirs
FILE(GLOB SRC_BRINE src/*.c src/ed25519/*.c src/blake2/*.c)
INCLUDE_DIRECTORIES(AFTER ./include src/ed25519 src/blake2)
ADD_LIBRARY(core OBJECT ${SRC_BRINE})
SET_TARGET_PROPERTIES(core PROPERTIES COMPILE_FLAGS "${BRINE_LIB_FLAGS}")

IF(ENABLE_SHARED)
  ADD_LIBRARY(brine_shared SHARED $<TARGET_OBJECTS:core>)
  IF(LIB_BASE_NAME)
    SET_TARGET_PROPERTIES(brine_shared PROPERTIES OUTPUT_NAME ${LIB_BASE_NAME})
  ELSE()
    SET_TARGET_PROPERTIES(brine_shared PROPERTIES OUTPUT_NAME "brine")
  ENDIF()
ENDIF()

IF(ENABLE_STATIC)
  ADD_LIBRARY(brine_static STATIC $<TARGET_OBJECTS:core>)
  IF(LIB_BASE_NAME)
    SET_TARGET_PROPERTIES(brine_static PROPERTIES OUTPUT_NAME ${LIB_BASE_NAME})
  ELSE()
    SET_TARGET_PROPERTIES(brine_static PROPERTIES OUTPUT_NAME "brine_s")
  ENDIF()
ENDIF()

IF(ENABLE_TESTS)  
  SET(TEST_FIXTURES "${CMAKE_CURRENT_SOURCE_DIR}/tests/resources/")
  SET(TEST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/tests")
  ADD_DEFINITIONS(-FIXTURE_PATH=\"${TEST_FIXTURES}\")
  ADD_DEFINITIONS(-TEST_PATH=\"${TEST_PATH}\")

  INCLUDE_DIRECTORIES(AFTER ${TEST_PATH})
  ADD_EXECUTABLE(keypair_test $<TARGET_OBJECTS:core> ${TEST_PATH}/keypair.c)
  ADD_EXECUTABLE(serialize_test $<TARGET_OBJECTS:core> ${TEST_PATH}/serialize.c)
  SET_TARGET_PROPERTIES(keypair_test PROPERTIES COMPILE_FLAGS "${BRINE_TEST_FLAGS}")
  SET_TARGET_PROPERTIES(serialize_test PROPERTIES COMPILE_FLAGS "${BRINE_TEST_FLAGS}")
  ENABLE_TESTING()
  ADD_TEST(keypair_test keypair_test -ionline)
  ADD_TEST(serialize_test serialize_test -ionline)
ENDIF()