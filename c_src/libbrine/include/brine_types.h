// -*- coding:utf-8;Mode:C;tab-width:2;c-basic-offset:2;indent-tabs-mode:nil -*-
// -------------------------------------------------------------------
//
// Copyright (c) 2013 Kevin A. Smith    All Rights Reserved
//
// This file is provided to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file
// except in compliance with the License.  You may obtain
// a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
//
// -------------------------------------------------------------------

#ifndef BRINE_TYPES_H
#define BRINE_TYPES_H

#define BRINE_SEED_SZ 32
#define BRINE_PUBKEY_SZ 32
#define BRINE_PRIVKEY_SZ 64
#define BRINE_SIG_SZ 64
#define BRINE_BLOB_HEADER_SZ 10
#define BRINE_BLOB_SZ BRINE_PRIVKEY_SZ + BRINE_PUBKEY_SZ + BRINE_BLOB_HEADER_SZ
#define BRINE_BLOB_VERSION 0x01

typedef struct {
  void *(*malloc)(size_t size);
  void (*free)(void *ptr);
} brine_memory_cb_s;

typedef struct {
  unsigned char private_key[BRINE_PRIVKEY_SZ];
  unsigned char public_key[BRINE_PUBKEY_SZ];
} brine_keypair_s;

#endif
