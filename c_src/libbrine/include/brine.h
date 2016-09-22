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

#ifndef BRINE_H
#define BRINE_H

#include "brine_deps.h"
#include "brine_types.h"
#include "brine_serialize.h"

void brine_init(brine_memory_cb_s *cb);

brine_keypair_s *brine_new_keypair();
bool brine_init_keypair(brine_keypair_s *keypair);
bool brine_init_keypair_from_seed(brine_keypair_s *keypair, const unsigned char *seed, size_t seedlen);
void brine_sign_message(const brine_keypair_s *keypair, const unsigned char *message, size_t msglen, unsigned char *buf);
bool brine_verify_signature(const unsigned char *key, const unsigned char *message, size_t msglen, unsigned char *signature);

bool brine_serialize_keypair(const brine_keypair_s *keypair, unsigned char *blob, size_t bloblen);
bool brine_deserialize_keypair(const unsigned char *blob, size_t bloblen, brine_keypair_s *keypair);

bool brine_keypairs_are_identical(const brine_keypair_s *k1, const brine_keypair_s *k2);

#endif
