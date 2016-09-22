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
#include "brine_deps.h"
#include "brine_types.h"
#include "brine_serialize.h"
#include "ed25519.h"

static void *(*brine_alloc)(size_t size) = NULL;
static void (*brine_free)(void *ptr) = NULL;

void brine_init(brine_memory_cb_s *cb) {
  if (cb == NULL) {
    brine_alloc = malloc;
    brine_free = free;
  }
  else {
    brine_alloc = cb->malloc;
    brine_free = cb->free;
  }
  brine_serializer_init();
}

bool brine_init_keypair(brine_keypair_s *keypair) {
  unsigned char seed[BRINE_SEED_SZ];
  if (ed25519_create_seed(seed) != 0) {
    return false;
  }
  ed25519_create_keypair(keypair->public_key, keypair->private_key, seed);
  return true;
}

bool brine_init_keypair_from_seed(brine_keypair_s *keypair, const unsigned char *seed, size_t seedlen) {
  if (seedlen != BRINE_SEED_SZ) {
    return false;
  }
  ed25519_create_keypair(keypair->public_key, keypair->private_key, seed);
  return true;
}

brine_keypair_s *brine_new_keypair() {
  brine_keypair_s *retval = (brine_keypair_s *) brine_alloc(sizeof(brine_keypair_s));
  if (retval) {
    if (!brine_init_keypair(retval)) {
      brine_free(retval);
      retval = NULL;
    }
  }
  return retval;
}

void brine_sign_message(const brine_keypair_s *keypair, const unsigned char *message, size_t msglen, unsigned char *signature) {
  ed25519_sign(signature, message, msglen, keypair->public_key, keypair->private_key);
}

bool brine_verify_signature(const unsigned char *key, const unsigned char *message, size_t msglen, const unsigned char *signature) {
  return ed25519_verify(signature, message, msglen, key);
}

bool brine_keypairs_are_identical(const brine_keypair_s *k1, const brine_keypair_s *k2) {
  if (k1 == NULL || k2 == NULL) {
    return false;
  }
  bool retval = true;
  for (int i = 0; i < BRINE_PRIVKEY_SZ; i++) {
    if(k1->private_key[i] != k2->private_key[i]) {
      retval = false;
      break;
    }
  }
  if (retval) {
    for (int i = 0; i < BRINE_PUBKEY_SZ; i++) {
      if (k1->public_key[i] != k2->public_key[i]) {
        retval = false;
        break;
      }
    }
  }
  return retval;
}
