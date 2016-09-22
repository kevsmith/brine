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

#ifndef BRINE_TASK_H
#define BRINE_TASK_H

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "erl_nif.h"
#include "brine_serialize.h"

typedef enum brine_cmd_e {
  BRINE_STOP,
  BRINE_NEW_KEYPAIR,
  BRINE_NEW_KEYPAIR_FROM_SEED,
  BRINE_SIGN_MSG,
  BRINE_VERIFY,
  BRINE_TO_BINARY,
  BRINE_TO_KEYPAIR
} brine_task_cmd_e;

typedef struct {
    ERL_NIF_TERM seed;
} brine_generate_s;

typedef struct {
  brine_keypair_s *keys;
  ERL_NIF_TERM message;
} brine_task_sig_s;

typedef struct {
  ERL_NIF_TERM pubkey;
  ERL_NIF_TERM signature;
  ERL_NIF_TERM message;
} brine_task_verify_s;

typedef struct {
  ErlNifEnv *env;
  ErlNifPid owner;
  brine_task_cmd_e cmd;
  ERL_NIF_TERM ref;
  union {
    brine_generate_s generate;
    brine_task_sig_s signature;
    brine_task_verify_s verify;
  } options;
} brine_task_s;

brine_task_s *brine_task_new(ErlNifPid *caller, brine_task_cmd_e command, ERL_NIF_TERM ref);
brine_task_s *brine_task_stop();
void brine_task_destroy(brine_task_s **task);

#endif
