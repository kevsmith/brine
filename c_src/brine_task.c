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

#include <stdio.h>
#include <time.h>
#include "brine_task.h"

brine_task_s *brine_task_new(ErlNifPid *caller, brine_task_cmd_e command, ERL_NIF_TERM ref) {
  brine_task_s *t = (brine_task_s *) enif_alloc(sizeof(brine_task_s));
  if (t) {
    memcpy(&t->owner, caller, sizeof(ErlNifPid));
    t->env = enif_alloc_env();
    if(!t->env) {
      enif_free(t);
      t = NULL;
    }
    else {
      t->cmd = command;
      t->ref = enif_make_copy(t->env, ref);
    }
  }
  return t;
}

brine_task_s *brine_task_stop() {
  brine_task_s *t = (brine_task_s *) enif_alloc(sizeof(brine_task_s));
  if (t) {
    t->cmd = BRINE_STOP;
    return t;
  }
  return NULL;
}

void brine_task_destroy(brine_task_s **task) {
  brine_task_s *t = *task;
  if (t->cmd != BRINE_STOP) {
    enif_free_env(t->env);
  }
  enif_free(t);
  *task = NULL;
}
