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

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "erl_nif.h"
#include "ed25519.h"
#include "brine_task.h"
#include "brine_queue.h"

static int workers = 0;
static brine_queue_s *queue;
static ErlNifTid *worker_threads;
static ErlNifResourceType *brine_keypair_resource;

// Prototypes
#define NIF(name) \
  ERL_NIF_TERM name(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])

#define QUEUE_CAPACITY 64
#define QUEUE_GROWTH   16

// Frequently used Erlang terms
static ERL_NIF_TERM BRINE_ATOM_OK;
static ERL_NIF_TERM BRINE_ATOM_ERROR;
static ERL_NIF_TERM BRINE_ATOM_NOT_IMPL;
static ERL_NIF_TERM BRINE_ATOM_KEYPAIR;
static ERL_NIF_TERM BRINE_ATOM_TRUE;
static ERL_NIF_TERM BRINE_ATOM_FALSE;
static ERL_NIF_TERM BRINE_ERROR_NO_MEMORY;

// NIF function forward declares
NIF(brine_generate_keypair);
NIF(brine_sign_message);
NIF(brine_verify_signature);

static ErlNifFunc nif_funcs[] =
{
  {"generate_keypair", 2, brine_generate_keypair},
  {"sign_message", 4, brine_sign_message},
  {"verify_signature", 5, brine_verify_signature}
};

static ERL_NIF_TERM make_error_tuple(ErlNifEnv *env, ERL_NIF_TERM reason) {
  return enif_make_tuple2(env, enif_make_copy(env, BRINE_ATOM_ERROR), reason);
}

static ERL_NIF_TERM make_keypair_record(ErlNifEnv *env, brine_keypair_s *keypair) {
  return enif_make_tuple4(env, enif_make_copy(env, BRINE_ATOM_KEYPAIR),
                          enif_make_resource(env, (void *) keypair),
                          // private key
                          enif_make_resource_binary(env, (void *) keypair, (void *) keypair->private, BRINE_PRIVKEY_SZ),
                          // public key
                          enif_make_resource_binary(env, (void *) keypair, (void *) keypair->public, BRINE_PUBKEY_SZ));
}

static void generate_keypair(brine_task_s *task) {
  unsigned char key_seed[BRINE_SEED_SZ];
  ErlNifEnv *env = task->env;
  ERL_NIF_TERM result;
  brine_keypair_s *keypair = (brine_keypair_s *) enif_alloc_resource(brine_keypair_resource, sizeof(brine_keypair_s));

  if (!keypair) {
    result = BRINE_ERROR_NO_MEMORY;
  }
  else {
    if (ed25519_create_seed(key_seed) != 0) {
      result = BRINE_ATOM_ERROR;
    }
    else {
      ed25519_create_keypair(keypair->public, keypair->private, key_seed);
      result = enif_make_tuple2(env, enif_make_copy(env, BRINE_ATOM_OK), make_keypair_record(env, keypair));
      enif_release_resource(keypair);
    }
  }
  enif_send(NULL, &task->owner, task->env, enif_make_tuple2(env, task->ref, result));
}

static void sign_message(brine_task_s *task) {
  ErlNifEnv *env = task->env;
  ErlNifBinary message;
  ErlNifBinary signature;
  ERL_NIF_TERM result;

  if (!enif_alloc_binary(BRINE_SIG_SZ, &signature)) {
    result = BRINE_ERROR_NO_MEMORY;
  }
  else {
    if (!enif_inspect_binary(env, task->options.signature.message, &message)) {
      enif_release_binary(&signature);
      result = BRINE_ERROR_NO_MEMORY;
    }
    else {
      ed25519_sign(signature.data, message.data, message.size,
                   task->options.signature.keys->public, task->options.signature.keys->private);
      result = enif_make_tuple2(env, enif_make_copy(env, BRINE_ATOM_OK), enif_make_binary(env, &signature));
    }
  }
  enif_release_resource((void *) task->options.signature.keys);
  enif_send(NULL, &task->owner, task->env, enif_make_tuple2(env, task->ref, result));
}

static void verify_signature(brine_task_s *task) {
  ErlNifEnv *env = task->env;
  ErlNifBinary pubkey, signature, message;
  ERL_NIF_TERM result;

  if (!enif_inspect_binary(env, task->options.verify.pubkey, &pubkey) ||
      !enif_inspect_binary(env, task->options.verify.signature, &signature) ||
      !enif_inspect_binary(env, task->options.verify.message, &message)) {
    result = BRINE_ERROR_NO_MEMORY;
  }
  else {
    if (pubkey.size != BRINE_PUBKEY_SZ || signature.size != BRINE_SIG_SZ) {
      result = enif_make_atom(env, "badarg");
    }
    else {
      if (ed25519_verify(signature.data, message.data, message.size, pubkey.data)) {
        result = BRINE_ATOM_TRUE;
      }
      else {
        result = BRINE_ATOM_FALSE;
      }
    }
  }
  enif_send(NULL, &task->owner, task->env, enif_make_tuple2(env, task->ref, result));
}

static void *worker_loop(void *ignored) {
  bool keep_running = true;
  while(keep_running) {
    brine_task_s *task = (brine_task_s *) brine_queue_dequeue(queue);
    if (!task) {
      break;
    }
    switch(task->cmd) {
    case BRINE_STOP:
      keep_running = false;
      break;
    case BRINE_NEW_KEYPAIR:
      generate_keypair(task);
      break;
    case BRINE_SIGN_MSG:
      sign_message(task);
      break;
    case BRINE_VERIFY:
      verify_signature(task);
      break;
    default:
      break;
    }
    brine_task_destroy(&task);
  }
  return NULL;
}

static bool start_workers() {
  worker_threads = (ErlNifTid *) enif_alloc(sizeof(ErlNifTid) * workers);
  if (!worker_threads) {
    return false;
  }
  for (int i = 0; i < workers; i++) {
    enif_thread_create("brine_worker_thread", &worker_threads[i], worker_loop, NULL, NULL);
  }
  return true;
}

NIF(brine_generate_keypair) {
  ErlNifPid owner;

  if (!enif_get_local_pid(env, argv[0], &owner) ||
      !enif_is_ref(env, argv[1])) {
    return enif_make_badarg(env);
  }

  brine_task_s *task = brine_task_new(&owner, BRINE_NEW_KEYPAIR, argv[1]);
  if (task) {
    if (brine_queue_enqueue(queue, task) != BQ_SUCCESS) {
      return make_error_tuple(env, enif_make_atom(env, "overload"));
    }
    return BRINE_ATOM_OK;
  }
  return BRINE_ATOM_ERROR;
}

NIF(brine_sign_message) {
  ErlNifPid owner;
  brine_keypair_s *keys;

  if (!enif_get_local_pid(env, argv[0], &owner) ||
      !enif_is_ref(env, argv[1]) ||
      !enif_get_resource(env, argv[2], brine_keypair_resource, (void **) &keys)) {
    return enif_make_badarg(env);
  }
  brine_task_s *task = brine_task_new(&owner, BRINE_SIGN_MSG, argv[1]);
  if (task) { 
    task->options.signature.keys = keys;
    task->options.signature.message = enif_make_copy(task->env, argv[3]);
    enif_keep_resource((void *) keys);
    if (brine_queue_enqueue(queue, task) != BQ_SUCCESS) {
      enif_release_resource((void *) keys);
      brine_task_destroy(&task);
      return make_error_tuple(env, enif_make_atom(env, "overload"));
    }
    return BRINE_ATOM_OK;
  }
  return BRINE_ERROR_NO_MEMORY;
}

NIF(brine_verify_signature) {
  ErlNifPid owner;

  if (!enif_get_local_pid(env, argv[0], &owner) || !enif_is_ref(env, argv[1]) ||
      !enif_is_binary(env, argv[2]) || !enif_is_binary(env, argv[3]) ||
      !enif_is_binary(env, argv[4])) {
    return enif_make_badarg(env);
  }
  brine_task_s *task = brine_task_new(&owner, BRINE_VERIFY, argv[1]);
  if (task) {
    task->options.verify.pubkey = enif_make_copy(task->env, argv[2]);
    task->options.verify.signature = enif_make_copy(task->env, argv[3]);
    task->options.verify.message = enif_make_copy(task->env, argv[4]);
    if (brine_queue_enqueue(queue, task) != BQ_SUCCESS) {
      brine_task_destroy(&task);
      return make_error_tuple(env, enif_make_atom(env, "overload"));
    }
    return BRINE_ATOM_OK;
  }
  return BRINE_ERROR_NO_MEMORY;
}

/**
   Callback function to be run when the Erlang VM loads this NIF for
   the first time.

   Returns 0 on success; 1 if problems were encountered.
 */
int on_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info) {
  if (enif_get_int(env, load_info, &workers) &&
      ((brine_keypair_resource = enif_open_resource_type(env, NULL, "brine_keypair_resource", NULL,
                                                         ERL_NIF_RT_CREATE, NULL)) != NULL) &&
      ((queue = brine_queue_new(QUEUE_CAPACITY, QUEUE_GROWTH)) != NULL) &&
      start_workers()) {
    BRINE_ATOM_OK = enif_make_atom(env, "ok");
    BRINE_ATOM_ERROR = enif_make_atom(env, "error");
    BRINE_ATOM_NOT_IMPL = enif_make_atom(env, "not_implemented");
    BRINE_ATOM_KEYPAIR = enif_make_atom(env, "brine_keypair");
    BRINE_ATOM_TRUE = enif_make_atom(env, "true");
    BRINE_ATOM_FALSE = enif_make_atom(env, "false");
    BRINE_ERROR_NO_MEMORY = enif_make_tuple2(env, BRINE_ATOM_ERROR, enif_make_atom(env, "no_memory"));
    return 0;
  }
  return 1;
}

void on_unload(ErlNifEnv* env, void* priv_data) {
  brine_queue_destroy(&queue);
  for (int i = 0; i < workers; i++) {
    void *result;
    enif_thread_join(worker_threads[i], &result);
  }
}

/**
   Upgrade callback for ERL_NIF_INIT.

   Apparently, the NIF fails to load if this is NULL or returns
   non-zero (See http://www.erlang.org/doc/man/erl_nif.html).  As
   such, this is pretty much a dummy function.
 */
int on_upgrade(ErlNifEnv* env, void** priv_data, void** old_priv_data, ERL_NIF_TERM load_info){
  return 0;
}

ERL_NIF_INIT(brine_nif, nif_funcs, on_load, NULL, on_upgrade, on_unload)
