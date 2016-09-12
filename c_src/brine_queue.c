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

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include "erl_nif.h"
#include "brine_queue.h"

struct brine_queue_s {
  size_t capacity;
  size_t growth_increment;
  size_t start;
  size_t end;
  size_t size;
  bool shutdown;
  void **data;
  ErlNifCond *cond;
  ErlNifMutex *lock;
};

#define BQ_BOTTOM(queue) queue->data[queue->start]
#define BQ_TOP(queue) queue->data[queue->end]
#define is_queue_full(queue) (queue->size == queue->capacity)
#define wrap_index(queue, index) (index == queue->capacity - 1) ? 0 : index + 1

static const size_t queue_entry_size = sizeof(void *);

brine_queue_errors grow_queue(brine_queue_s *queue);

brine_queue_s* brine_queue_new(size_t initial_capacity, size_t growth_increment) {
  brine_queue_s *retval = enif_alloc(sizeof(brine_queue_s));
  if (!retval) {
    goto ERROR;
  }
  if ((retval->data = enif_alloc(queue_entry_size * initial_capacity)) == NULL) {
      goto ERROR;
  }
  if ((retval->cond = enif_cond_create("brine_queue_cond")) == NULL) {
      goto ERROR;
  }
  if ((retval->lock = enif_mutex_create("brine_queue_lock")) == NULL) {
    goto ERROR;
  }
  retval->growth_increment = growth_increment;
  retval->start = 0;
  retval->end = 0;
  retval->size = 0;
  retval->capacity = initial_capacity;
  retval->shutdown = false;
  return retval;

ERROR:
  if (retval) {
    if (retval->data) {
      enif_free(retval->data);
    }
    if (retval->cond) {
      enif_cond_destroy(retval->cond);
    }
    if (retval->lock) {
      enif_mutex_destroy(retval->lock);
    }
    enif_free(retval);
    retval = NULL;
  }
  return retval;
}

void brine_queue_destroy(brine_queue_s **ref) {
  brine_queue_s *queue = *ref;
  enif_free(queue->data);
  enif_cond_destroy(queue->cond);
  enif_mutex_destroy(queue->lock);
  enif_free(queue);
  *ref = NULL;
}

void* brine_queue_dequeue(brine_queue_s *queue){

  void *retval;
  if (!queue) {
    return NULL;
  }
  enif_mutex_lock(queue->lock);
  if (queue->size == 0) {
    while(queue->size == 0) {
      enif_cond_wait(queue->cond, queue->lock);
    }
  }
  retval = BQ_BOTTOM(queue);
  BQ_BOTTOM(queue) = NULL;
  queue->size--;
  if (queue->size == 0) {
    queue->start = 0;
    queue->end = 0;
  }
  else {
    queue->start = wrap_index(queue, queue->start);
  }
  enif_mutex_unlock(queue->lock);
  return retval;
}

brine_queue_errors brine_queue_enqueue(brine_queue_s *queue, void* entry) {

  int retval;
  if (!queue) {
    return BQ_NULL_QUEUE;
  }
  if (!entry) {
    return BQ_NULL_DATA;
  }
  enif_mutex_lock(queue->lock);
  if (is_queue_full(queue)) {
    if ((retval = grow_queue(queue)) != BQ_SUCCESS) {
      return retval;
    }
  }
  BQ_TOP(queue) = entry;
  queue->size++;
  queue->end = wrap_index(queue, queue->end);
  enif_cond_signal(queue->cond);
  enif_mutex_unlock(queue->lock);
  return BQ_SUCCESS;
}

brine_queue_errors grow_queue(brine_queue_s *queue) {
  size_t index = 0;
  size_t count = 0;
  size_t new_capacity = queue->capacity + queue->growth_increment;
  void ** data = enif_alloc(new_capacity * queue_entry_size);
  if(data == NULL) {
    return BQ_NO_MEMORY;
  }
  for(index = queue->start, count = 0; count < queue->size;
      index = (index + 1) % queue->size, count++) {
    data[count] = queue->data[index]; 
  }
  //delete old queue and fix meta data.
  enif_free(queue->data);
  queue->data = data;
  queue->capacity = new_capacity;
  queue->start = 0;
  queue->end = queue->size; 

  return BQ_SUCCESS;;
}
