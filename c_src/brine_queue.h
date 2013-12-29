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

#ifndef BRINE_QUEUE_H
#define BRINE_QUEUE_H

typedef enum brine_queue_errors {
  BQ_SUCCESS,
  BQ_NULL_QUEUE,
  BQ_NO_MEMORY,
  BQ_NULL_DATA,
  BQ_SHUTDOWN
} brine_queue_errors;

typedef struct brine_queue_s brine_queue_s;

brine_queue_s *brine_queue_new(size_t initial_capacity, size_t growth_increment);
void brine_queue_destroy(brine_queue_s **queue);

void *brine_queue_dequeue(brine_queue_s *queue);
brine_queue_errors brine_queue_enqueue(brine_queue_s *queue, void *entry);

#endif
