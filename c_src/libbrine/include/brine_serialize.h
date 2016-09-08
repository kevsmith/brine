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

#ifndef BRINE_SERIALIZE_H
#define BRINE_SERIALIZE_H

#include "brine_deps.h"
#include "brine_types.h"

void brine_serializer_init();

bool brine_serialize_keypair(const brine_keypair_s *keypair, unsigned char *blob, size_t bloblen);
bool brine_deserialize_keypair(const unsigned char *blob, size_t bloblen, brine_keypair_s *keypair);

#endif
