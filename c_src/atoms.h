/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2020 Xaptum, Inc.
 */

#pragma once

#ifndef ATOMS_H
#define ATOMS_H

#include "erl_nif.h"

typedef struct
{
  ERL_NIF_TERM ok;
  ERL_NIF_TERM error;
  ERL_NIF_TERM alloc_failed;

  ERL_NIF_TERM want_write;
  ERL_NIF_TERM want_read;
  ERL_NIF_TERM want_buildserverattest;
  ERL_NIF_TERM want_preparseserverattest;
  ERL_NIF_TERM want_buildidclientattest;
  ERL_NIF_TERM want_preparseidclientattest;
  ERL_NIF_TERM want_verifygroupsignature;
  ERL_NIF_TERM want_buiildidserverfinshed;
  ERL_NIF_TERM want_parseidserverfinished;
  ERL_NIF_TERM handshake_finished;
} atoms;

extern atoms ATOMS;

#endif // ATOMS_H
