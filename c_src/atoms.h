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
} atoms;

extern atoms ATOMS;

#endif // ATOMS_H
