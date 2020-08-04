/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2020 Xaptum, Inc.
 */

#pragma once

#ifndef NIF_UTILS_H
#define NIF_UTILS_H

#include "erl_nif.h"

ERL_NIF_TERM make_atom(ErlNifEnv* env, const char* name);
ERL_NIF_TERM make_ok(ErlNifEnv* env, ERL_NIF_TERM term);
ERL_NIF_TERM make_error(ErlNifEnv* env, ERL_NIF_TERM term);

#endif // NIF_UTILS_H
