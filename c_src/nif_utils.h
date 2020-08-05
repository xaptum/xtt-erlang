/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2020 Xaptum, Inc.
 */

#pragma once

#ifndef NIF_UTILS_H
#define NIF_UTILS_H

#include "erl_nif.h"

#define UNUSED(expr) do { (void)(expr); } while (0)

ERL_NIF_TERM make_atom(ErlNifEnv* env, const char* name);
ERL_NIF_TERM make_binary(ErlNifEnv* env, void* buf, size_t len);

ERL_NIF_TERM make_ok(ErlNifEnv* env, ERL_NIF_TERM term);
ERL_NIF_TERM make_error(ErlNifEnv* env, ERL_NIF_TERM term);

ERL_NIF_TERM make_result(ErlNifEnv* env, ERL_NIF_TERM res);
ERL_NIF_TERM make_result_binary(ErlNifEnv* env, ERL_NIF_TERM res, void* buf, size_t len);
ERL_NIF_TERM make_result_int(ErlNifEnv* env, ERL_NIF_TERM res, int i);

#endif // NIF_UTILS_H
