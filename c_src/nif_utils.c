/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2020 Xaptum, Inc.
 */

#include "nif_utils.h"

#include "atoms.h"

ERL_NIF_TERM make_atom(ErlNifEnv* env, const char* name)
{
  ERL_NIF_TERM atom;

  if (enif_make_existing_atom(env, name, &atom, ERL_NIF_LATIN1))
    return atom;

  return enif_make_atom(env, name);
}

ERL_NIF_TERM make_ok(ErlNifEnv* env, ERL_NIF_TERM term)
{
  return enif_make_tuple2(env, ATOMS.ok, term);
}

ERL_NIF_TERM make_error(ErlNifEnv* env, ERL_NIF_TERM term)
{
  return enif_make_tuple2(env, ATOMS.error, term);
}
