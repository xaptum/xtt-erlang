/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2020 Xaptum, Inc.
 */

#include "client_group_context.h"

#include "atoms.h"
#include "nif_utils.h"
#include "xtt_nif.h"

ERL_NIF_TERM xtt_nif_initialize_client_group_context_lrsw(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  xtt_nif_data* data = enif_priv_data(env);

  ErlNifBinary gid, priv_key, cred, basename;
  struct xtt_client_group_context* obj = NULL;

  xtt_return_code_type rc;
  ERL_NIF_TERM ret;

  if ((4 != argc) ||
      (!enif_inspect_binary(env, argv[0], &gid)) ||
      (!enif_inspect_binary(env, argv[1], &priv_key)) ||
      (!enif_inspect_binary(env, argv[2], &cred)) ||
      (!enif_inspect_binary(env, argv[3], &basename)))
    return enif_make_badarg(env);

  if ((gid.size != sizeof(xtt_group_id)) ||
      (priv_key.size != sizeof(xtt_daa_priv_key_lrsw)) ||
      (cred.size != sizeof(xtt_daa_credential_lrsw)) ||
      (basename.size > MAX_BASENAME_LENGTH))
    return enif_make_badarg(env);

  obj = enif_alloc_resource(data->res_client_group_context, sizeof(*obj));
  if (NULL == obj)
    return make_error(env, ATOMS.alloc_failed);

  rc = xtt_initialize_client_group_context_lrsw(obj,
                                                (xtt_group_id*) gid.data,
                                                (xtt_daa_priv_key_lrsw*) priv_key.data,
                                                (xtt_daa_credential_lrsw*) cred.data,
                                                basename.data, basename.size);

  if (XTT_RETURN_SUCCESS != rc)
    ret = make_error(env, enif_make_int(env, rc));
  else
    ret = make_ok(env, enif_make_resource(env, obj));

  enif_release_resource(obj);
  return ret;
}
