/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2020 Xaptum, Inc.
 */

#include "server_root_certificate_context.h"

#include "atoms.h"
#include "nif_utils.h"
#include "xtt_nif.h"

ERL_NIF_TERM xtt_nif_initialize_server_root_certificate_context_ecdsap256(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  xtt_nif_data* data = enif_priv_data(env);

  ErlNifBinary id, public_key;
  struct xtt_server_root_certificate_context* obj = NULL;

  xtt_return_code_type rc;
  ERL_NIF_TERM ret;

  if ((2 != argc) ||
      (!enif_inspect_binary(env, argv[0], &id)) ||
      (!enif_inspect_binary(env, argv[1], &public_key)))
    return enif_make_badarg(env);

  if ((id.size != sizeof(xtt_certificate_root_id)) ||
      (public_key.size != sizeof(xtt_ecdsap256_pub_key)))
    return enif_make_badarg(env);

  obj = enif_alloc_resource(data->res_server_root_certificate_context, sizeof(*obj));
  if (NULL == obj)
    return make_error(env, ATOMS.alloc_failed);

  rc = xtt_initialize_server_root_certificate_context_ecdsap256(obj,
                                                                (xtt_certificate_root_id*) id.data,
                                                                (xtt_ecdsap256_pub_key*) public_key.data);

  if (XTT_RETURN_SUCCESS != rc)
    ret = make_error(env, enif_make_int(env, rc));
  else
    ret = make_ok(env, enif_make_resource(env, obj));

  enif_release_resource(obj);
  return ret;

}
