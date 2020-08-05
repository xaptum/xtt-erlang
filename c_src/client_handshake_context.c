/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2020 Xaptum, Inc.
 */

#include "client_handshake_context.h"

#include "atoms.h"
#include "nif_utils.h"
#include "xtt_nif.h"

// --------------- initialization ---------------
ERL_NIF_TERM xtt_nif_initialize_client_handshake_context(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  xtt_nif_data* data = enif_priv_data(env);

  int version, suite_spec;
  xtt_nif_client_handshake_context* obj = NULL;

  xtt_return_code_type rc;
  ERL_NIF_TERM ret;

  if ((argc != 2) ||
      (!enif_get_int(env, argv[0], &version)) ||
      (!enif_get_int(env, argv[1], &suite_spec)))
    return enif_make_badarg(env);

  obj = enif_alloc_resource(data->res_client_handshake_context, sizeof(*obj));
  if (NULL == obj)
    return make_error(env, ATOMS.alloc_failed);

  rc = xtt_initialize_client_handshake_context(&obj->base,
                                               obj->in, sizeof(obj->in),
                                               obj->out, sizeof(obj->out),
                                               version, suite_spec);

  if (XTT_RETURN_SUCCESS != rc)
    ret = make_error(env, enif_make_int(env, rc));
  else
    ret = make_ok(env, enif_make_resource(env, obj));

  enif_release_resource(obj);
  return ret ;
}

// --------------- accessors ---------------
ERL_NIF_TERM xtt_nif_get_my_identity(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  xtt_nif_data* data = enif_priv_data(env);

  const xtt_nif_client_handshake_context* ctx;
  xtt_identity_type* identity;
  ERL_NIF_TERM term;

  xtt_return_code_type rc;

  if ((argc != 1) ||
      (!enif_get_resource(env, argv[0], data->res_client, (void**) &ctx)))
    return enif_make_badarg(env);

  identity = (void*) enif_make_new_binary(env, sizeof(*identity), &term);
  rc = xtt_get_my_identity(identity, &ctx->base);

  if (XTT_RETURN_SUCCESS != rc)
    return make_error(env, enif_make_int(env, rc));

  return make_ok(env, term);
}

ERL_NIF_TERM xtt_nif_get_my_longterm_key_ecdsap256(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  xtt_nif_data* data = enif_priv_data(env);

  const xtt_nif_client_handshake_context* ctx;
  xtt_ecdsap256_pub_key* key;
  ERL_NIF_TERM term;

  xtt_return_code_type rc;

  if ((argc != 1) ||
      (!enif_get_resource(env, argv[0], data->res_client, (void**) &ctx)))
    return enif_make_badarg(env);

  key = (void*) enif_make_new_binary(env, sizeof(*key), &term);
  rc = xtt_get_my_longterm_key_ecdsap256(key, &ctx->base);

  if (XTT_RETURN_SUCCESS != rc)
    return make_error(env, enif_make_int(env, rc));

  return make_ok(env, term);
}

ERL_NIF_TERM xtt_nif_get_my_longterm_private_key_ecdsap256(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  xtt_nif_data* data = enif_priv_data(env);

  const xtt_nif_client_handshake_context* ctx;
  xtt_ecdsap256_priv_key* private_key;
  ERL_NIF_TERM term;

  xtt_return_code_type rc;

  if ((argc != 1) ||
      (!enif_get_resource(env, argv[0], data->res_client_handshake_context, (void**) &ctx)))
    return enif_make_badarg(env);

  private_key = (void*) enif_make_new_binary(env, sizeof(*private_key), &term);
  rc = xtt_get_my_longterm_private_key_ecdsap256(private_key, &ctx->base);

  if (XTT_RETURN_SUCCESS != rc)
    return make_error(env, enif_make_int(env, rc));

  return make_ok(env, term);
}

ERL_NIF_TERM xtt_nif_get_my_pseudonym_lrsw(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  xtt_nif_data* data = enif_priv_data(env);

  const xtt_nif_client_handshake_context* ctx;
  xtt_daa_pseudonym_lrsw* pseudonym;
  ERL_NIF_TERM term;

  xtt_return_code_type rc;

  if ((argc != 1) ||
      (!enif_get_resource(env, argv[0], data->res_client_handshake_context, (void**) &ctx)))
    return enif_make_badarg(env);

  pseudonym = (void*) enif_make_new_binary(env, sizeof(*pseudonym), &term);
  rc = xtt_get_my_pseudonym_lrsw(pseudonym, &ctx->base);

  if (XTT_RETURN_SUCCESS != rc)
    return make_error(env, enif_make_int(env, rc));

  return make_ok(env, term);
}

// --------------- handshake --------------
static
ERL_NIF_TERM prepare_result(ErlNifEnv* env, int rc, xtt_nif_client_handshake_context* ctx)
{
  switch(rc) {
  case XTT_RETURN_WANT_WRITE:
    return make_result_binary(env, ATOMS.want_write,
                              ctx->io_ptr, ctx->io_bytes_requested);
  case XTT_RETURN_WANT_READ:
    return make_result_int(env, ATOMS.want_read,
                           ctx->io_bytes_requested);
  case XTT_RETURN_WANT_BUILDIDCLIENTATTEST:
    return make_result_binary(env, ATOMS.want_buildidclientattest,
                              &ctx->claimed_root_id, sizeof(ctx->claimed_root_id));
  case XTT_RETURN_WANT_PREPARSESERVERATTEST:
    return make_result(env, ATOMS.want_preparseserverattest);
  case XTT_RETURN_WANT_PARSEIDSERVERFINISHED:
    return make_result(env, ATOMS.want_parseidserverfinished);
  case XTT_RETURN_HANDSHAKE_FINISHED:
    return make_result(env, ATOMS.handshake_finished);
  default:
    return make_result_int(env, ATOMS.error, rc);
  }
}

ERL_NIF_TERM xtt_nif_handshake_client_start(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  xtt_nif_data* data = enif_priv_data(env);
  xtt_nif_client_handshake_context* ctx;
  xtt_return_code_type rc;

  if ((argc != 1) ||
      (!enif_get_resource(env, argv[0], data->res_client_handshake_context, (void**) &ctx)))
    return enif_make_badarg(env);

  rc = xtt_handshake_client_start(&ctx->io_bytes_requested, &ctx->io_ptr, &ctx->base);
  return prepare_result(env, rc, ctx);
}

ERL_NIF_TERM xtt_nif_handshake_client_handle_io(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  xtt_nif_data* data = enif_priv_data(env);
  xtt_nif_client_handshake_context* ctx;
  int bytes_written;
  ErlNifBinary received;
  xtt_return_code_type rc;

  if ((argc != 3) ||
      (!enif_get_resource(env, argv[0], data->res_client_handshake_context, (void**) &ctx)) ||
      (!enif_get_int(env, argv[1], &bytes_written)) ||
      (!enif_inspect_binary(env, argv[2], &received)))
    return enif_make_badarg(env);

  if ((bytes_written > ctx->io_bytes_requested) ||
      (received.size > ctx->io_bytes_requested))
    return enif_make_badarg(env);

  memcpy(ctx->io_ptr, received.data, received.size);

  rc = xtt_handshake_client_handle_io(bytes_written, received.size,
                                      &ctx->io_bytes_requested, &ctx->io_ptr,
                                      &ctx->base);
  return prepare_result(env, rc, ctx);
}

ERL_NIF_TERM xtt_nif_handshake_client_preparse_serverattest(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  xtt_nif_data* data = enif_priv_data(env);
  xtt_nif_client_handshake_context* ctx;
  xtt_return_code_type rc;

  if ((argc != 1) ||
      (!enif_get_resource(env, argv[0], data->res_client_handshake_context, (void**) &ctx)))
    return enif_make_badarg(env);

  rc = xtt_handshake_client_preparse_serverattest(&ctx->claimed_root_id,
                                                  &ctx->io_bytes_requested, &ctx->io_ptr,
                                                  &ctx->base);
  return prepare_result(env, rc, ctx);
}

ERL_NIF_TERM xtt_nif_handshake_client_build_idclientattest(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  xtt_nif_data* data = enif_priv_data(env);
  xtt_nif_client_handshake_context* ctx;

  struct xtt_server_root_certificate_context* root_cert;
  ErlNifBinary requested_client_id;
  struct xtt_client_group_context group_ctx;

  xtt_return_code_type rc;

  if ((argc != 4) ||
      (!enif_get_resource(env, argv[0], data->res_client_handshake_context, (void**) &ctx)) ||
      (!enif_get_resource(env, argv[1], data->res_server_root_certificate_context, (void**) &root_cert)) ||
      (!enif_inspect_binary(env, argv[2], &requested_client_id)) ||
      (!enif_get_resource(env, argv[3], data->res_client_group_context, (void**) &group_ctx)))
    return enif_make_badarg(env);

  if ((requested_client_id.size != sizeof(xtt_identity_type)))
    return enif_make_badarg(env);

  rc = xtt_handshake_client_preparse_serverattest(&ctx->claimed_root_id,
                                                  &ctx->io_bytes_requested, &ctx->io_ptr,
                                                  &ctx->base);
  return prepare_result(env, rc, ctx);
}

ERL_NIF_TERM xtt_nif_handshake_client_parse_idserverfinished(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  xtt_nif_data* data = enif_priv_data(env);
  xtt_nif_client_handshake_context* ctx;
  xtt_return_code_type rc;

  if ((argc != 1) ||
      (!enif_get_resource(env, argv[0], data->res_client_handshake_context, (void**) &ctx)))
    return enif_make_badarg(env);

  rc = xtt_handshake_client_preparse_serverattest(&ctx->claimed_root_id,
                                                  &ctx->io_bytes_requested, &ctx->io_ptr,
                                                  &ctx->base);
  return prepare_result(env, rc, ctx);
}

ERL_NIF_TERM xtt_nif_client_build_error_msg(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  xtt_nif_data* data = enif_priv_data(env);
  xtt_nif_client_handshake_context* ctx;
  xtt_return_code_type rc;

  if ((argc != 1) ||
      (!enif_get_resource(env, argv[0], data->res_client_handshake_context, (void**) &ctx)))
    return enif_make_badarg(env);

  rc = xtt_client_build_error_msg(&ctx->io_bytes_requested, &ctx->io_ptr, &ctx->base);
  return prepare_result(env, rc, ctx);
}
