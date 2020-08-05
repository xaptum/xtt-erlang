#include <string.h>
#include <openssl/ssl.h>
#include <ecdaa.h>
#include <xtt.h>

#include "erl_nif.h"

#include "xtt_nif.h"

#include "atoms.h"
#include "nif_utils.h"

#include "asn1.h"
#include "client_group_context.h"
#include "client_handshake_context.h"
#include "server_root_certificate_context.h"

const char *longterm_public_key_out_file = "longterm_certificate.asn1.bin";
const char *longterm_private_key_out_file = "longterm_priv.asn1.bin";

static
int open_resources(ErlNifEnv* env, xtt_nif_data* data)
{
  ErlNifResourceFlags flags = (ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER);

  data->res_server_root_certificate_context = enif_open_resource_type(env, NULL,
                                                                      "xtt_server_root_certificate_context",
                                                                      NULL, flags, NULL);
  data->res_client_group_context = enif_open_resource_type(env, NULL, "xtt_client_group_context",
                                                           NULL, flags, NULL);

  data->res_client_handshake_context = enif_open_resource_type(env, NULL, "xtt_client_handshake_context",
                                                               NULL, flags, NULL);

  data->res_client = enif_open_resource_type(env, NULL, "xtt_nif_client", NULL, flags, NULL);
  data->res_struct = enif_open_resource_type(env, NULL, "xtt_nif_struct", NULL, flags, NULL);

  if (!data->res_server_root_certificate_context  ||
      !data->res_client_group_context ||
      !data->res_client_handshake_context ||
      !data->res_client ||
      !data->res_struct)
    return -1;

  return xtt_crypto_initialize_crypto();
}

#define DECLARE_ATOM(name) \
  ATOMS.name = make_atom(env, #name)

static int
on_nif_load(ErlNifEnv* env, void** priv, ERL_NIF_TERM load_info)
{
  DECLARE_ATOM(ok);
  DECLARE_ATOM(error);

  DECLARE_ATOM(want_write);
  DECLARE_ATOM(want_read);
  DECLARE_ATOM(want_buildserverattest);
  DECLARE_ATOM(want_preparseserverattest);
  DECLARE_ATOM(want_buildidclientattest);
  DECLARE_ATOM(want_preparseidclientattest);
  DECLARE_ATOM(want_verifygroupsignature);
  DECLARE_ATOM(want_buiildidserverfinshed);
  DECLARE_ATOM(want_parseidserverfinished);
  DECLARE_ATOM(handshake_finished);

  DECLARE_ATOM(alloc_failed);

  xtt_nif_data* data = enif_alloc(sizeof(*data));
  if (0 != open_resources(env, data))
  {
    enif_free(data);
    return -1;
  }

  *priv = data;
  return 0;
}

static void
on_nif_unload(ErlNifEnv* env, void* priv)
{
  UNUSED(env);
  xtt_nif_data* data = priv;
  enif_free(data);
}

static int
on_nif_upgrade(ErlNifEnv* env, void** priv, void** old_priv, ERL_NIF_TERM info)
{
  UNUSED(old_priv);
  UNUSED(info);

  xtt_nif_data* data = enif_alloc(sizeof(*data));
  if (!open_resources(env, data))
  {
    enif_free(data);
    return -1;
  }

  *priv = data;
  return 0;
}

static
ERL_NIF_TERM xtt_nif_identity_to_string(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){
  ErlNifBinary identity;
  xtt_identity_string* string;
  ERL_NIF_TERM ret;

  if ((argc != 1) ||
      (!enif_inspect_binary(env, argv[0], &identity)))
    return enif_make_badarg(env);

  if (identity.size != sizeof(xtt_identity_type))
    return enif_make_badarg(env);

  string = (void*) enif_make_new_binary(env, sizeof(*string), &ret);

  (void) xtt_identity_to_string((void*)identity.data, string);

  return ret;
}

static ErlNifFunc nif_funcs[] = {
    {"xtt_initialize_client_handshake_context", 2, xtt_nif_initialize_client_handshake_context, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_handshake_client_start", 1, xtt_nif_handshake_client_start, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_handshake_client_handle_io", 3, xtt_nif_handshake_client_handle_io, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_handshake_client_preparse_serverattest", 1, xtt_nif_handshake_client_preparse_serverattest, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_handshake_client_build_idclientattest", 4, xtt_nif_handshake_client_build_idclientattest, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_handshake_client_parse_idserverfinished", 1, xtt_nif_handshake_client_parse_idserverfinished, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_client_build_error_msg", 1, xtt_nif_client_build_error_msg, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_initialize_client_group_context_lrsw", 4, xtt_nif_initialize_client_group_context_lrsw, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_initialize_server_root_certificate_context_ecdsap256", 2, xtt_nif_initialize_server_root_certificate_context_ecdsap256, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_get_my_longterm_key_ecdsap256", 1, xtt_nif_get_my_longterm_key_ecdsap256, 0},
    {"xtt_get_my_longterm_private_key_ecdsap256", 1, xtt_nif_get_my_longterm_private_key_ecdsap256, 0},
    {"xtt_get_my_identity", 1, xtt_nif_get_my_identity, 0},
    {"xtt_get_my_pseudonym_lrsw", 1, xtt_nif_get_my_pseudonym_lrsw, 0},
    {"xtt_identity_to_string", 1, xtt_nif_identity_to_string, 0},
    {"xtt_x509_from_ecdsap256_keypair", 3, xtt_nif_x509_from_ecdsap256_keypair, 0},
};

ERL_NIF_INIT(xtt_nif, nif_funcs, &on_nif_load, NULL, on_nif_upgrade, on_nif_unload);
