#include <string.h>
#include <openssl/ssl.h>
#include <ecdaa.h>
#include <xtt.h>

#include "erl_nif.h"

#include "xtt_nif.h"

#include "atoms.h"
#include "nif_utils.h"

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

static int write_buffer_to_file(const char *filename, unsigned char *buffer, size_t bytes_to_write)
{
    FILE *ptr;

    ptr = fopen(filename, "wb");
    if (NULL == ptr)
        return -1;

    size_t bytes_written = fwrite(buffer, 1, bytes_to_write, ptr);

    (void)fclose(ptr);


    return (int)bytes_written;
}

static ERL_NIF_TERM
xtt_id_to_string(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){

//    puts("START NIF: xtt_id_to_string...\n");

    if(argc != 1){
        return enif_make_badarg(env);
    }

    ErlNifBinary my_assigned_id;

    if(!enif_inspect_binary(env, argv[0], &my_assigned_id) ) {
        fprintf(stderr, "Bad 'my_assigned_id' arg\n");
        return enif_make_badarg(env);
    }
    else if (my_assigned_id.size != sizeof(xtt_identity_type)){
        fprintf(stderr, "Bad arg at position 0: expecting 'my_assigned_id' of size %lu got %zu\n",
        sizeof(xtt_identity_type), my_assigned_id.size);
        return enif_make_badarg(env);
    }

    xtt_identity_string my_assigned_id_as_string;
    int convert_ret = xtt_identity_to_string(
                                    (xtt_identity_type *) my_assigned_id.data,
                                    &my_assigned_id_as_string
                                );
    if (0 != convert_ret) {
        fprintf(stderr, "Error converting assigned id %s to string\n", my_assigned_id.data);
        return make_error(env, enif_make_int(env, convert_ret));
    }

    printf("Converted my_assigned_id %s to string %s\n", my_assigned_id.data, my_assigned_id_as_string.data);

    ErlNifBinary id_str_bin;
    enif_alloc_binary((size_t) sizeof(xtt_identity_string), &id_str_bin);
    memcpy(id_str_bin.data, my_assigned_id_as_string.data, sizeof(xtt_identity_string));
    return make_ok(env, enif_make_binary(env, &id_str_bin));
}

static ERL_NIF_TERM
xtt_x509_from_keypair(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){

//    puts("START NIF: xtt_x509_from_keypair...\n");

    if(argc != 3){
        return enif_make_badarg(env);
    }

    ErlNifBinary my_longterm_key;
    ErlNifBinary my_longterm_priv_key;
    ErlNifBinary my_assigned_id;

    if(!enif_inspect_binary(env, argv[0], &my_longterm_key) ) {
        fprintf(stderr, "Bad 'my_longterm_key' arg\n");
        return enif_make_badarg(env);
    }
    else if (my_longterm_key.size != sizeof(xtt_ecdsap256_pub_key)){
        fprintf(stderr, "Bad arg at position 0: expecting 'my_longterm_key' of size %lu got %zu\n",
        sizeof(xtt_ecdsap256_pub_key), my_longterm_key.size);
        return enif_make_badarg(env);
    }

    if(!enif_inspect_binary(env, argv[1], &my_longterm_priv_key) ) {
        fprintf(stderr, "Bad 'my_longterm_priv_key' arg\n");
        return enif_make_badarg(env);
    }
    else if (my_longterm_priv_key.size != sizeof(xtt_ecdsap256_priv_key)){
        fprintf(stderr, "Bad arg at position 1: expecting 'my_longterm_priv_key' of size %lu got %zu\n",
        sizeof(xtt_ecdsap256_priv_key), my_longterm_priv_key.size);
        return enif_make_badarg(env);
    }

    if(!enif_inspect_binary(env, argv[2], &my_assigned_id) ) {
        fprintf(stderr, "Bad 'my_assigned_id' arg\n");
        return enif_make_badarg(env);
    }
    else if (my_assigned_id.size != sizeof(xtt_identity_type)){
        fprintf(stderr, "Bad arg at position 0: expecting 'my_assigned_id' of size %lu got %zu\n",
        sizeof(xtt_identity_type), my_assigned_id.size);
        return enif_make_badarg(env);
    }

    // Save longterm keypair as X509 certificate
    unsigned char cert_buf[XTT_X509_CERTIFICATE_LENGTH];

    if (0 != xtt_x509_from_ecdsap256_keypair((xtt_ecdsap256_pub_key *) my_longterm_key.data,
                                           (xtt_ecdsap256_priv_key *) my_longterm_priv_key.data,
                                           (xtt_identity_type *) my_assigned_id.data,
                                           cert_buf, sizeof(cert_buf))) {



        fprintf(stderr, "Error creating X509 certificate\n");
        return make_error(env, enif_make_int(env, 1));
    }
    else{
        ErlNifBinary cert_bin;
        enif_alloc_binary((size_t) XTT_X509_CERTIFICATE_LENGTH, &cert_bin);
        memcpy(cert_bin.data, cert_buf, XTT_X509_CERTIFICATE_LENGTH);

        int write_ret = write_buffer_to_file(longterm_public_key_out_file, cert_buf, sizeof(cert_buf));
        if (sizeof(cert_buf) != write_ret) {
            fprintf(stderr, "Error writing longterm public key certificate to file\n");
            return 1;
        }

        return make_ok(env, enif_make_binary(env, &cert_bin));
    }
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
    {"xtt_id_to_string", 1, xtt_id_to_string, 0},
    {"xtt_x509_from_keypair", 3, xtt_x509_from_keypair, 0},
};

ERL_NIF_INIT(xtt_nif, nif_funcs, &on_nif_load, NULL, on_nif_upgrade, on_nif_unload);
