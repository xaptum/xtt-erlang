#include <string.h>
#include <ecdaa.h>
#include <xtt.h>
#include <erl_nif.h>

#define MAX_MESSAGE_SIZE 1024
#define MAX_BASENAME_SIZE 1024

static ERL_NIF_TERM
xtt_client_handshake_context(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){
{
    if(argc != 2) {
        return enif_make_badarg(env);
    }

    int version;
    int suite;

    if(!enif_get_int(env, argv[0], &version)) {
        return enif_make_badarg(env);
    }

    if(!enif_get_int(env, argv[1], &suite)) {
        return enif_make_badarg(env);
    }
    else if (suite != 1 && suite != 2 && suite != 3 && suite != 4) {
        fprintf(stderr, "Unknown suite %d\n", suite);
        return enif_make_badarg(env);
    }

    ERL_NIF_TERM result;

    xtt_return_code_type rc = XTT_RETURN_SUCCESS;

    // 1) Create client's handshake context
    unsigned char in_buffer[MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH];
    unsigned char out_buffer[MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH];
    struct xtt_client_handshake_context ctx;

    rc = xtt_initialize_client_handshake_context(&ctx, in_buffer, sizeof(in_buffer), out_buffer, sizeof(out_buffer), (xtt_version) version, (xtt_suite_spec) suite);
    if (XTT_RETURN_SUCCESS != rc) {
        fprintf(stderr, "Error initializing client handshake context: %d\n", rc);
        return enif_make_int(env, rc);
    }

    result = enif_make_resource(env, &ctx);
    enif_release_resource(&ctx);
    return result;
}

static ERL_NIF_TERM
xtt_initialize_client_group_context(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){

    if(argc != 4) {
        return enif_make_badarg(env);
    }

    xtt_group_id gid;
    xtt_daa_priv_key_lrsw priv_key;
    xtt_daa_credential_lrsw cred;
    const unsigned char basename;

    if(!enif_get_string(env, argv[0], &gid)) {
            return enif_make_badarg(env);
    }

    if(!enif_get_string(env, argv[1], &priv_key)) {
            return enif_make_badarg(env);
    }

    if(!enif_get_string(env, argv[2], &cred)) {
                return enif_make_badarg(env);
    }

    if(!enif_get_string(env, argv[3], &basename)) {
        return enif_make_badarg(env);
    }


    struct xtt_client_group_context group_ctx_out;
    xtt_initialize_client_group_context_lrsw(&group_ctx_out,
                                &gid,
                                &priv_key,
                                &cred,
                                &basename, sizeof(basename))

    result = enif_make_resource(env, &group_ctx_out);
    enif_release_resource(&group_ctx_out);
    return result;
}

//static ERL_NIF_TERM
//xtt_build_client_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){
//
//    if(argc != 1) {
//        return enif_make_badarg(env);
//    }
//
//    struct xtt_client_handshake_context client_handshake_ctx;
//
//    if(!enif_get_resource(env, argv[0], &client_handshake_ctx)) {
//        return enif_make_badarg(env);
//    }
//
//    uint16_t client_init_send_length;
//    unsigned char client_to_server[1024];
//
//    xtt_return_code_type rc = xtt_build_client_init(
//                               client_to_server,
//                               &client_init_send_length,
//                               &client_handshake_ctx);
//
//    if(rc != 0){
//        fputs("Error initializing xtt handshake context\n", stderr);
//            return enif_make_int(env, rc);
//        }
//    }
//
//    ErlNifBinary ret_bin;
//
//    enif_alloc_binary(client_init_send_length, ret_bin); // Size of new binary
//    memcpy(ret_bin.data, client_to_server, client_init_send_length); // Copying the contents of binary
//
//    return enif_make_binary(env, ret_bin)
//}


static ErlNifFunc nif_funcs[] = {
    {"xtt_client_handshake_context", 2, xtt_client_handshake_context},
    {"xtt_initialize_client_group_context", 4, xtt_initialize_client_group_context}
};

ERL_NIF_INIT(xtt_nifs, nif_funcs, NULL, NULL, NULL, NULL)