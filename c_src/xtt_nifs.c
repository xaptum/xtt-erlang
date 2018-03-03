#include <string.h>
#include <ecdaa.h>
#include <xtt.h>
#include <erl_nif.h>

#define MAX_MESSAGE_SIZE 1024
#define MAX_BASENAME_SIZE 1024

static ERL_NIF_TERM
{
    if(argc != 2) {
        return enif_make_badarg(env);
    }
    if(!enif_get_int(env, argv[0], &version)) {
        return enif_make_badarg(env);
    }
    if(!enif_get_int(env, argv[1], &suite)) {
        return enif_make_badarg(env);
    }

    ERL_NIF_TERM result;
    ErlNifResourceType* ctx_type = (ErlNifResourceType*)enif_priv_data(env);

    xtt_error_code rc;
    unsigned char server_to_client[1024];
    unsigned char client_to_server[1024];
    // 1) Create client's handshake context
    (struct xtt_client_handshake_context) *client_handshake_ctx =
    (struct xtt_client_handshake_context *) enif_alloc_resource(ctx_type, sizeof(struct xtt_client_handshake_context));;
    rc = xtt_initialize_client_handshake_context(client_handshake_ctx,
                                                  version,
                                                  suite);

    if(rc != 0){
        fputs("Error initializing xtt handshake context\n", stderr);
            return enif_make_int(env, rc);
        }
    }

    result = enif_make_resource(env, client_handshake_ctx);
    enif_release_resource(client_handshake_ctx);
    return result;
}

static ERL_NIF_TERM
xtt_build_client_init(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){

    if(argc != 1) {
        return enif_make_badarg(env);
    }

    if(!enif_get_resource(env, argv[0], &client_handshake_ctx)) {
        return enif_make_badarg(env);
    }

    uint16_t client_init_send_length;
    rc = xtt_build_client_init(client_to_server,
                               &client_init_send_length,
                               &client_handshake_ctx);

    if(rc != 0){
        fputs("Error initializing xtt handshake context\n", stderr);
            return enif_make_int(env, rc);
        }
    }

    ErlNifBinary ret_bin;

    enif_alloc_binary(client_init_send_length, ret_bin); // Size of new binary
    memcpy(ret_bin.data, client_to_server, client_init_send_length); // Copying the contents of binary

    return enif_make_binary(env, ret_bin)
}