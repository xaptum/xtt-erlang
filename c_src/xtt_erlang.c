#include <string.h>
#include <ecdaa.h>
#include <xtt.h>
#include <erl_nif.h>

static ERL_NIF_TERM
xtt_client_handshake_context(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
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

    ERL_NIF_TERM  result = enif_make_resource(env, &ctx);
    enif_release_resource(&ctx);
    return result;
}

static ERL_NIF_TERM
xtt_initialize_client_group_context(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){

    if(argc != 4) {
        fprintf(stderr, "Bad arg error: expected 4 got %d\n", argc);
        return enif_make_badarg(env);
    }

    xtt_group_id gid;
    xtt_daa_priv_key_lrsw priv_key;
    xtt_daa_credential_lrsw cred;
    const unsigned char basename;

    if(!enif_get_string(env, argv[0], (char *) &gid, sizeof(gid), ERL_NIF_LATIN1 ) ) {
            fprintf(stderr, "Bad arg at position 0\n");
            return enif_make_badarg(env);
    }

    if(!enif_get_string(env, argv[1], (char *) &priv_key, sizeof(priv_key), ERL_NIF_LATIN1 ) ) {
            fprintf(stderr, "Bad arg at position 1\n");
            return enif_make_badarg(env);
    }

    if(!enif_get_string(env, argv[2], (char *) &cred, sizeof(cred), ERL_NIF_LATIN1 ) ) {
             fprintf(stderr, "Bad arg at position 2\n");
             return enif_make_badarg(env);
    }

    if(!enif_get_string(env, argv[3], (char *) &basename, sizeof(basename), ERL_NIF_LATIN1) ) {
        fprintf(stderr, "Bad arg at position 3\n");
        return enif_make_badarg(env);
    }


    struct xtt_client_group_context group_ctx_out;
    xtt_initialize_client_group_context_lrsw(&group_ctx_out,
                                &gid,
                                &priv_key,
                                &cred,
                                &basename, sizeof(basename));

    ERL_NIF_TERM result = enif_make_resource(env, &group_ctx_out);
    enif_release_resource(&group_ctx_out);
    return result;
}

static ErlNifFunc nif_funcs[] = {
    {"xtt_client_handshake_context", 2, xtt_client_handshake_context},
    {"xtt_initialize_client_group_context", 4, xtt_initialize_client_group_context}
};

ERL_NIF_INIT(xtt_erlang, nif_funcs, NULL, NULL, NULL, NULL)