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

    printf("xtt_initialize_client_handshake_context with version %d and suite %d\n", version, suite);

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

    ErlNifBinary gidBin;
    ErlNifBinary daaPrivKeyBin;
    ErlNifBinary daaCredBin;
    ErlNifBinary basenameBin;

    if(!enif_inspect_binary(env, argv[0], &gidBin) ) {
            fprintf(stderr, "Bad arg at position 0\n");
            return enif_make_badarg(env);
    }
    else if (gidBin.size != sizeof(xtt_group_id)){
        fprintf(stderr, "Bad arg at position 0: expecting xtt_group_id size %lu got %zu\n",
        sizeof(xtt_group_id), gidBin.size);
        return enif_make_badarg(env);
    }

    if(!enif_inspect_binary(env, argv[1], &daaPrivKeyBin) ) {
            fprintf(stderr, "Bad arg at position 1\n");
            return enif_make_badarg(env);
    }
    else if (daaPrivKeyBin.size != sizeof(xtt_daa_priv_key_lrsw)){
        fprintf(stderr, "Bad arg at position 1: expecting xtt_daa_priv_key_lrsw size %lu got %zu\n",
        sizeof(xtt_daa_priv_key_lrsw), gidBin.size);
        return enif_make_badarg(env);
    }

    if(!enif_inspect_binary(env, argv[2], &daaCredBin) ) {
             fprintf(stderr, "Bad arg at position 2\n");
             return enif_make_badarg(env);
    }
    else if (daaCredBin.size != sizeof(xtt_daa_credential_lrsw)){
        fprintf(stderr, "Bad arg at position 2: expecting xtt_daa_credential_lrsw size %lu got %zu\n",
        sizeof(xtt_daa_credential_lrsw), gidBin.size);
        return enif_make_badarg(env);
    }

    if(!enif_inspect_binary(env, argv[3], &basenameBin) ) {
        fprintf(stderr, "Bad arg at position 3\n");
        return enif_make_badarg(env);
    }
    else if (sizeof(basenameBin) > MAX_BASENAME_LENGTH){
        fprintf(stderr, "Bad arg at position 3: size of basename %lu more than MAX %d\n", sizeof(basenameBin), MAX_BASENAME_LENGTH);
        return enif_make_badarg(env);
    }

    struct xtt_client_group_context group_ctx_out;

    puts("Starting xtt_initialize_client_group_context_lrsw\n");

    xtt_return_code_type rc = xtt_initialize_client_group_context_lrsw(&group_ctx_out,
                                (xtt_group_id *) gidBin.data,
                                (xtt_daa_priv_key_lrsw *) daaPrivKeyBin.data,
                                (xtt_daa_credential_lrsw *) daaCredBin.data,
                                basenameBin.data,
                                basenameBin.size);

    printf("Finished xtt_initialize_client_group_context_lrsw with rc %d\n", rc);

    if (XTT_RETURN_SUCCESS != rc) {
            fprintf(stderr, "Error initializing client group context: %d\n", rc);
            return enif_make_int(env, rc);
    }

    ERL_NIF_TERM result = enif_make_resource(env, &group_ctx_out);
    enif_release_resource(&group_ctx_out);

    return result;
}

static ERL_NIF_TERM
xtt_initialize_server_root_certificate_context(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){

    if(argc != 2) {
        fprintf(stderr, "Bad arg error: expected 2 got %d\n", argc);
        return enif_make_badarg(env);
    }

    ErlNifBinary certRootIdBin;
    ErlNifBinary certRootPubKeyBin;

    if(!enif_inspect_binary(env, argv[0], &certRootIdBin) ) {
        fprintf(stderr, "Bad arg at position 1\n");
        return enif_make_badarg(env);
    }
    else if (certRootIdBin.size != sizeof(xtt_certificate_root_id)){
        fprintf(stderr, "Bad arg at position 0: expecting xtt_certificate_root_id size %lu got %zu\n",
        sizeof(xtt_certificate_root_id), certRootIdBin.size);
        return enif_make_badarg(env);
    }

    if(!enif_inspect_binary(env, argv[1], &certRootPubKeyBin) ) {
            fprintf(stderr, "Bad arg at position 1\n");
            return enif_make_badarg(env);
    }
    else if (certRootPubKeyBin.size != sizeof(xtt_ed25519_pub_key)){
        fprintf(stderr, "Bad arg at position 2: expecting xtt_ed25519_pub_key size %lu got %zu\n",
        sizeof(xtt_ed25519_pub_key), certRootPubKeyBin.size);
        return enif_make_badarg(env);
    }

    struct xtt_server_root_certificate_context *cert_ctx;
    xtt_return_code_type rc = xtt_initialize_server_root_certificate_context_ed25519(cert_ctx,
                                                                (xtt_certificate_root_id *) certRootIdBin.data,
                                                                (xtt_ed25519_pub_key *) certRootPubKeyBin.data);
    if (XTT_RETURN_SUCCESS != rc){
        fprintf(stderr, "Error initializing root certificate context: %d\n", rc);
        return enif_make_int(env, rc);
    }

    ERL_NIF_TERM result = enif_make_resource(env, &cert_ctx);
    enif_release_resource(&cert_ctx);
    return result;
}

static ErlNifFunc nif_funcs[] = {
    {"xtt_client_handshake_context", 2, xtt_client_handshake_context},
    {"xtt_initialize_client_group_context", 4, xtt_initialize_client_group_context},
    {"xtt_initialize_server_root_certificate_context", 2, xtt_initialize_server_root_certificate_context}
};

ERL_NIF_INIT(xtt_erlang, nif_funcs, NULL, NULL, NULL, NULL)