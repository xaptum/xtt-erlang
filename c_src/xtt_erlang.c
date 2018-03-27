#include <string.h>
#include <ecdaa.h>
#include <xtt.h>
#include <erl_nif.h>
#include <mcheck.h>

ErlNifResourceType* CLIENT_STATE_RESOURCE_TYPE;
ErlNifResourceType* GROUP_CONTEXT_RESOURCE_TYPE;
ErlNifResourceType* SERVER_ROOT_CERT_RESOURCE_TYPE;

struct client_state {
          unsigned char in[MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH];
          unsigned char out[MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH];
          unsigned char *io_ptr;
          uint16_t bytes_requested;
          xtt_certificate_root_id claimed_root_id;
          struct xtt_client_handshake_context ctx;
        };

void
free_resource(ErlNifEnv* env, void* obj)
{
   enif_free(obj);
}

static int
load(ErlNifEnv* env, void** priv, ERL_NIF_TERM load_info)
{
    const char* mod = "xtt_erlang";
    const char* cs_name = "struct client_state";
    const char* gc_name = "struct xtt_client_group_context";
    const char* srcc_name = "struct xtt_server_root_certificate_context";

    CLIENT_STATE_RESOURCE_TYPE = enif_open_resource_type(
        env, mod, cs_name, free_resource, ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL
    );

    if(CLIENT_STATE_RESOURCE_TYPE == NULL)
        return -1;

    GROUP_CONTEXT_RESOURCE_TYPE = enif_open_resource_type(
            env, mod, gc_name, free_resource, ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL
    );

    if(GROUP_CONTEXT_RESOURCE_TYPE == NULL)
        return -1;

    SERVER_ROOT_CERT_RESOURCE_TYPE = enif_open_resource_type(
        env, mod, srcc_name, free_resource, ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER, NULL
    );

    if(SERVER_ROOT_CERT_RESOURCE_TYPE == NULL)
        return -1;

    return 0;
}

// *************** INTERNAL FUNCTIONS *****************

static ERL_NIF_TERM
build_response(ErlNifEnv* env, int rc, ERL_NIF_TERM state, struct client_state *cs){

    printf("Building response with ret code %d\n", rc);

    ERL_NIF_TERM ret_code = enif_make_int(env, rc);
//    ERL_NIF_TERM state = enif_make_resource(env, &cs);
//    enif_release_resource(&cs);

    switch(rc){
        case XTT_RETURN_WANT_READ:
            puts("Building response for XTT_RETURN_WANT_READ\n");
            return enif_make_tuple3(env, ret_code, enif_make_int(env, cs->bytes_requested), state);
        case XTT_RETURN_WANT_WRITE:
            puts("Building response for XTT_RETURN_WANT_WRITE\n");
            printf("Creating write buffer of length %d from %s\n", cs->bytes_requested, cs->ctx.base.out_end);
            ErlNifBinary *write_bin;
            enif_alloc_binary(cs->bytes_requested, write_bin);
            memcpy(write_bin->data, cs->ctx.base.out_end, cs->bytes_requested);

            return XTT_RETURN_WANT_WRITE;

            return enif_make_tuple3(env, ret_code, enif_make_binary(env, write_bin), state);
        case XTT_RETURN_WANT_BUILDIDCLIENTATTEST:
            puts("Building response for XTT_RETURN_WANT_BUILDIDCLIENTATTEST\n");

            //typedef struct {unsigned char data[16];} xtt_certificate_root_id;
            ErlNifBinary *claimed_root_id_bin;
            enif_alloc_binary(sizeof(xtt_certificate_root_id), claimed_root_id_bin);
            memcpy(claimed_root_id_bin->data, &(cs->claimed_root_id), sizeof(xtt_certificate_root_id));
            return enif_make_tuple3(env, ret_code, enif_make_binary(env, claimed_root_id_bin), state);
        default:
            printf("Building default response for %d\n", rc);
            return enif_make_tuple2(env, ret_code, state);
    }
}


 // ******************************************************


static ERL_NIF_TERM
xtt_init_client_group_context(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){

    puts("START NIF: xtt_init_client_group_context...\n");

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
    else if (basenameBin.size > MAX_BASENAME_LENGTH){
        fprintf(stderr, "Bad arg at position 3: size of basename %lu more than MAX %d\n", basenameBin.size, MAX_BASENAME_LENGTH);
        return enif_make_badarg(env);
    }

    struct xtt_client_group_context *group_ctx_out = enif_alloc_resource(GROUP_CONTEXT_RESOURCE_TYPE, sizeof(struct xtt_client_group_context));

    if(group_ctx_out == NULL){
        puts("Failed to allocate xtt_client_group_context group_ctx_out!\n");
        return enif_make_badarg(env);
    }

    puts("Starting xtt_initialize_client_group_context_lrsw.....\n");

    xtt_return_code_type rc = xtt_initialize_client_group_context_lrsw(group_ctx_out,
                                (xtt_group_id *) gidBin.data,
                                (xtt_daa_priv_key_lrsw *) daaPrivKeyBin.data,
                                (xtt_daa_credential_lrsw *) daaCredBin.data,
                                basenameBin.data,
                                basenameBin.size);

    printf("Finished xtt_initialize_client_group_context_lrsw with return code %d\n", rc);

    ERL_NIF_TERM result;

    if (XTT_RETURN_SUCCESS != rc) {
            fprintf(stderr, "Error initializing client group context: %d\n", rc);
            result = enif_make_int(env, rc);
    }
    else{
        puts("SUCCESS\n");
        result = enif_make_resource(env, group_ctx_out);
    }

    enif_release_resource(group_ctx_out);

    return result;
}

static ERL_NIF_TERM
xtt_init_server_root_certificate_context(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){

    puts("START NIF: xtt_init_server_root_certificate_context...\n");

    if(argc != 2) {
        fprintf(stderr, "Bad arg error: expected 2 got %d\n", argc);
        return enif_make_badarg(env);
    }

    ErlNifBinary certRootIdBin;
    ErlNifBinary certRootPubKeyBin;

    if(!enif_inspect_binary(env, argv[0], &certRootIdBin) ) {
        fprintf(stderr, "Bad arg at position 0\n");
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
        fprintf(stderr, "Bad arg at position 1: expecting xtt_ed25519_pub_key size %lu got %zu\n",
        sizeof(xtt_ed25519_pub_key), certRootPubKeyBin.size);
        return enif_make_badarg(env);
    }


    puts("enif_alloc_resource xtt_server_root_certificate_context\n");

    struct xtt_server_root_certificate_context *cert_ctx = enif_alloc_resource(SERVER_ROOT_CERT_RESOURCE_TYPE, sizeof(struct xtt_server_root_certificate_context));

    if(cert_ctx == NULL){
        puts("Failed to allocate xtt_server_root_certificate_context cert_ctx!\n");
        return enif_make_badarg(env);
    }

    puts("STARTing xtt_initialize_server_root_certificate_context_ed25519.....\n");

    xtt_return_code_type rc = xtt_initialize_server_root_certificate_context_ed25519(cert_ctx,
                                                                (xtt_certificate_root_id *) certRootIdBin.data,
                                                                (xtt_ed25519_pub_key *) certRootPubKeyBin.data);

    ERL_NIF_TERM result;

    if (XTT_RETURN_SUCCESS != rc){
        fprintf(stderr, "Error initializing root certificate context: %d\n", rc);
        result = enif_make_int(env, rc);
    }
    else{
        puts("SUCCESS\n");
        result = enif_make_resource(env, cert_ctx);
    }

    enif_release_resource(cert_ctx);

    return result;
}

static ERL_NIF_TERM
xtt_init_client_handshake_context(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    puts("START NIF: xtt_client_handshake_context...\n");

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

     struct client_state *cs = enif_alloc_resource(CLIENT_STATE_RESOURCE_TYPE, sizeof(struct client_state));

     if(cs == NULL){
        puts("Failed to allocate client_state cs!\n");
        return enif_make_badarg(env);
     }


     cs->io_ptr = NULL;

     printf("STARTING xtt_initialize_client_handshake_context with version %d and suite %d...\n", version, suite);

     xtt_return_code_type rc = xtt_initialize_client_handshake_context(
            &(cs->ctx), cs->in, sizeof(cs->in), cs->out, sizeof(cs->out), (xtt_version) version, (xtt_suite_spec) suite);


     ERL_NIF_TERM  result;

     if (XTT_RETURN_SUCCESS != rc) {
        fprintf(stderr, "Error initializing client handshake context: %d\n", rc);
        result = enif_make_int(env, rc);
     }
     else {
        puts("SUCCESS\n");
        result = enif_make_resource(env, cs);
     }

     enif_release_resource(cs);

     return result;

}

//STEP 1.
static ERL_NIF_TERM
xtt_start_client_handshake(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    puts("START NIF: xtt_start_client_handshake...\n");

    if(argc != 1) {
        return enif_make_badarg(env);
    }

    struct client_state *cs;

    ERL_NIF_TERM cs_term = argv[0];

    if(!enif_get_resource(env, cs_term, CLIENT_STATE_RESOURCE_TYPE, (void**) &cs)) {
        return enif_make_badarg(env);
    }

    xtt_return_code_type rc = xtt_handshake_client_start(&(cs->bytes_requested), &(cs->io_ptr), &(cs->ctx));

    printf("Result of xtt_handshake_test %d\n", rc);

    return build_response(env, rc, cs_term, cs);
}

static ERL_NIF_TERM
xtt_client_handshake(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){

    puts("START NIF: xtt_client_handshake...\n");

    if(argc != 3){
        return enif_make_badarg(env);
    }

    struct client_state *cs;

    ERL_NIF_TERM cs_term = argv[0];

    if(!enif_get_resource(env, cs_term, CLIENT_STATE_RESOURCE_TYPE, (void**) &cs)) {
        return enif_make_badarg(env);
    }

    int bytes_written;

    if(!enif_get_int(env, argv[1],  &bytes_written)) {
            return enif_make_badarg(env);
    }

    ErlNifBinary received_bin;

    if(!enif_inspect_binary(env, argv[2], &received_bin)) {
            return enif_make_badarg(env);
    }

    if(received_bin.size > 0 && bytes_written == 0){
        printf("Appending received binary of size %lu to io_ptr...\n", received_bin.size);
        memcpy(cs->io_ptr, received_bin.data, received_bin.size);
        puts("DONE\n");
    }

    xtt_return_code_type rc = xtt_handshake_client_handle_io(
                               (uint16_t) &bytes_written,
                               (uint16_t) &(received_bin.size),
                               &(cs->bytes_requested),
                               &(cs->io_ptr),
                               &(cs->ctx));

    return build_response(env, rc, cs_term, cs);
}

static ERL_NIF_TERM
xtt_handshake_preparse_serverattest(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){

    puts("START NIF: xtt_handshake_preparse_serverattest...\n");

    if(argc != 1){
        return enif_make_badarg(env);
    }

    struct client_state *cs;

    ERL_NIF_TERM cs_term = argv[0];

    if(!enif_get_resource(env, cs_term, CLIENT_STATE_RESOURCE_TYPE, (void**) &cs)) {
        return enif_make_badarg(env);
    }

    xtt_return_code_type rc = xtt_handshake_client_preparse_serverattest(&(cs->claimed_root_id),
                                                    &(cs->bytes_requested),
                                                    &(cs->io_ptr),
                                                    &(cs->ctx));
    return build_response(env, rc, cs_term, cs);
}

static ERL_NIF_TERM
xtt_handshake_build_idclientattest(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){

    puts("START NIF: xtt_handshake_build_idclientattest...\n");

    if(argc != 5){
        return enif_make_badarg(env);
    }

    struct xtt_server_root_certificate_context *server_cert;
    //typedef struct {unsigned char data[16];} xtt_identity_type;
    ErlNifBinary *requested_client_id;
    ErlNifBinary *intended_server_id;
    struct xtt_client_group_context *group_ctx;
    struct client_state *cs;


    if(!enif_get_resource(env, argv[0], SERVER_ROOT_CERT_RESOURCE_TYPE, (void**) &server_cert)) {
    	return enif_make_badarg(env);
    }


    if(!enif_inspect_binary(env, argv[1], requested_client_id) ) {
        fprintf(stderr, "Bad arg at position 1\n");
        return enif_make_badarg(env);
    }
    else if (requested_client_id->size != sizeof(xtt_identity_type)){
            fprintf(stderr, "Bad arg at position 1: expecting requested_client_id size %lu got %zu\n",
            sizeof(xtt_identity_type), requested_client_id->size);
            return enif_make_badarg(env);
     }

     if(!enif_inspect_binary(env, argv[2], intended_server_id) ) {
            fprintf(stderr, "Bad arg at position 1\n");
            return enif_make_badarg(env);
     }
     else if (intended_server_id->size != sizeof(xtt_identity_type)){
            fprintf(stderr, "Bad arg at position 1: expecting requested_client_id size %lu got %zu\n",
            sizeof(xtt_identity_type), intended_server_id->size);
            return enif_make_badarg(env);
     }

    if(!enif_get_resource(env, argv[3], GROUP_CONTEXT_RESOURCE_TYPE, (void**) &group_ctx)) {
                return enif_make_badarg(env);
    }

    ERL_NIF_TERM cs_term = argv[4];

    if(!enif_get_resource(env, cs_term, CLIENT_STATE_RESOURCE_TYPE, (void**) &cs)) {
            return enif_make_badarg(env);
    }

    xtt_return_code_type rc = xtt_handshake_client_build_idclientattest(&(cs->bytes_requested),
                                                   &(cs->io_ptr),
                                                   server_cert,
						   (xtt_identity_type *) &(requested_client_id->data),
                                                   (xtt_identity_type *) &(intended_server_id->data),
                                                   group_ctx,
                                                   &(cs->ctx));

    return build_response(env, rc, cs_term, cs);
}

static ERL_NIF_TERM
xtt_handshake_parse_idserverfinished(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){

    puts("START NIF: xtt_handshake_parse_idserverfinished...\n");

    if(argc != 1){
        return enif_make_badarg(env);
    }

    struct client_state *cs;

    ERL_NIF_TERM cs_term = argv[0];

    if(!enif_get_resource(env, cs_term, CLIENT_STATE_RESOURCE_TYPE, (void**) &cs)) {
        return enif_make_badarg(env);
    }

    xtt_return_code_type rc = xtt_handshake_client_parse_idserverfinished(&(cs->bytes_requested),
                                                     &(cs->io_ptr),
                                                     &(cs->ctx));
    return build_response(env, rc, cs_term, cs);
}

static ERL_NIF_TERM
xtt_build_error_msg(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){

   if(argc != 1) {
           return enif_make_badarg(env);
   }

   int version;

   if(!enif_get_int(env, argv[0], &version)) {
        return enif_make_badarg(env);
   }

//   unsigned char err_buffer[16]; // TODO fix
  // (void)build_error_msg(err_buffer, &bytes_requested, version);

   uint16_t *err_buff_len = (uint16_t *) 16;
   ErlNifBinary *err_buffer_bin;
   enif_alloc_binary((size_t) err_buff_len, err_buffer_bin);
   (void)build_error_msg(err_buffer_bin->data, err_buff_len, version);
   //         memcpy(err_buffer_bin->data, err_buffer, sizeof(err_buffer);

   return enif_make_binary(env, err_buffer_bin); // for writing by xtt_erlang.erl
}

// STEP 2. repeat (SENDING) until XTT_RETURN_WANT_READ returned
// ctx->state = XTT_CLIENT_HANDSHAKE_STATE_SENDING_CLIENTINIT;
// rc = XTT_RETURN_WANT_READ if sent complete message || XTT_RETURN_WANT_WRITE if we need to send more || XTT_RETURN_BAD_IO_LENGTH if sent too much
//
// STEP 3. repeat (RECEIVING) until XTT_RETURN_WANT_WRITE
// ctx->state = XTT_CLIENT_HANDSHAKE_STATE_READING_SERVERATTESTHEADER;
// rc = XTT_RETURN_WANT_READ;
//
// STEP 4.

static ErlNifFunc nif_funcs[] = {
    {"xtt_init_client_handshake_context", 2, xtt_init_client_handshake_context, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_start_client_handshake", 1, xtt_start_client_handshake, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_client_handshake", 3, xtt_client_handshake, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_handshake_preparse_serverattest", 1, xtt_handshake_preparse_serverattest, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_handshake_build_idclientattest", 5, xtt_handshake_build_idclientattest, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_handshake_parse_idserverfinished", 1, xtt_handshake_parse_idserverfinished, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_build_error_msg", 1, xtt_build_error_msg, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_init_client_group_context", 4, xtt_init_client_group_context, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_init_server_root_certificate_context", 2, xtt_init_server_root_certificate_context, ERL_NIF_DIRTY_JOB_CPU_BOUND}
};

ERL_NIF_INIT(xtt_erlang, nif_funcs, &load, NULL, NULL, NULL);