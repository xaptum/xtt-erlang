#include <string.h>
#include <openssl/ssl.h>
#include <ecdaa.h>
#include <xtt.h>
#include <erl_nif.h>

#include "atoms.h"
#include "nif_utils.h"
#include "xtt_nif.h"

const char *longterm_public_key_out_file = "longterm_certificate.asn1.bin";
const char *longterm_private_key_out_file = "longterm_priv.asn1.bin";

static
int open_resources(ErlNifEnv* env, xtt_nif_data* data)
{
  ErlNifResourceFlags flags = (ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER);

  data->res_cert_context = enif_open_resource_type(env, NULL, "xtt_cert_context", NULL, flags, NULL);
  data->res_group_context = enif_open_resource_type(env, NULL, "xtt_group_context", NULL, flags, NULL);

  data->res_client = enif_open_resource_type(env, NULL, "xtt_nif_client", NULL, flags, NULL);
  data->res_struct = enif_open_resource_type(env, NULL, "xtt_nif_struct", NULL, flags, NULL);

  if (!data->res_cert_context  ||
      !data->res_group_context ||
      !data->res_client        ||
      !data->res_struct)
    return -1;

  return 0;
}

#define DECLARE_ATOM(name) \
  ATOMS.name = make_atom(env, #name);

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

  xtt_nif_data* data = enif_alloc(sizeof(*data));
  if (0 != open_resources(env, data))
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

// *************** INTERNAL FUNCTIONS *****************

static ERL_NIF_TERM
build_response(ErlNifEnv* env, int rc, xtt_nif_client *cs, ErlNifBinary *temp_bin)
{
    switch(rc) {
        case XTT_RETURN_WANT_WRITE:
            enif_alloc_binary(cs->bytes_requested, temp_bin);
            memcpy(temp_bin->data, cs->io_ptr, cs->bytes_requested);
            return make_return_binary(env, ATOMS.want_write, temp_bin);
        case XTT_RETURN_WANT_READ:
            return make_return_int(env, ATOMS.want_read, cs->bytes_requested);
        case XTT_RETURN_WANT_BUILDIDCLIENTATTEST:
            enif_alloc_binary(sizeof(xtt_certificate_root_id), temp_bin);
            memcpy(temp_bin->data, &(cs->claimed_root_id), sizeof(xtt_certificate_root_id));
            return make_return_binary(env, ATOMS.want_buildidclientattest, temp_bin);
        case XTT_RETURN_WANT_PREPARSESERVERATTEST:
            return make_return(env, ATOMS.want_preparseserverattest);
        case XTT_RETURN_WANT_PARSEIDSERVERFINISHED:
            return make_return(env, ATOMS.want_parseidserverfinished);
        case XTT_RETURN_HANDSHAKE_FINISHED:
            return make_return(env, ATOMS.handshake_finished);
        default:
            return make_return_int(env, ATOMS.error, rc);
    }
}

// ******************************************************

static ERL_NIF_TERM
xtt_init_client_group_context(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){
    xtt_nif_data* data = enif_priv_data(env);

    if(argc != 5) {
        fprintf(stderr, "Bad arg error: expected 4 got %d\n", argc);
        return enif_make_badarg(env);
    }

    ErlNifBinary gpkBin;
    ErlNifBinary daaPrivKeyBin;
    ErlNifBinary daaCredBin;
    ErlNifBinary basenameBin;
    ErlNifBinary gidBin;

    if(!enif_inspect_binary(env, argv[0], &gpkBin) ) {
            fprintf(stderr, "Bad arg at position 0\n");
            return enif_make_badarg(env);
    }
    else if (gpkBin.size != sizeof(xtt_group_id)){
        fprintf(stderr, "Bad arg at position 0: expecting xtt_daa_group_pub_key_lrsw size %lu got %zu\n",
        sizeof(xtt_daa_group_pub_key_lrsw), gpkBin.size);
        return enif_make_badarg(env);
    }

    if(!enif_inspect_binary(env, argv[1], &daaPrivKeyBin) ) {
            fprintf(stderr, "Bad arg at position 1\n");
            return enif_make_badarg(env);
    }
    else if (daaPrivKeyBin.size != sizeof(xtt_daa_priv_key_lrsw)){
        fprintf(stderr, "Bad arg at position 1: expecting xtt_daa_priv_key_lrsw size %lu got %zu\n",
        sizeof(xtt_daa_priv_key_lrsw), daaPrivKeyBin.size);
        return enif_make_badarg(env);
    }

    if(!enif_inspect_binary(env, argv[2], &daaCredBin) ) {
             fprintf(stderr, "Bad arg at position 2\n");
             return enif_make_badarg(env);
    }
    else if (daaCredBin.size != sizeof(xtt_daa_credential_lrsw)){
        fprintf(stderr, "Bad arg at position 2: expecting xtt_daa_credential_lrsw size %lu got %zu\n",
        sizeof(xtt_daa_credential_lrsw), daaCredBin.size);
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

     if(!enif_inspect_binary(env, argv[4], &gidBin) ) {
        fprintf(stderr, "Bad arg at position 4\n");
        return enif_make_badarg(env);
     }
     else if (gidBin.size != sizeof(xtt_group_id)){
        fprintf(stderr, "Bad arg at position 4: size of gid %lu more than xtt_group_id %d\n", gidBin.size, sizeof(xtt_group_id));
        return enif_make_badarg(env);
     }

    struct xtt_client_group_context *group_ctx = enif_alloc_resource(data->res_group_context, sizeof(struct xtt_client_group_context));

    if(group_ctx == NULL){
        puts("Failed to allocate xtt_client_group_context group_ctx!\n");
        return enif_make_badarg(env);
    }

    xtt_daa_priv_key_lrsw  *xtt_daa_priv_key = enif_alloc_resource(data->res_struct, sizeof(xtt_daa_priv_key_lrsw));
    xtt_daa_credential_lrsw *xtt_daa_cred = enif_alloc_resource(data->res_struct, sizeof(xtt_daa_credential_lrsw));

    memcpy(xtt_daa_priv_key->data, daaPrivKeyBin.data, sizeof(xtt_daa_priv_key_lrsw));
    memcpy(xtt_daa_cred->data, daaCredBin.data, sizeof(xtt_daa_credential_lrsw));

    xtt_group_id *gid = enif_alloc_resource(data->res_struct, sizeof(xtt_group_id));
    memcpy(gid->data, gidBin.data, sizeof(xtt_group_id));

    xtt_return_code_type rc = xtt_initialize_client_group_context_lrsw(group_ctx,
                                  gid,
                                  xtt_daa_priv_key,
                                  xtt_daa_cred,
                                  basenameBin.data,
                                  basenameBin.size);

    printf("Finished xtt_initialize_client_group_context_lrsw with return code %d\n", rc);

    ERL_NIF_TERM result;

    if (XTT_RETURN_SUCCESS != rc) {
            fprintf(stderr, "Error initializing client group context: %d\n", rc);
            result = make_error(env, enif_make_int(env, rc));
    }
    else{
        puts("SUCCESS\n");
        result = make_ok(env, enif_make_resource(env, group_ctx));
    }

    enif_release_resource(group_ctx);

    return result;
}

static ERL_NIF_TERM
xtt_init_server_root_certificate_context(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){
    xtt_nif_data* data = enif_priv_data(env);

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
    else if (certRootPubKeyBin.size != sizeof(xtt_ecdsap256_pub_key)){
        fprintf(stderr, "Bad arg at position 1: expecting xtt_ecdsap256_pub_key size %lu got %zu\n",
        sizeof(xtt_ecdsap256_pub_key), certRootPubKeyBin.size);
        return enif_make_badarg(env);
    }

    puts("enif_alloc_resource xtt_server_root_certificate_context\n");

    struct xtt_server_root_certificate_context *cert_ctx = enif_alloc_resource(data->res_cert_context,
                                                                               sizeof(struct xtt_server_root_certificate_context));

    if(cert_ctx == NULL){
        puts("Failed to allocate xtt_server_root_certificate_context cert_ctx!\n");
        return enif_make_badarg(env);
    }

    puts("STARTing xtt_initialize_server_root_certificate_context_ecdsap256.....\n");

    xtt_return_code_type rc = xtt_initialize_server_root_certificate_context_ecdsap256(cert_ctx,
                                                                (xtt_certificate_root_id *) certRootIdBin.data,
                                                                (xtt_ecdsap256_pub_key *) certRootPubKeyBin.data);

    ERL_NIF_TERM result;

    if (XTT_RETURN_SUCCESS != rc){
        fprintf(stderr, "Error initializing root certificate context: %d\n", rc);
        result = make_error(env, enif_make_int(env, rc));
    }
    else{
        puts("xtt_initialize_server_root_certificate_context_ecdsap256 SUCCESS\n");
        result = make_ok(env, enif_make_resource(env, cert_ctx));
    }

    enif_release_resource(cert_ctx);

    return result;
}

static ERL_NIF_TERM
xtt_init_client_handshake_context(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    xtt_nif_data* data = enif_priv_data(env);

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

     xtt_nif_client *cs = enif_alloc_resource(data->res_client, sizeof(*cs));

     if(cs == NULL){
        puts("Failed to allocate xtt_nif_client cs!\n");
        return enif_make_badarg(env);
     }


     cs->io_ptr = NULL;

     printf("STARTING xtt_initialize_client_handshake_context with version %d and suite %d...\n", version, suite);

     xtt_return_code_type rc = xtt_initialize_client_handshake_context(
            &(cs->ctx), cs->in, sizeof(cs->in), cs->out, sizeof(cs->out), (xtt_version) version, (xtt_suite_spec) suite);


     ERL_NIF_TERM  result;

     if (XTT_RETURN_SUCCESS != rc) {
        fprintf(stderr, "Error initializing client handshake context: %d\n", rc);
        result = make_error(env, enif_make_int(env, rc));
     }
     else {
        puts("SUCCESS\n");
        result = make_ok(env, enif_make_resource(env, cs));
     }

     enif_release_resource(cs);

     return result;

}

//STEP 1.
static ERL_NIF_TERM
xtt_start_client_handshake(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    xtt_nif_data* data = enif_priv_data(env);

    if(argc != 1) {
        return enif_make_badarg(env);
    }

    xtt_nif_client *cs;

    if(!enif_get_resource(env, argv[0], data->res_client, (void**) &cs)) {
        return enif_make_badarg(env);
    }

    xtt_return_code_type rc = xtt_handshake_client_start(&(cs->bytes_requested), &(cs->io_ptr), &(cs->ctx));

    printf("Result of xtt_handshake_client_start %d\n", rc);

    ErlNifBinary temp_bin;

    return build_response(env, rc, cs, &temp_bin);
}

static ERL_NIF_TERM
xtt_client_handshake(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){
    xtt_nif_data* data = enif_priv_data(env);

    if(argc != 3){
        return enif_make_badarg(env);
    }

    xtt_nif_client *cs;

    if(!enif_get_resource(env, argv[0], data->res_client, (void**) &cs)) {
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
    else{
        printf("Received bytes: %lu Written bytes: %zu\n", received_bin.size, bytes_written);
    }

    xtt_return_code_type rc = xtt_handshake_client_handle_io(
                               (uint16_t) bytes_written,
                               (uint16_t) received_bin.size,
                               &(cs->bytes_requested),
                               &(cs->io_ptr),
                               &(cs->ctx));

    ErlNifBinary temp_bin;

    return build_response(env, rc, cs, &temp_bin);
}

static ERL_NIF_TERM
xtt_handshake_preparse_serverattest(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){
    xtt_nif_data* data = enif_priv_data(env);

    if(argc != 1){
        return enif_make_badarg(env);
    }

    xtt_nif_client *cs;

    if(!enif_get_resource(env, argv[0], data->res_client, (void**) &cs)) {
        return enif_make_badarg(env);
    }

    xtt_return_code_type rc = xtt_handshake_client_preparse_serverattest(&(cs->claimed_root_id),
                                                    &(cs->bytes_requested),
                                                    &(cs->io_ptr),
                                                    &(cs->ctx));

    ErlNifBinary temp_bin;

    return build_response(env, rc, cs, &temp_bin);
}

static ERL_NIF_TERM
xtt_handshake_build_idclientattest(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){
    xtt_nif_data* data = enif_priv_data(env);

    if(argc != 5){
        return enif_make_badarg(env);
    }

    struct xtt_server_root_certificate_context *server_cert;

    ErlNifBinary requested_client_id;
    ErlNifBinary intended_server_id;
    struct xtt_client_group_context *group_ctx;
    xtt_nif_client *cs;

    if(!enif_get_resource(env, argv[0], data->res_cert_context, (void**) &server_cert)) {
    	return enif_make_badarg(env);
    }


    if(!enif_inspect_binary(env, argv[1], &requested_client_id) ) {
        fprintf(stderr, "Bad arg at position 1\n");
        return enif_make_badarg(env);
    }
    else if (requested_client_id.size != sizeof(xtt_identity_type)){
            fprintf(stderr, "Bad arg at position 1: expecting requested_client_id size %lu got %zu\n",
            sizeof(xtt_identity_type), requested_client_id.size);
            return enif_make_badarg(env);
     }

     if(!enif_inspect_binary(env, argv[2], &intended_server_id) ) {
            fprintf(stderr, "Bad arg at position 1\n");
            return enif_make_badarg(env);
     }
     else if (intended_server_id.size != sizeof(xtt_identity_type)){
            fprintf(stderr, "Bad arg at position 1: expecting requested_client_id size %lu got %zu\n",
            sizeof(xtt_identity_type), intended_server_id.size);
            return enif_make_badarg(env);
     }

    if(!enif_get_resource(env, argv[3], data->res_group_context, (void**) &group_ctx)) {
                return enif_make_badarg(env);
    }

    if(!enif_get_resource(env, argv[4], data->res_client, (void**) &cs)) {
            return enif_make_badarg(env);
    }

    xtt_return_code_type rc = xtt_handshake_client_build_idclientattest(&(cs->bytes_requested),
                                                       &(cs->io_ptr),
                                                       server_cert,
                                                       (xtt_identity_type *) requested_client_id.data,
                                                       group_ctx,
                                                       &(cs->ctx));

     printf("FINISHED NIF: xtt_handshake_build_idclientattest with response %d\n", rc);

     ErlNifBinary temp_bin;

     return build_response(env, rc, cs, &temp_bin);
}

static ERL_NIF_TERM
xtt_handshake_parse_idserverfinished(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){
    xtt_nif_data* data = enif_priv_data(env);

    if(argc != 1){
        return enif_make_badarg(env);
    }

    xtt_nif_client *cs;

    if(!enif_get_resource(env, argv[0], data->res_client, (void**) &cs)) {
        return enif_make_badarg(env);
    }

    xtt_return_code_type rc = xtt_handshake_client_parse_idserverfinished(&(cs->bytes_requested),
                                                     &(cs->io_ptr),
                                                     &(cs->ctx));
    ErlNifBinary temp_bin;

    return build_response(env, rc, cs, &temp_bin);
}

static ERL_NIF_TERM
xtt_client_build_error_msg_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){

   if(argc != 1) {
           return enif_make_badarg(env);
   }

   int version;

   if(!enif_get_int(env, argv[0], &version)) {
        return enif_make_badarg(env);
   }

   uint16_t *err_buff_len = (uint16_t *) 16;
   ErlNifBinary err_buffer_bin;
   enif_alloc_binary((size_t) err_buff_len, &err_buffer_bin);
   (void)xtt_client_build_error_msg(err_buffer_bin.data, err_buff_len, version);

   return enif_make_binary(env, &err_buffer_bin);
}

static ERL_NIF_TERM
xtt_get_my_longterm_key(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){
    xtt_nif_data* data = enif_priv_data(env);

    if(argc != 1){
        return enif_make_badarg(env);
    }

    xtt_nif_client *cs;

    if(!enif_get_resource(env, argv[0], data->res_client, (void**) &cs)) {
        return enif_make_badarg(env);
    }

    xtt_ecdsap256_pub_key clients_longterm_key;

    xtt_return_code_type rc = xtt_get_my_longterm_key_ecdsap256(&clients_longterm_key, &(cs->ctx));

    printf("Result of xtt_get_my_longterm_key_ecdsap256 is %d\n", rc);

    if (XTT_RETURN_SUCCESS != rc) {
        printf("Error getting the client's public longterm key!\n");
        return make_error(env, enif_make_int(env, rc));
    }
    else{
       ErlNifBinary longterm_key_bin;
       enif_alloc_binary(sizeof(xtt_ecdsap256_pub_key), &longterm_key_bin);
       memcpy(longterm_key_bin.data, clients_longterm_key.data, sizeof(xtt_ecdsap256_pub_key));
       return make_ok(env, enif_make_binary(env, &longterm_key_bin));
    }
}


static ERL_NIF_TERM
xtt_get_my_longterm_private_key(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){
    xtt_nif_data* data = enif_priv_data(env);

    if(argc != 1){
        return enif_make_badarg(env);
    }

    xtt_nif_client *cs;

    if(!enif_get_resource(env, argv[0], data->res_client, (void**) &cs)) {
        return enif_make_badarg(env);
    }

    xtt_ecdsap256_priv_key my_longterm_priv_key;

    xtt_return_code_type rc = xtt_get_my_longterm_private_key_ecdsap256(&my_longterm_priv_key, &(cs->ctx));

    printf("Result of xtt_get_my_longterm_private_key_ecdsap256 is %d\n", rc);

    if (XTT_RETURN_SUCCESS != rc) {
        printf("Error getting the client's private longterm key!\n");
        return make_error(env, enif_make_int(env, rc));
    }
    else{
        ErlNifBinary longterm_priv_key_bin;
        enif_alloc_binary(sizeof(xtt_ecdsap256_priv_key), &longterm_priv_key_bin);
        memcpy(longterm_priv_key_bin.data, my_longterm_priv_key.data, sizeof(xtt_ecdsap256_priv_key));
        return make_ok(env, enif_make_binary(env, &longterm_priv_key_bin));
    }
}

static ERL_NIF_TERM
xtt_get_my_id(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){
    xtt_nif_data* data = enif_priv_data(env);

    if(argc != 1){
        return enif_make_badarg(env);
    }

    xtt_nif_client *cs;

    if(!enif_get_resource(env, argv[0], data->res_client, (void**) &cs)) {
        return enif_make_badarg(env);
    }

    xtt_identity_type client_id;

    xtt_return_code_type rc = xtt_get_my_identity(&client_id, &(cs->ctx));

    printf("Result of xtt_get_my_identity is %d\n", rc);

    if (XTT_RETURN_SUCCESS != rc) {
        printf("Error getting the client's identity!\n");
        return make_error(env, enif_make_int(env, rc));
    }
    else{
       ErlNifBinary client_id_bin;
       enif_alloc_binary(sizeof(xtt_identity_type), &client_id_bin);
       memcpy(client_id_bin.data, client_id.data, sizeof(xtt_identity_type));
       return make_ok(env, enif_make_binary(env, &client_id_bin));
    }
}

static ERL_NIF_TERM
xtt_get_my_pseudonym(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){
    xtt_nif_data* data = enif_priv_data(env);

    if(argc != 1){
        return enif_make_badarg(env);
    }

    xtt_nif_client *cs;

    if(!enif_get_resource(env, argv[0], data->res_client, (void**) &cs)) {
        return enif_make_badarg(env);
    }

    xtt_daa_pseudonym_lrsw pseudonym;

    xtt_return_code_type rc = xtt_get_my_pseudonym_lrsw(&pseudonym, &(cs->ctx));

    printf("Result of xtt_get_my_pseudonym_lrsw is %d\n", rc);

    if (XTT_RETURN_SUCCESS != rc) {
        printf("Error getting the client's pseudonym!\n");
        return make_error(env, enif_make_int(env, rc));
    }
    else{
       ErlNifBinary pseudonym_bin;
       enif_alloc_binary((size_t) sizeof(xtt_daa_pseudonym_lrsw), &pseudonym_bin);
       memcpy(pseudonym_bin.data, pseudonym.data, sizeof(xtt_daa_pseudonym_lrsw));
       return make_ok(env, enif_make_binary(env, &pseudonym_bin));
    }
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
        X509 * temp_x509 = (X509 *) cert_buf;

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
    {"xtt_init_client_handshake_context", 2, xtt_init_client_handshake_context, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_start_client_handshake", 1, xtt_start_client_handshake, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_client_handshake", 3, xtt_client_handshake, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_handshake_preparse_serverattest", 1, xtt_handshake_preparse_serverattest, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_handshake_build_idclientattest", 5, xtt_handshake_build_idclientattest, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_handshake_parse_idserverfinished", 1, xtt_handshake_parse_idserverfinished, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_client_build_error_msg_nif", 1, xtt_client_build_error_msg_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_init_client_group_context", 5, xtt_init_client_group_context, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_init_server_root_certificate_context", 2, xtt_init_server_root_certificate_context, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"xtt_get_my_longterm_key", 1, xtt_get_my_longterm_key, 0},
    {"xtt_get_my_longterm_private_key", 1, xtt_get_my_longterm_private_key, 0},
    {"xtt_get_my_id", 1, xtt_get_my_id, 0},
    {"xtt_get_my_pseudonym", 1, xtt_get_my_pseudonym, 0},
    {"xtt_id_to_string", 1, xtt_id_to_string, 0},
    {"xtt_x509_from_keypair", 3, xtt_x509_from_keypair, 0},
};

ERL_NIF_INIT(xtt_nif, nif_funcs, &on_nif_load, NULL, NULL, NULL);
