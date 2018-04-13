#include <string.h>
#include <ecdaa.h>
#include <xtt.h>
#include <erl_nif.h>

extern ErlNifResourceType* TCTI_RESOURCE_TYPE;

#define USE_TPM 1

ERL_NIF_TERM ATOM_OK;
ERL_NIF_TERM ATOM_ERROR;

static int
load(ErlNifEnv* env, void** priv, ERL_NIF_TERM load_info)
{
    ATOM_OK = enif_make_atom(env, "ok");
    ATOM_ERROR = enif_make_atom(env, "error");


    return 0;
}

static ERL_NIF_TERM
get_TCTI(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]){

    puts("START NIF: get_TCTI...\n");

    if(argc != 1) {
        fprintf(stderr, "Bad arg error: expected 1 got %d\n", argc);
        return enif_make_badarg(env);
    }

    TSS2_TCTI_CONTEXT * tcti_context;

    if(!enif_get_resource(env, argv[0], TCTI_RESOURCE_TYPE, (void**) &tcti_context)) {
        return enif_make_badarg(env);
    }

    printf("SUCCESS getting TCTI context arg: %p\n", tcti_context);

    return enif_make_tuple2(env, ATOM_OK, argv[0]);

}

static ErlNifFunc nif_funcs[] = {
   {"get_TCTI", 1, get_TCTI, ERL_NIF_DIRTY_JOB_CPU_BOUND}
};

ERL_NIF_INIT(xtt_erlang, nif_funcs, &load, NULL, NULL, NULL);