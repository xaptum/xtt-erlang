/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2020 Xaptum, Inc.
 */

#pragma once

#ifndef XTT_NIF_CLIENT_HANDSHAKE_CONTEXT_H
#define XTT_NIF_CLIENT_HANDSHAKE_CONTEXT_H

#include "erl_nif.h"

// --------------- initialization ---------------
ERL_NIF_TERM xtt_nif_initialize_client_handshake_context(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

// --------------- accessors ---------------
ERL_NIF_TERM xtt_nif_get_my_identity(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM xtt_nif_get_my_longterm_key_ecdsap256(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM xtt_nif_get_my_longterm_private_key_ecdsap256(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM xtt_nif_get_my_pseudonym_lrsw(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

// --------------- handshake ---------------
ERL_NIF_TERM xtt_nif_handshake_client_start(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM xtt_nif_handshake_client_handle_io(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM xtt_nif_handshake_client_preparse_serverattest(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM xtt_nif_handshake_client_build_idclientattest(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM xtt_nif_handshake_client_parse_idserverfinished(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

ERL_NIF_TERM xtt_nif_client_build_error_msg(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

#endif // XTT_NIF_CLIENT_HANDSHAKE_CONTEXT_H
