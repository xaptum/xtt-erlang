/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2020 Xaptum, Inc.
 */

#pragma once

#ifndef XTT_NIF_CLIENT_GROUP_CONTEXT_H
#define XTT_NIF_CLIENT_GROUP_CONTEXT_H

#include "erl_nif.h"

ERL_NIF_TERM xtt_nif_initialize_client_group_context_lrsw(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

#endif // XTT_NIF_CLIENT_GROUP_CONTEXT_H
