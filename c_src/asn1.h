/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2020 Xaptum, Inc.
 */

#pragma once

#ifndef XTT_NIF_ASN1_H
#define XTT_NIF_ASN1_H

#include "erl_nif.h"

ERL_NIF_TERM xtt_nif_x509_from_ecdsap256_keypair(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

#endif // XTT_NIF_ASN1_H
