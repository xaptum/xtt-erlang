/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2020 Xaptum, Inc.
 */

#pragma once

#ifndef XTT_NIF_H
#define XTT_NIF_H

#include <xtt.h>

#include "erl_nif.h"

typedef struct
{
  unsigned char in[MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH];
  unsigned char out[MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH];
  unsigned char *io_ptr;
  uint16_t bytes_requested;
  xtt_certificate_root_id claimed_root_id;
  struct xtt_client_handshake_context ctx;
} xtt_nif_client;

typedef struct
{
  ErlNifResourceType* res_struct;
  ErlNifResourceType* res_client_group_context;
  ErlNifResourceType* res_cert_context;
  ErlNifResourceType* res_client;
} xtt_nif_data;

#endif // XTT_NIF_H
