/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2020 Xaptum, Inc.
 */

#include "asn1.h"

#include "atoms.h"
#include "nif_utils.h"
#include "xtt_nif.h"

ERL_NIF_TERM xtt_nif_x509_from_ecdsap256_keypair(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  ErlNifBinary pub_key, priv_key, common_name;
  unsigned char* cert;
  size_t cert_len = XTT_X509_CERTIFICATE_LENGTH;
  xtt_return_code_type rc;
  ERL_NIF_TERM term;

  if ((argc != 3) ||
      (!enif_inspect_binary(env, argv[0], &pub_key)) ||
      (!enif_inspect_binary(env, argv[1], &priv_key)) ||
      (!enif_inspect_binary(env, argv[2], &common_name)))
    return enif_make_badarg(env);

  if ((pub_key.size != sizeof(xtt_ecdsap256_pub_key)) ||
      (priv_key.size != sizeof(xtt_ecdsap256_priv_key)) ||
      (common_name.size != sizeof(xtt_identity_type)))
    return enif_make_badarg(env);

  cert = (void*) enif_make_new_binary(env, cert_len, &term);

  rc = xtt_x509_from_ecdsap256_keypair((void*)pub_key.data, (void*)priv_key.data,
                                       (void*)common_name.data,
                                       cert, cert_len);

  if (0 != rc)
    return make_error(env, enif_make_int(env, rc));

  return make_ok(env, term);
}
