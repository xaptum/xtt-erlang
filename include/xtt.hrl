%%%-------------------------------------------------------------------
%%% @author iguberman
%%% @copyright (C) 2018, Xaptum, Inc.
%%% @doc
%%%
%%% @end
%%% Created : 19. Mar 2018 5:28 PM
%%%-------------------------------------------------------------------
-author("iguberman").

-record(priv_key_tpm,
{key_handle, tpm_password="", tcti_context}).

-record(group_context_inputs,
{gpk, credential, basename, priv_key}).


-define(XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512, 1).
-define(XTT_X25519_LRSW_ED25519_CHACHA20POLY1305_BLAKE2B, 2).
-define(XTT_X25519_LRSW_ED25519_AES256GCM_SHA512, 3).
-define(XTT_X25519_LRSW_ED25519_AES256GCM_BLAKE2B, 4).

-define(XTT_VERSION_ONE, 1).

-define(XTT_IDENTITY_SIZE, 16).
-define(XTT_REQUEST_ID_FROM_SERVER, <<"0">>).
-define(XTT_NULL_IDENTITY, <<0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>).

-define(XTT_RETURN_SUCCESS, 0).
-define(XTT_RETURN_FAILURE, -1).

%% Handahske next-state return codes:
-define(XTT_RETURN_WANT_WRITE, 1).
-define(XTT_RETURN_WANT_READ, 2).
-define(XTT_RETURN_WANT_BUILDSERVERATTEST, 3).
-define(XTT_RETURN_WANT_PREPARSESERVERATTEST, 4).
-define(XTT_RETURN_WANT_BUILDIDCLIENTATTEST, 5).
-define(XTT_RETURN_WANT_PREPARSEIDCLIENTATTEST, 6).
-define(XTT_RETURN_WANT_VERIFYGROUPSIGNATURE, 7).
-define(XTT_RETURN_WANT_BUILDIDSERVERFINISHED, 8).
-define(XTT_RETURN_WANT_PARSEIDSERVERFINISHED, 9).
-define(XTT_RETURN_HANDSHAKE_FINISHED, 10).

%% Error codes:
-define(XTT_RETURN_RECEIVED_ERROR_MSG,  11).

-define(CERT_TABLE, cert).