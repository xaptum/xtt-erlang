%%%-------------------------------------------------------------------
%%% @author iguberman
%%% @copyright (C) 2018, Xaptum, Inc.
%%% @doc
%%%
%%% @end
%%% Created : 28. Apr 2018 9:21 PM
%%%-------------------------------------------------------------------
-module(handshake_SUITE).
-author("iguberman").

-include_lib("common_test/include/ct.hrl").

-include_lib("xtt_erlang/include/xtt.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([test_file/1, test_tpm/1]).
-export([test_handshake/3, group_context_inputs_tpm/1]).

%% Defaults
-define(XTT_VERSION, ?XTT_VERSION_ONE).
-define(XTT_SUITE, ?XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512).
-define(EXAMPLE_DATA_DIR, "example_data").

-define(XTT_SERVER_PORT, 4444).
-define(XTT_SERVER_PORT_TPM, 4445).
-define(XTT_SERVER_HOST, "localhost").

-define(TPM_HOSTNAME, "localhost").
-define(TPM_PORT,  "2321").
-define(TPM_PASSWORD, <<>>).

%%all() -> [test_tpm,test_file].
all() -> [].

init_per_suite(Config)->
  application:ensure_all_started(lager),
  Config.

end_per_suite(_Config) ->
  ok.

test_file(Config) ->
  lager:md([{source, "TEST_FILE"}]),
  DataDir = ?config(data_dir, Config),

  ok = initialize_certs(DataDir),

  {ok, GroupContextInputs} = group_context_inputs(DataDir),

  test_handshake(DataDir, ?XTT_SERVER_PORT, GroupContextInputs),

  Config.

test_tpm(Config) ->
  lager:md([{source, "TEST_TPM"}]),
  DataDir = ?config(data_dir, Config),

  {ok, GroupContextInputsTpm} = group_context_inputs_tpm(DataDir),
  test_handshake(DataDir, ?XTT_SERVER_PORT_TPM, GroupContextInputsTpm),
  Config.

test_handshake(DataDir, XttServerPort, GroupContextInputs)->
  RequestedClientIdFile = filename:join([DataDir, ?REQUESTED_CLIENT_ID_FILE]),
  IntendedServerIdFile = filename:join([DataDir, ?SERVER_ID_FILE]),

  {RequestedClientId, IntendedServerId} =
    xtt_utils:initialize_ids(RequestedClientIdFile, IntendedServerIdFile),
  {ok, Pid} = xtt_handshake:start_handshake(
    ?XTT_SERVER_HOST, XttServerPort,
    RequestedClientId, IntendedServerId,
    ?XTT_VERSION, ?XTT_SUITE,
    GroupContextInputs),
  process_handshake_result(Pid),
  xtt_handshake:handshake_complete(Pid).

process_handshake_result(HandshakePid)->
  {ok, HandshakeContext} = xtt_utils:get_handshake_result(HandshakePid),
  validate_handshake_context(HandshakeContext).

validate_handshake_context(HandshakeContext)->
  lager:info("Handshake finished, validating results!"),

  {ok, LongTermKey} = xtt_erlang:xtt_get_my_longterm_key(HandshakeContext),
  lager:info("LongTermKey: ~p", [LongTermKey]),

  {ok, LongTermPrivKey} = xtt_erlang:xtt_get_my_longterm_private_key(HandshakeContext),
  lager:info("LongTermPrivKey: ~p", [LongTermPrivKey]),

  {ok, Identity} = xtt_erlang:xtt_get_my_id(HandshakeContext),
  lager:info("Identity: ~p", [Identity]),

  lager:info("Ipv6: ~p", [xtt_utils:identity_to_ipv6_str(Identity)]),

  {ok, IdStr} = xtt_erlang:xtt_id_to_string(Identity),
  lager:info("Converted identity string: ~p", [IdStr]),

  {ok, Pseudonym} = xtt_erlang:xtt_get_my_pseudonym(HandshakeContext),
  lager:info("Psuedonym: ~p", [Pseudonym]),

  {ok, Cert} = xtt_erlang:xtt_x509_from_keypair(LongTermKey, LongTermPrivKey, Identity),
  lager:info("Cert: ~p", [Cert]),

  {ok, Asn1} = xtt_erlang:xtt_asn1_from_private_key(LongTermKey, LongTermPrivKey),
  lager:info("Asn1: ~p", [Asn1]),

  {ok, handshake_valid}.

initialize_certs(DataDir) ->
  RootIdFile = filename:join([DataDir,?ROOT_ID_FILE]),
  RootPubKeyFile = filename:join([DataDir, ?ROOT_PUBKEY_FILE]),

  xtt_utils:initialize_certs(RootIdFile, RootPubKeyFile).

group_context_inputs(DataDir) ->
  BasenameFile = filename:join([DataDir, ?BASENAME_FILE]),
  GpkFile = filename:join([DataDir, ?DAA_GPK_FILE]),
  CredFile = filename:join([DataDir, ?DAA_CRED_FILE]),
  PrivKeyFile = filename:join([DataDir, ?DAA_SECRETKEY_FILE]),
  GidFile = filename:join([DataDir, ?DAA_GID_FILE]),

  xtt_utils:group_context_inputs(
      GpkFile, CredFile, PrivKeyFile, BasenameFile, GidFile).

group_context_inputs_tpm(DataDir)->
  BasenameFile = filename:join([DataDir, ?BASENAME_FILE]),
  xtt_utils:group_context_inputs_tpm(BasenameFile, ?TPM_HOSTNAME, ?TPM_PORT, ?TPM_PASSWORD).
