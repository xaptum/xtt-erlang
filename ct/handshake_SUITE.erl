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
-include("../include/xtt.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([test_file/1, test_tpm/1]).
-export([test_handshake/4, group_context_inputs_tpm/1]).

%% DEFAULT FILENAMES
-define(REQUESTED_CLIENT_ID_FILE, "requested_client_id.bin").
-define(SERVER_ID_FILE, "server_id.bin").
-define(DAA_GPK_FILE, "daa_gpk.bin").
-define(DAA_CRED_FILE, "daa_cred.bin").
-define(DAA_SECRETKEY_FILE, "daa_secretkey.bin").
-define(BASENAME_FILE, "basename.bin").
-define(ROOT_ID_FILE, "root_id.bin").
-define(ROOT_PUBKEY_FILE, "root_pub.bin").

%% Defaults
-define(XTT_VERSION, ?XTT_VERSION_ONE).
-define(XTT_SUITE, ?XTT_X25519_LRSW_ED25519_AES256GCM_SHA512).
-define(EXAMPLE_DATA_DIR, "example_data").

-define(XTT_SERVER_PORT, 4444).
-define(XTT_SERVER_PORT_TPM, 4445).
-define(XTT_SERVER_HOST, "localhost").

-define(TPM_HOSTNAME, "localhost").
-define(TPM_PORT,  "2321").
-define(TPM_PASSWORD, <<>>).

all() -> [test_tpm,test_file].

init_per_suite(Config)->
  application:ensure_all_started(lager),
  Config.

end_per_suite(Config) ->
  ok.

test_file(Config) ->
  lager:md([{source, "TEST_FILE"}]),
  DataDir = ?config(data_dir, Config),
  lager:info("test_file DataDir is ~p", [DataDir]),
  {ok, GroupContextInputs} = group_context_inputs(DataDir),
  test_handshake(DataDir, 'TEST_FILE', ?XTT_SERVER_PORT, GroupContextInputs),
  Config.

test_tpm(Config) ->
  lager:md([{source, "TEST_TPM"}]),
  DataDir = ?config(data_dir, Config),
  lager:info("test_tpm: DataDir is ~p", [DataDir]),
  {ok, GroupContextInputsTpm} = group_context_inputs_tpm(DataDir),
  test_handshake(DataDir, 'TEST_TPM', ?XTT_SERVER_PORT_TPM, GroupContextInputsTpm),
  Config.

test_handshake(DataDir, TestId, XttServerPort, GroupContextInputs)->
  {RequestedClientId, IntendedServerId} =
    xtt_utils:initialize_ids(DataDir, ?REQUESTED_CLIENT_ID_FILE, ?SERVER_ID_FILE),
  {ok, _Pid} = xtt_handshake:start_link(TestId,
    ?XTT_SERVER_HOST, XttServerPort,
    RequestedClientId, IntendedServerId,
    ?XTT_VERSION, ?XTT_SUITE,
    GroupContextInputs),
  process_handshake_result(TestId).

process_handshake_result(TestId)->
  process_handshake_result(TestId, gen_server:call(TestId, get_handshake_context, 10000)).

process_handshake_result(_TestId, {ok, HandshakeContext})->
  validate_handshake_context(HandshakeContext);
process_handshake_result(TestId, {error, {in_progress, CurrentStatus}})->
  lager:info("Waiting for handshake to finish, current status ~p", [CurrentStatus]),
  timer:sleep(100),
  process_handshake_result(TestId, gen_server:call(TestId, get_handshake_context, 10000));
process_handshake_result(_TestId, TotalFailure)->
  lager:info("Handshake failed: ~p", [TotalFailure]),
  {error, TotalFailure}.

validate_handshake_context(HandshakeContext)->
  lager:info("Handshake finished, validating results!"),

  {ok, LongTermKey} = xtt_erlang:xtt_get_my_longterm_key(HandshakeContext),
  lager:info("LongTermKey: ~p", [LongTermKey]),

  {ok, LongTermPrivKey} = xtt_erlang:xtt_get_my_longterm_private_key(HandshakeContext),
  lager:info("LongTermPrivKey: ~p", [LongTermPrivKey]),


  {ok, Identity} = xtt_erlang:xtt_get_my_id(HandshakeContext),
  lager:info("Identity: ~p", [Identity]),

  <<IP1:16,IP2:16,IP3:16,IP4:16,IP5:16,IP6:16, IP7:16,IP8:16>> = Identity,
  lager:info("Ipv6: ~p", [inet:ntoa({IP1, IP2, IP3, IP4, IP5, IP6, IP7, IP8})]),

  {ok, IdStr} = xtt_erlang:xtt_id_to_string(Identity),
  lager:info("Converted identity string: ~p", [IdStr]),

  {ok, Pseudonym} = xtt_erlang:xtt_get_my_pseudonym(HandshakeContext),
  lager:info("Psuedonym: ~p", [Pseudonym]),

  {ok, Cert} = xtt_erlang:xtt_x509_from_keypair(LongTermKey, LongTermPrivKey, Identity),
  lager:info("Cert: ~p", [Cert]),

  {ok, Asn1} = xtt_erlang:xtt_asn1_from_private_key(LongTermPrivKey),
  lager:info("Asn1: ~p", [Asn1]),

  {ok, handshake_valid}.

group_context_inputs(DataDir) ->
  xtt_utils:group_context_inputs(DataDir,
    ?BASENAME_FILE, ?DAA_GPK_FILE, ?DAA_CRED_FILE, ?DAA_SECRETKEY_FILE,
     ?ROOT_ID_FILE, ?ROOT_PUBKEY_FILE).

group_context_inputs_tpm(DataDir)->
  xtt_utils:group_context_inputs_tpm(DataDir, ?BASENAME_FILE, ?TPM_HOSTNAME, ?TPM_PORT, ?TPM_PASSWORD).
