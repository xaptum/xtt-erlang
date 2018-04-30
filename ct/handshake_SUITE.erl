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

-define(XTT_DAA_CRED_SIZE, 260).
-define(XTT_DAA_GROUP_PUB_KEY_SIZE, 258).
-define(XTT_DAA_ROOT_ID_SIZE, 16).
-define(XTT_DAA_ROOT_PUB_KEY_SIZE, 32).

-define(KEY_HANDLE, 16#81800000).
-define(GPK_HANDLE, 16#1410000).
-define(CRED_HANDLE, 16#1410001).
-define(ROOT_ID_HANDLE, 16#1410003).
-define(ROOT_PUBKEY_HANDLE, 16#1410004).


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
  ct:print("test_file DataDir is ~p~n", [DataDir]),
  {ok, GroupContextInputs} = group_context_inputs(DataDir),
  test_handshake(DataDir, 'TEST_FILE', ?XTT_SERVER_PORT, GroupContextInputs),
  Config.

test_tpm(Config) ->
  lager:md([{source, "TEST_TPM"}]),
  DataDir = ?config(data_dir, Config),
  ct:print("test_tpm: DataDir is ~p~n", [DataDir]),
  {ok, GroupContextInputsTpm} = group_context_inputs_tpm(DataDir),
  test_handshake(DataDir, 'TEST_TPM', ?XTT_SERVER_PORT_TPM, GroupContextInputsTpm),
  Config.


test_handshake(DataDir, TestId, XttServerPort, GroupContextInputs)->
  {RequestedClientId, IntendedServerId} = initialize_ids(DataDir),
  ok = initialize_certs(DataDir),
  {ok, _Pid} = xtt_handshake:start_link(TestId,
    ?XTT_SERVER_HOST, XttServerPort,
    RequestedClientId, IntendedServerId,
    ?XTT_VERSION, ?XTT_SUITE,
    GroupContextInputs),
  timer:sleep(5000), %% TODO wait for handshake to finish by adding separate status field to xtt_handshake state
  process_handshake_result(TestId).

process_handshake_result(TestId)->
  process_handshake_result(TestId, gen_server:call(TestId, get_handshake_context, 10000)).

process_handshake_result(_TestId, {ok, HandshakeContext})->
  validate_handshake_context(HandshakeContext);
process_handshake_result(TestId, {error, {in_progress, CurrentStatus}})->
  ct:print("Waiting for handshake to finish, current status ~p~n", [CurrentStatus]),
  timer:sleep(100),
  process_handshake_result(TestId, gen_server:call(TestId, get_handshake_context, 10000));
process_handshake_result(_TestId, TotalFailure)->
  ct:print("Handshake failed: ~p~n", [TotalFailure]),
  {error, TotalFailure}.

validate_handshake_context(HandshakeContext)->
  ct:print("Handshake finished, validating results!~n"),

  {ok, LongTermKey} = xtt_erlang:xtt_get_my_longterm_key(HandshakeContext),
  ct:print("LongTermKey: ~p~n", [LongTermKey]),

  {ok, LongTermPrivKey} = xtt_erlang:xtt_get_my_longterm_private_key(HandshakeContext),
  ct:print("LongTermPrivKey: ~p~n", [LongTermPrivKey]),

  {ok, Identity} = xtt_erlang:xtt_get_my_id(HandshakeContext),
  ct:print("Identity: ~p~n", [Identity]),

  {ok, IdStr} = xtt_erlang:xtt_id_to_string(Identity),
  ct:print("Converted identity string: ~p~n", [IdStr]),

  {ok, Pseudonym} = xtt_erlang:xtt_get_my_pseudonym(HandshakeContext),
  ct:print("Psuedonym: ~p~n", [Pseudonym]),

  {ok, handshake_valid}.

group_context_inputs(DataDir) ->
  BasenameFile = filename:join([DataDir, ?BASENAME_FILE]),
  GpkFile = filename:join([DataDir, ?DAA_GPK_FILE]),
  CredFile = filename:join([DataDir, ?DAA_CRED_FILE]),
  PrivKeyFile = filename:join([DataDir, ?DAA_SECRETKEY_FILE]),

  {ok, Basename} = file:read_file(BasenameFile),

  {ok, Gpk} = file:read_file(GpkFile),

  {ok, Credential} = file:read_file(CredFile),

  {ok, PrivKey} = file:read_file(PrivKeyFile),

  Gid = crypto:hash(sha256, Gpk),

  ok = initialize_certs(DataDir), %% do it here for symmetry with below TPM group_context_inputs

  {ok, #group_context_inputs{gpk=Gid, credential = Credential, basename = Basename, priv_key = PrivKey}}.

group_context_inputs_tpm(DataDir)->
  ct:print("DataDir is ~p~n", [DataDir]),
  BasenameFile = filename:join([DataDir, ?BASENAME_FILE]),
  {ok, Basename} = file:read_file(BasenameFile),
  case xaptum_tpm:tss2_sys_maybe_initialize(?TPM_HOSTNAME, ?TPM_PORT) of
    {ok, SapiContext} ->
      {ok, Gpk} = xaptum_tpm:tss2_sys_nv_read(?XTT_DAA_GROUP_PUB_KEY_SIZE, ?GPK_HANDLE, SapiContext),

      {ok, Credential} = xaptum_tpm:tss2_sys_nv_read(?XTT_DAA_CRED_SIZE, ?CRED_HANDLE, SapiContext),

      Gid = crypto:hash(sha256, Gpk),

      PrivKeyInputs = #priv_key_tpm{key_handle = ?KEY_HANDLE,
        tcti_context = undefined,
        tpm_host = ?TPM_HOSTNAME, tpm_port = ?TPM_PORT, tpm_password = ?TPM_PASSWORD},

      ok = initialize_certsTPM(SapiContext),

      %% TODO: temporarily using Gpk (and do hashing inside the NIF)
      %% using Gid instead of Gpk inside TPM group context creation
      %% later causes error 28 during xtt_handshake_build_idclientattest
      {ok, #group_context_inputs{
        gpk = Gpk,
        credential = Credential,
        basename = Basename,
        priv_key = PrivKeyInputs}};
    {error, _ErrorCode} -> {error, init_tss2_sys_failed}
  end.

initialize_certs(DataDir)->
  RootIdFilename = filename:join(DataDir, ?ROOT_ID_FILE),
  RootPubkeyFilename = filename:join(DataDir, ?ROOT_PUBKEY_FILE),

  {ok, RootId} = file:read_file(RootIdFilename),
  {ok, RootPubKey} = file:read_file(RootPubkeyFilename),

  xtt_utils:init_cert_db(RootId, RootPubKey).

initialize_certsTPM(SapiContext)->
  {ok, RootId} = xaptum_tpm:tss2_sys_nv_read(?XTT_DAA_ROOT_ID_SIZE, ?ROOT_ID_HANDLE, SapiContext),
  {ok, RootPubKey} = xaptum_tpm:tss2_sys_nv_read(?XTT_DAA_ROOT_PUB_KEY_SIZE, ?ROOT_PUBKEY_HANDLE, SapiContext),
  xtt_utils:init_cert_db(RootId, RootPubKey).


initialize_ids(DataDir)->
  RequestedClientIdFile = filename:join([DataDir, ?REQUESTED_CLIENT_ID_FILE]),
  IntendedServerIdFile = filename:join([DataDir, ?SERVER_ID_FILE]),

  RequestedClientId =
    case file:read_file(RequestedClientIdFile) of
      {ok, ?XTT_REQUEST_ID_FROM_SERVER} -> ?XTT_NULL_IDENTITY;
      {ok, ClientId} when size(ClientId) =/= ?XTT_IDENTITY_SIZE ->
        lager:error("Invalid requested client id ~p of size ~b while expecting size ~b in file ~p",
          [ClientId, size(ClientId), ?XTT_IDENTITY_SIZE, ?REQUESTED_CLIENT_ID_FILE]),
        false = true;
      {ok, ClientId} when size(ClientId) =:= ?XTT_IDENTITY_SIZE -> ClientId
    end,

  {ok, IntendedServerId} = file:read_file(IntendedServerIdFile),

  {RequestedClientId, IntendedServerId}.
