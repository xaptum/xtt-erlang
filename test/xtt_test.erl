%%%-------------------------------------------------------------------
%%% @author iguberman
%%% @copyright (C) 2018, Xaptum, Inc.
%%% @doc
%%%
%%% @end
%%% Created : 19. Mar 2018 7:11 PM
%%%-------------------------------------------------------------------
-module(xtt_test).
-author("iguberman").

%% API
-export([test_params/0,
  client_test/0,
  client_TPM_test/0]).

-include_lib("eunit/include/eunit.hrl").
-include("../include/xtt.hrl").

-define(DEFAULT_DATA_DIR, ".").

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

example_data_dir()->
  filename:join([xtt_erlang:priv_dir(), ?EXAMPLE_DATA_DIR]).

test_params() ->
 #{
    host => ?XTT_SERVER_HOST,
    port => ?XTT_SERVER_PORT,
    xtt_version => ?XTT_VERSION_ONE,
    xtt_suite  => ?XTT_X25519_LRSW_ED25519_AES256GCM_SHA512,
    data_dir => example_data_dir(),
    use_tpm => false
 }.

test_paramsTPM() ->
  #{
    host => ?XTT_SERVER_HOST,
    port => ?XTT_SERVER_PORT_TPM,
    xtt_version => ?XTT_VERSION_ONE,
    xtt_suite  => ?XTT_X25519_LRSW_ED25519_AES256GCM_SHA512,
    data_dir => example_data_dir(),
    use_tpm => true,
    tpm_host => "localhost",
    tpm_port => "2321",
    tpm_password => <<>>
  }.

test_handshake(TestId, Params)->
  #{port := XttServerPort, host := XttServerHost} = Params,
  ensure_xtt_server_started(XttServerHost, XttServerPort),
  {RequestedClientId, IntendedServerId} = initialize_ids(Params),
  ok = initialize_certs(Params),
  {ok, GroupContextInputs} = group_context_inputs(Params),
  {ok, _Pid} = xtt_handshake:start_link(TestId,
    XttServerHost, XttServerPort,
    RequestedClientId, IntendedServerId,
    ?XTT_VERSION, ?XTT_SUITE,
    GroupContextInputs),
  {ok, HandshakeContext} = gen_server:call(TestId, get_handshake_context, 100000),
  ok = validate_handshake_context(HandshakeContext).

client_test()->
  Params = test_params(),
  lager:md([{source, "TEST_FILE"}]),
  lager:info("Staring client test with params ~p~n", [Params]),
  test_handshake('TEST_FILE', Params).

client_TPM_test()->
  Params = test_paramsTPM(),
  ensure_xtt_server_started(?XTT_SERVER_HOST, ?XTT_SERVER_PORT_TPM),
  lager:md([{source, "TEST_TPM"}]),
  lager:info("Staring client tst with params ~p~n", [Params]),
  test_handshake('TEST_TPM', Params).

ensure_xtt_server_started(ServerHost, ServerPort)->
  %% Check if running or
  %% Find xtt install dir and run
  %%os:cmd(?XTT_INSTALL_DIR ++ "/xtt_server " ++ integer_to_list(ServerPort)),
  ok.


validate_handshake_context(HandshakeContext)->
  %% TODO create and test here NIFs that retreive various bits of info from post-handshake context
  ok.

group_context_inputs(#{data_dir := DataDir, use_tpm := false} = ParameterMap) ->
  BasenameFile = maps:get(base_filename, ParameterMap, filename:join([DataDir, ?BASENAME_FILE])),
  GpkFile = maps:get(gpk_filename, ParameterMap, filename:join([DataDir, ?DAA_GPK_FILE])),
  CredFile = maps:get(cred_filename, ParameterMap, filename:join([DataDir, ?DAA_CRED_FILE])),
  PrivKeyFile = maps:get(priv_key_filename, ParameterMap, filename:join([DataDir, ?DAA_SECRETKEY_FILE])),

  {ok, Basename} = file:read_file(BasenameFile),

  {ok, Gpk} = file:read_file(GpkFile),

  {ok, Credential} = file:read_file(CredFile),

  {ok, PrivKey} = file:read_file(PrivKeyFile),

  Gid = crypto:hash(sha256, Gpk),

  ok = initialize_certs(ParameterMap), %% do it here for symmetry with below TPM group_context_inputs

  {ok, #group_context_inputs{gpk=Gid, credential = Credential, basename = Basename, priv_key = PrivKey}};

group_context_inputs(#{
  data_dir := DataDir,
  use_tpm := true,
  tpm_host := TpmHostname,
  tpm_port:= TpmPort,
  tpm_password := TpmPassword} = ParameterMap)->
  BasenameFile = maps:get(base_filename, ParameterMap, filename:join([DataDir, ?BASENAME_FILE])),
  {ok, Basename} = file:read_file(BasenameFile),
  case xaptum_tpm:tss2_tcti_initialize_socket(TpmHostname, TpmPort) of
    {ok, TctiContext} ->
      case  xaptum_tpm:tss2_sys_initialize(TctiContext) of
        {ok, SapiContext} ->
          {ok, Gpk} = xaptum_tpm:tss2_sys_nv_read(?XTT_DAA_GROUP_PUB_KEY_SIZE, ?GPK_HANDLE, SapiContext),

          {ok, Credential} = xaptum_tpm:tss2_sys_nv_read(?XTT_DAA_CRED_SIZE, ?CRED_HANDLE, SapiContext),

          Gid = crypto:hash(sha256, Gpk),

          PrivKeyInputs = #priv_key_tpm{key_handle = ?KEY_HANDLE, tpm_host = TpmHostname, tpm_port = TpmPort, tpm_password = TpmPassword},

          ok = initialize_certsTPM(SapiContext),

          {ok, #group_context_inputs{gpk = Gid, credential = Credential, basename = Basename, priv_key = PrivKeyInputs}};
        {error, _ErrorCode} -> {error, init_tss2_sys_failed}
      end;
    {error, _ErrorCode} -> {error, init_tss2_tcti_failed}
  end.

initialize_certs(#{data_dir := DataDir} = ParameterMap)->
  RootIdFilename = maps:get(root_id_filename, ParameterMap, filename:join(DataDir, ?ROOT_ID_FILE)),
  RootPubkeyFilename = maps:get(root_pubkey_filename, ParameterMap, filename:join(DataDir, ?ROOT_PUBKEY_FILE)),

  {ok, RootId} = file:read_file(RootIdFilename),
  {ok, RootPubKey} = file:read_file(RootPubkeyFilename),

  xtt_utils:init_cert_db(RootId, RootPubKey).

initialize_certsTPM(SapiContext)->
  {ok, RootId} = xaptum_tpm:tss2_sys_nv_read(?XTT_DAA_ROOT_ID_SIZE, ?ROOT_ID_HANDLE, SapiContext),
  {ok, RootPubKey} = xaptum_tpm:tss2_sys_nv_read(?XTT_DAA_ROOT_PUB_KEY_SIZE, ?ROOT_PUBKEY_HANDLE, SapiContext),
  xtt_utils:init_cert_db(RootId, RootPubKey).


initialize_ids(#{data_dir := DataDir} = ParameterMap)->
  RequestedClientIdFile = maps:get(requested_client_id_file, ParameterMap, filename:join([DataDir, ?REQUESTED_CLIENT_ID_FILE])),
  IntendedServerIdFile = maps:get(server_id_file, ParameterMap, filename:join([DataDir, ?SERVER_ID_FILE])),

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
