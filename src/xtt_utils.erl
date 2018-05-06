%%%-------------------------------------------------------------------
%%% @author iguberman
%%% @copyright (C) 2018, Xaptum, Inc.
%%% @doc
%%%
%%% @end
%%% Created : 19. Mar 2018 9:27 PM
%%%-------------------------------------------------------------------
-module(xtt_utils).
-author("iguberman").

-include("../include/xtt.hrl").

%% API
-export([
  get_handshake_result/1,
  group_context_inputs/7,
  group_context_inputs_tpm/5,
  initialize_certs/3,
  initialize_certsTPM/1,
  init_cert_db/2,
  lookup_cert/1,
  maybe_init_group_context/1,
  initialize_ids/3,
  identity_to_ipv6_str/1]).

-define(DEFAULT_ETS_OPTS, [named_table, set, public, {write_concurrency, true}, {read_concurrency, true}]).


get_handshake_result(HandshakeId)->
  wait_for_handshake_result(HandshakeId, gen_server:call(HandshakeId, get_handshake_context, 10000)).

wait_for_handshake_result(_HandshakeId, {ok, HandshakeContext})->
  {ok, HandshakeContext};
wait_for_handshake_result(HandshakeId, {error, {in_progress, CurrentStatus}})->
  lager:info("Waiting for handshake to finish, current status ~p", [CurrentStatus]),
  timer:sleep(100),
  wait_for_handshake_result(HandshakeId, gen_server:call(HandshakeId, get_handshake_context, 10000));
wait_for_handshake_result(HandshakeId, TotalFailure)->
  lager:info("Handshake ~p failed: ~p", [HandshakeId, TotalFailure]),
  {error, TotalFailure}.

group_context_inputs(DataDir, BasenameFile, GpkFile, CredFile, SecretkeyFile, RootIdFile, RootPubkeyFile) ->
  BasenameFileName = filename:join([DataDir, BasenameFile]),
  GpkFileName = filename:join([DataDir, GpkFile]),
  CredFileName = filename:join([DataDir, CredFile]),
  PrivKeyFileName = filename:join([DataDir, SecretkeyFile]),

  {ok, Basename} = file:read_file(BasenameFileName),

  {ok, Gpk} = file:read_file(GpkFileName),

  {ok, Credential} = file:read_file(CredFileName),

  {ok, PrivKey} = file:read_file(PrivKeyFileName),

  Gid = crypto:hash(sha256, Gpk),

  ok = xtt_utils:initialize_certs(DataDir, RootIdFile, RootPubkeyFile), %% do it here for symmetry with below TPM group_context_inputs

  {ok, #group_context_inputs{gpk=Gid, credential = Credential, basename = Basename, priv_key = PrivKey}}.


group_context_inputs_tpm(DataDir, BasenameFile, TpmHost, TpmPort, TpmPassword)->
  BasenameFileName = filename:join([DataDir, BasenameFile]),
  {ok, Basename} = file:read_file(BasenameFileName),
  case xaptum_tpm:tss2_sys_maybe_initialize(TpmHost, TpmPort) of
    {ok, SapiContext} ->
      {ok, Gpk} = xaptum_tpm:tss2_sys_nv_read(?XTT_DAA_GROUP_PUB_KEY_SIZE, ?GPK_HANDLE, SapiContext),

      {ok, Credential} = xaptum_tpm:tss2_sys_nv_read(?XTT_DAA_CRED_SIZE, ?CRED_HANDLE, SapiContext),

      Gid = crypto:hash(sha256, Gpk),

      PrivKeyInputs = #priv_key_tpm{key_handle = ?KEY_HANDLE,
        tcti_context = undefined,
        tpm_host = TpmHost, tpm_port = TpmPort, tpm_password = TpmPassword},

      ok = xtt_utils:initialize_certsTPM(SapiContext),

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


initialize_certs(DataDir, RootIdFile, RootPubkeyFile)->
  RootIdFilename = filename:join(DataDir, RootIdFile),
  RootPubkeyFilename = filename:join(DataDir, RootPubkeyFile),

  {ok, RootId} = file:read_file(RootIdFilename),
  {ok, RootPubKey} = file:read_file(RootPubkeyFilename),

  xtt_utils:init_cert_db(RootId, RootPubKey).

initialize_certsTPM(SapiContext)->
  {ok, RootId} = xaptum_tpm:tss2_sys_nv_read(?XTT_DAA_ROOT_ID_SIZE, ?ROOT_ID_HANDLE, SapiContext),
  {ok, RootPubKey} = xaptum_tpm:tss2_sys_nv_read(?XTT_DAA_ROOT_PUB_KEY_SIZE, ?ROOT_PUBKEY_HANDLE, SapiContext),
  xtt_utils:init_cert_db(RootId, RootPubKey).


init_cert_db(RootId, RootPubkey)->
  lager:info("Initializing cert db with RootId ~p and RootPubKey ~p", [RootId, RootPubkey]),
  case xtt_erlang:xtt_init_server_root_certificate_context(RootId, RootPubkey) of
    {ok, CertContext} ->
      case lists:member(?CERT_TABLE, ets:all()) of
        false -> ets:new(?CERT_TABLE, ?DEFAULT_ETS_OPTS);
        _True -> ok
      end,
      ets:insert(?CERT_TABLE, {RootId, CertContext}), %% TODO DB: Should replace file reading stuff with write ets to disk?
      lager:info("Initialized Certificates in '~p' table: ~p", [?CERT_TABLE, ets:tab2list(?CERT_TABLE)]),
      ok;
    {error, ErrorCode} ->
      lager:error("Error ~p initializing server root certificate context", [ErrorCode] ),
      {error, init_cert_context_failed}
  end.

lookup_cert(ClaimedRootId)->
  lager:info("Looking up server's certificate from its claimed root_id ~p", [ClaimedRootId]),
  case ets:lookup(?CERT_TABLE, ClaimedRootId) of
    [{ClaimedRootId, CertCtx}] -> {ClaimedRootId, CertCtx};
    [] -> %% TODO TEMP HACK
      RootId = ets:last(?CERT_TABLE),
      case ets:lookup(?CERT_TABLE, RootId) of
        [{ClaimedRootId, CertCtx}] -> {ClaimedRootId, CertCtx};
        _Other -> {error, doesnt_exist}
      end
  end.

maybe_init_group_context(GroupContext) when is_reference(GroupContext)->
  {ok, GroupContext};
maybe_init_group_context(#group_context_inputs{
  priv_key = #priv_key_tpm{tcti_context = undefined, tpm_host = TpmHost, tpm_port = TpmPort} = PrivKeyTpm} = GroupContextInputs) ->
  case xaptum_tpm:tss2_tcti_maybe_initialize_socket(TpmHost , TpmPort) of
    {ok, TctiContext} -> maybe_init_group_context(GroupContextInputs#group_context_inputs{priv_key = PrivKeyTpm#priv_key_tpm{tcti_context = TctiContext}});
    {error, ErrorCode} -> lager:error("Failed to initialize tcti context with error ~p", [ErrorCode]),
      {error, init_tss2_sys_failed}
  end;
maybe_init_group_context(#group_context_inputs{
  gpk = Gpk, credential = Credential, basename = Basename,
  priv_key = #priv_key_tpm{tcti_context = TctiContext, key_handle = KeyHandle, tpm_password = TpmPassword}}) ->
  case xtt_erlang:xtt_init_client_group_contextTPM(
    Gpk, Credential, Basename, KeyHandle, TpmPassword, TctiContext) of
    {ok, GroupCtxTPM} ->
      lager:info("Succes Creating GroupCtxTPM"),
      {ok, GroupCtxTPM};
    {error, ErrorCode} ->
      lager:error("Error ~p initializing client group context TPM", [ErrorCode]),
      {error, init_client_group_context_tpm_failed}
  end;
maybe_init_group_context(#group_context_inputs{
  gpk = Gpk, credential = Credential, basename = Basename, priv_key = PrivKey}) when is_binary(PrivKey) ->
  case xtt_erlang:xtt_init_client_group_context(Gpk, PrivKey, Credential, Basename) of
    {ok, GroupCtx} ->
      lager:info("Success Creating GroupCtx"),
      {ok, GroupCtx};
    {error, ErrorCode} ->
      lager:error("Error ~p initializing client group context", [ErrorCode]),
      {error, init_client_group_context_failed}
  end.



initialize_ids(DataDir, RequestedClientIdFile, ServerIdFile)->
  RequestedClientIdFileName = filename:join([DataDir, RequestedClientIdFile]),
  IntendedServerIdFileName = filename:join([DataDir, ServerIdFile]),

  RequestedClientId =
    case file:read_file(RequestedClientIdFileName) of
      {ok, ?XTT_REQUEST_ID_FROM_SERVER} -> ?XTT_NULL_IDENTITY;
      {ok, ClientId} when size(ClientId) =/= ?XTT_IDENTITY_SIZE ->
        lager:error("Invalid requested client id ~p of size ~b while expecting size ~b in file ~p",
          [ClientId, size(ClientId), ?XTT_IDENTITY_SIZE, RequestedClientIdFileName]),
        false = true;
      {ok, ClientId} when size(ClientId) =:= ?XTT_IDENTITY_SIZE -> ClientId
    end,

  {ok, IntendedServerId} = file:read_file(IntendedServerIdFileName),

  {RequestedClientId, IntendedServerId}.


identity_to_ipv6_str(Identity)->
  <<IP1:16,IP2:16,IP3:16,IP4:16,IP5:16,IP6:16, IP7:16,IP8:16>> = Identity,
  inet:ntoa({IP1, IP2, IP3, IP4, IP5, IP6, IP7, IP8}).