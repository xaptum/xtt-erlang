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

-include("xtt.hrl").

%% API
-export([
  get_handshake_result/1,
  group_context_inputs/5,
  initialize_certs/2,
  init_cert_db/2,
  lookup_cert/1,
  maybe_init_group_context/1,
  initialize_ids/2,
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

group_context_inputs(GpkFile, CredFile, SecretkeyFile, BasenameFile, GidFile) ->

  {ok, Basename} = file:read_file(BasenameFile),

  {ok, _Gpk} = file:read_file(GpkFile),

  {ok, Credential} = file:read_file(CredFile),

  {ok, PrivKey} = file:read_file(SecretkeyFile),

  {ok, Gid} = file:read_file(GidFile),

  {ok, #group_context_inputs{gpk=Gid, credential = Credential, basename = Basename, priv_key = PrivKey, gid = Gid}}.

initialize_certs(RootIdFile, RootPubkeyFile) ->
  {ok, RootId} = file:read_file(RootIdFile),
  {ok, RootPubKey} = file:read_file(RootPubkeyFile),

  xtt_utils:init_cert_db(RootId, RootPubKey).

init_cert_db(RootId, RootPubkey)->
  lager:info("Initializing cert db with RootId ~p and RootPubKey ~p", [RootId, RootPubkey]),
  case xtt_nif:xtt_initialize_server_root_certificate_context_ecdsap256(RootId, RootPubkey) of
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
  case lists:member(?CERT_TABLE, ets:all()) of
    true ->
      case ets:lookup(?CERT_TABLE, ClaimedRootId) of
        [{ClaimedRootId, CertCtx}] -> {ClaimedRootId, CertCtx};
        [] -> %% TODO TEMP HACK
          RootId = ets:last(?CERT_TABLE),
          case ets:lookup(?CERT_TABLE, RootId) of
          [{ClaimedRootId, CertCtx}] -> {ClaimedRootId, CertCtx};
          _Other -> {error, doesnt_exist}
          end
      end;
    _False -> {error, cert_table_not_initialized}
  end.

maybe_init_group_context(GroupContext) when is_reference(GroupContext)->
  {ok, GroupContext};
maybe_init_group_context(#group_context_inputs{
  gpk = Gpk, credential = Credential, basename = Basename, priv_key = PrivKey, gid = Gid}) when is_binary(PrivKey) ->
  case xtt_nif:xtt_initialize_client_group_context_lrsw(Gid, PrivKey, Credential, Basename) of
    {ok, GroupCtx} ->
      lager:info("Success Creating GroupCtx"),
      {ok, GroupCtx};
    {error, ErrorCode} ->
      lager:error("Error ~p initializing client group context", [ErrorCode]),
      {error, init_client_group_context_failed}
  end.


initialize_ids(RequestedClientIdFile, IntendedServerIdFile)->
  RequestedClientId =
    case file:read_file(RequestedClientIdFile) of
      {ok, ?XTT_REQUEST_ID_FROM_SERVER} -> ?XTT_NULL_IDENTITY;
      {ok, ClientId} when size(ClientId) =/= ?XTT_IDENTITY_SIZE ->
        lager:error("Invalid requested client id ~p of size ~b while expecting size ~b in file ~p",
          [ClientId, size(ClientId), ?XTT_IDENTITY_SIZE, RequestedClientIdFile]),
        false = true;
      {ok, ClientId} when size(ClientId) =:= ?XTT_IDENTITY_SIZE -> ClientId
    end,

  {ok, IntendedServerId} = file:read_file(IntendedServerIdFile),

  {RequestedClientId, IntendedServerId}.


identity_to_ipv6_str(Identity)->
  <<IP1:16,IP2:16,IP3:16,IP4:16,IP5:16,IP6:16, IP7:16,IP8:16>> = Identity,
  inet:ntoa({IP1, IP2, IP3, IP4, IP5, IP6, IP7, IP8}).
