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
  init_cert_db/2,
  lookup_cert/1,
  maybe_init_group_context/1]).

-define(DEFAULT_ETS_OPTS, [named_table, set, public, {write_concurrency, true}, {read_concurrency, true}]).

init_cert_db(RootId, RootPubkey)->
  lager:info("Initializing cert db with RootId ~p and RootPubKey ~p", [RootId, print_bin(RootPubkey)]),
  case xtt_init_server_root_certificate_context(RootId, RootPubkey) of
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
  end




