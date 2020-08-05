-module(xtt_nif).

%% API exports
-export([
  init/0,
  xtt_initialize_client_group_context_lrsw/4,
  xtt_initialize_server_root_certificate_context_ecdsap256/2,
  xtt_initialize_client_handshake_context/2,
  xtt_handshake_client_start/1,
  xtt_handshake_client_handle_io/3,
  xtt_handshake_client_preparse_serverattest/1,
  xtt_handshake_client_build_idclientattest/4,
  xtt_handshake_client_parse_idserverfinished/1,
  xtt_client_build_error_msg/1,
  xtt_get_my_longterm_key_ecdsap256/1,
  xtt_get_my_longterm_private_key_ecdsap256/1,
  xtt_get_my_identity/1,
  xtt_get_my_pseudonym_lrsw/1,
  xtt_identity_to_string/1,
  xtt_x509_from_ecdsap256_keypair/3]).

-export([priv_dir/0]).

-on_load(init/0).

-include("xtt.hrl").

-define(XTT_APPNAME, xtt_erlang).
-define(XTT_LIBNAME, 'xtt_nif').

init() ->
  application:set_env(lager, handlers, [
    {lager_console_backend, [{level, info}, {formatter, lager_default_formatter},
      {formatter_config, [time," [",source,"][",severity,"] ", message, "\n"]}]}]),
  application:ensure_all_started(lager),
  PrivDir = priv_dir(),
  case try_load(PrivDir, ?XTT_LIBNAME) of
    {error, Error} ->
      lager:info("Couldn't load lib ~p from ~p: ~p", [?XTT_LIBNAME, PrivDir, Error]),
      lager:info("Trying to load from ~p", [?XTT_APPNAME]),
      case try_load(PrivDir, ?XTT_APPNAME) of
        {error, Error} -> lager:error("Error loading lib ~p from ~p: ~p", [?XTT_APPNAME, PrivDir, Error]);
        ok ->
		      lager:info("Loaded ~p NIFs", [?XTT_APPNAME]),
		      ok
      end;
    ok -> ok
  end.

try_load(PrivDir, SoNameSuffix)->
  SoName = filename:join([PrivDir, SoNameSuffix]),
  lager:info("Loading XTT NIFs from ~p", [SoName]),
  case erlang:load_nif(SoName, 0) of
    ok ->
      lager:info("Successfully loaded NIFs from ~p", [SoName]);
    {error, {reload, ReloadMessage}} ->
		  lager:info("XTT NIFs already loaded"),
      ok;
    {error, RealError} ->
      {error, RealError}
  end.


priv_dir() ->
  case code:priv_dir(?XTT_APPNAME) of
    {error, bad_name} ->
      case filelib:is_dir(filename:join(["..", priv])) of
        true ->
          filename:join(["..", priv]);
        _ -> "priv"
      end;
    Dir -> Dir
  end.

-define(PRINT_BIN_LEN, 5).
%%-define(PRINT_BIN(Bin), binary:part(Bin, {0, ?PRINT_BIN_LEN})).
-define(PRINT_BIN(Bin), Bin).

%%====================================================================
%% NIFs
%%====================================================================

xtt_initialize_client_group_context_lrsw(_Gid, _PrivKey, _Credential, _Basename) ->
  erlang:nif_error(?LINE).

xtt_initialize_server_root_certificate_context_ecdsap256(_RootId, _RootPubKey) ->
  erlang:nif_error(?LINE).

xtt_initialize_client_handshake_context(_XttVersion, _XttSuiteSpec) ->
  erlang:nif_error(?LINE).

xtt_get_my_longterm_key_ecdsap256(_ClientHandshakeCtx)->
  erlang:nif_error(?LINE).

xtt_get_my_longterm_private_key_ecdsap256(_ClientHandshakeCtx)->
  erlang:nif_error(?LINE).

xtt_get_my_identity(_ClientHandshakeCtx)->
  erlang:nif_error(?LINE).

xtt_get_my_pseudonym_lrsw(_ClientHandshakeCtx)->
  erlang:nif_error(?LINE).

xtt_handshake_client_start(_ClientHandshakeCtx) ->
  erlang:nif_error(?LINE).

xtt_handshake_client_handle_io(_ClientHandshakeCtx, _BytesWritten, _Received) ->
  erlang:nif_error(?LINE).

xtt_handshake_client_preparse_serverattest(_ClientHandshakeCtx) ->
  erlang:nif_error(?LINE).

xtt_handshake_client_build_idclientattest(_ClientHandshakeCtx, _ServerRootCert, _RequestedClientId, _GroupCtx) ->
  erlang:nif_error(?LINE).

xtt_handshake_client_parse_idserverfinished(_ClientHandshakeCtx)->
  erlang:nif_error(?LINE).

xtt_client_build_error_msg(_ClientHandshakeCtx)->
  erlang:nif_error(?LINE).

xtt_identity_to_string(_Identity)->
  erlang:nif_error(?LINE).

xtt_x509_from_ecdsap256_keypair(_PublicKey, _PrivateKey, _CommonName)->
  erlang:nif_error(?LINE).
