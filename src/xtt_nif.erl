-module(xtt_nif).

%% API exports
-export([
  init/0,
  xtt_init_client_handshake_context/2,
  xtt_initialize_client_group_context_lrsw/4,
  xtt_initialize_server_root_certificate_context_ecdsap256/2,
  xtt_start_client_handshake/1,
  xtt_client_handshake/3,
  xtt_handshake_preparse_serverattest/1,
  xtt_handshake_build_idclientattest/5,
  xtt_handshake_parse_idserverfinished/1,
  xtt_client_build_error_msg_nif/1,
  xtt_get_my_longterm_key/1,
  xtt_get_my_longterm_private_key/1,
  xtt_get_my_id/1,
  xtt_get_my_pseudonym/1,
  xtt_id_to_string/1,
  xtt_x509_from_keypair/3,
  xtt_asn1_from_private_key/2]).

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
%% API functions
%%====================================================================


%%====================================================================
%% NIFs
%%====================================================================

xtt_initialize_client_group_context_lrsw(_Gid, _PrivKey, _Credential, _Basename)->
  erlang:nif_error(?LINE).

xtt_initialize_server_root_certificate_context_ecdsap256(_RootId, _RootPubKey)->
  erlang:nif_error(?LINE).

xtt_init_client_handshake_context(_XttVersion, _XttSuite)->
  erlang:nif_error(?LINE).

xtt_start_client_handshake(_XttClientState)->
  erlang:nif_error(?LINE).

xtt_client_handshake(_XttClientState, _NumBytesWritten, _BytesRead)->
  erlang:nif_error(?LINE).

xtt_handshake_preparse_serverattest(_HandshakeState) ->
  erlang:nif_error(?LINE).

xtt_handshake_build_idclientattest(_ServerCert, _RequestedClientId, _IntendedServerId, _GroupContext, _HandshakeState)->
  erlang:nif_error(?LINE).

xtt_handshake_parse_idserverfinished(_HandsakeState)->
  erlang:nif_error(?LINE).

xtt_client_build_error_msg_nif(_XttVersion)->
  erlang:nif_error(?LINE).

xtt_get_my_longterm_key(_HandsakeState)->
  erlang:nif_error(?LINE).

xtt_get_my_longterm_private_key(_HandsakeState)->
  erlang:nif_error(?LINE).

xtt_get_my_id(_HandsakeState)->
  erlang:nif_error(?LINE).

xtt_get_my_pseudonym(_HandsakeState)->
  erlang:nif_error(?LINE).

xtt_id_to_string(_Identity)->
  erlang:nif_error(?LINE).

xtt_x509_from_keypair(_LongtermKey, _LongtermPrivKey, _Identity)->
  erlang:nif_error(?LINE).

xtt_asn1_from_private_key(_LontermKey, _LongtermPrivKey)->
  erlang:nif_error(?LINE).

%%====================================================================
%% Internal functions
%%====================================================================
