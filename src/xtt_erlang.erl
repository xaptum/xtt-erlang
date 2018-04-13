-module(xtt_erlang).

%% API exports
-export([
  init/0,
  create_and_pass_TCTI/0,
  get_TCTI/1]).

-export([priv_dir/0]).

-on_load(init/0).

-include("xtt.hrl").

-define(XTT_APPNAME, xtt_erlang).
-define(XTT_LIBNAME, 'xtt-erlang').

-define(TCP_OPTIONS, [binary, {packet, 0}, {keepalive, true}, {active, false}]).

-define(DEFAULT_ETS_OPTS, [named_table, set, public, {write_concurrency, true}, {read_concurrency, true}]).

-define(CERT_TABLE, cert).

init() ->
  application:ensure_all_started(lager),

  SoName = filename:join([priv_dir(), ?XTT_LIBNAME]),
  lager:info("Loading XTT NIFs from ~p", [SoName]),
  case erlang:load_nif(SoName, 0) of
    ok ->
      lager:info("Successfully loaded NIFs from ~p", [SoName]);
    {error, {reload, ReloadMessage}} ->
      lager:info("Reload attempt: ~p", [ReloadMessage]),
      ok;
    {error, RealError} -> lager:error("Error loading NIF library: ~p", [RealError])
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

create_and_pass_TCTI()->
  case xaptum_tpm:tss2_tcti_initialize_socket("localhost", "2321") of
    {ok, TctiContext} ->
      {ok, TctiContext} = get_TCTI(TctiContext),
      {ok, TctiContext};
    {error, RC} -> {error, RC}
  end.

%%====================================================================
%% NIFs
%%====================================================================

get_TCTI(_TctiContext)->
  erlang:nif_error(?LINE).

%%====================================================================
%% Internal functions
%%====================================================================
