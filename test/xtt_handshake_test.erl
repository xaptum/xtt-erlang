%%%-------------------------------------------------------------------
%%% @author iguberman
%%% @copyright (C) 2018, Xaptum, Inc.
%%% @doc
%%%
%%% @end
%%% Created : 19. Mar 2018 7:11 PM
%%%-------------------------------------------------------------------
-module(xtt_handshake_test).
-author("iguberman").

%% API
-export([]).

-include_lib("eunit/include/eunit.hrl").
-include("xtt.hrl").

%% Defaults
-define(XTT_VERSION, ?XTT_VERSION_ONE).
-define(XTT_SUITE, ?XTT_X25519_LRSW_ED25519_AES256GCM_SHA512).
-define(EXAMPLE_DATA_DIR, "example_data").

-define(XTT_SERVER_PORT, 4445).
-define(XTT_SERVER_HOST, "localhost").


example_data_file(Filename)->
  filename:join([xtt_erlang:priv_dir(), ?EXAMPLE_DATA_DIR, Filename]).

handshake_test()->
  ensure_xtt_server_started(?XTT_SERVER_HOST, ?XTT_SERVER_PORT),
  Params = #{
    server => ?XTT_SERVER_HOST,
    port => ?XTT_SERVER_PORT,
    xtt_version => ?XTT_VERSION_ONE,
    xtt_suite  => ?XTT_X25519_LRSW_ED25519_AES256GCM_SHA512},
  xtt_erlang:xtt_client_handshake(Params).

ensure_xtt_server_started(ServerHost, ServerPort)->
  %% Check if running or
  %% Find xtt install dir and run
  %%os:cmd(?XTT_INSTALL_DIR ++ "/xtt_server " ++ integer_to_list(ServerPort)),
  ok.





