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

example_data_file(Filename)->
  filename:join([xtt_erlang:priv_dir(), ?EXAMPLE_DATA_DIR, Filename]).




