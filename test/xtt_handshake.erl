%%%-------------------------------------------------------------------
%%% @author iguberman
%%% @copyright (C) 2018, Xaptum, Inc.
%%% @doc
%%%
%%% @end
%%% Created : 19. Mar 2018 7:11 PM
%%%-------------------------------------------------------------------
-module(xtt_handshake).
-author("iguberman").

%% API
-export([tcti_test/0]).

-include_lib("eunit/include/eunit.hrl").
-include("xtt.hrl").

-define(XTT_SERVER_PORT, 4445).
-define(XTT_SERVER_HOST, "localhost").

tcti_test()->
  {ok, _TctiContext} = xtt_erlang:create_and_pass_TCTI().




