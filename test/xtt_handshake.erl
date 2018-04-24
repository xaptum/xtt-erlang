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
-export([test_params/0,
  client_test/0,
  client_TPM_test/0]).

-include_lib("eunit/include/eunit.hrl").
-include("xtt.hrl").

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
    data_dir => example_data_dir()
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

test_handshake(Params)->
  #{port := Port, host := Host} = Params,
  ensure_xtt_server_started(Host, Port),
  Result = xtt_erlang:xtt_client_handshake(Params),
  lager:info("Handshake complete with result ~b!~n", [Result]).

client_test()->
  Params = test_params(),
  lager:info("Staring client test with params ~p~n", [Params]),
  test_handshake(Params).

client_TPM_test()->
  Params = test_paramsTPM(),
  ensure_xtt_server_started(?XTT_SERVER_HOST, ?XTT_SERVER_PORT_TPM),
  lager:info("Staring client test with params ~p~n", [Params]),
  test_handshake(Params).

ensure_xtt_server_started(ServerHost, ServerPort)->
  %% Check if running or
  %% Find xtt install dir and run
  %%os:cmd(?XTT_INSTALL_DIR ++ "/xtt_server " ++ integer_to_list(ServerPort)),
  ok.