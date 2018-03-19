-module('xtt-erlang').

%% API exports
-export([xtt_client_handshake/1,
  xtt_client_handshake_context/2,
  xtt_build_client_init/1,
  xtt_build_error_msg/0]).

%% TODO temp -- read from config
-define(XTT_VERSION, 1).
-define(XTT_SUITE, 3).

-define(TCP_OPTIONS, [binary, {packet, 2}, {keepalive, true}]).

%%====================================================================
%% API functions
%%====================================================================

xtt_client_handshake(PropertyFileName) when is_list(PropertyFileName)->
  {ok, PropertiesBin} = file:read_file(PropertyFileName),
  xtt_client_handshake(convert_to_map(PropertiesBin));
xtt_client_handshake(#{ server := ServerName, port := Port,
                        xtt_version := _XttVersion, xtt_suite := _XttSuite} = _ParameterMap) ->
  {ok, Socket} = gen_tcp:connect(ServerName, Port, ?TCP_OPTIONS),
  XttHandshakeContext = xtt_client_handshake_context(?XTT_VERSION, ?XTT_SUITE),
  OutputBuffer = xtt_build_client_init(XttHandshakeContext),
  gen_tcp:send(Socket, OutputBuffer),
  {ok, RespBuffer} = gen_tcp:recv(Socket, 0),
  io:format("Finished client init!  Received buffer ~p from server ~p", [RespBuffer, ServerName]).


%%====================================================================
%% NIFs
%%====================================================================

xtt_client_handshake_context(_XttVersion, _XttSuite)->
  erlang:nif_error(?LINE).

xtt_build_client_init(_XttClientHandshakeContext)->
  erlang:nif_error(?LINE).

xtt_build_error_msg()->
  erlang:nif_error(?LINE).
%%====================================================================
%% Internal functions
%%====================================================================

convert_to_map(PropertiesBin) when is_binary(PropertiesBin)->
  ok.

