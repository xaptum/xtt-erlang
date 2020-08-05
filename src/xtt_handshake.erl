%%%-------------------------------------------------------------------
%%% @author iguberman
%%% @copyright (C) 2018, Xaptum, Inc.
%%% @doc
%%%
%%% @end
%%% Created : 25. Apr 2018 8:57 PM
%%%-------------------------------------------------------------------
-module(xtt_handshake).
-author("iguberman").

-behaviour(gen_server).

-include("xtt.hrl").

%% API
-export([
  xtt_handshake_reg_name/2,
  start_handshake/7,
  handshake_complete/1,
  group_context/4]).

%% gen_server callbacks
-export([init/1,
  handle_call/3,
  handle_cast/2,
  handle_info/2,
  terminate/2,
  code_change/3]).

-define(SERVER, ?MODULE).
-define(TCP_OPTIONS, [binary, {packet, 0}, {keepalive, true}, {active, false}]).

-record(state,
{
  handshake_status,
  xtt_server_host, xtt_server_port, xtt_server_socket,
  requested_client_id, intended_server_id,
  xtt_version = ?XTT_VERSION_ONE,  xtt_suite = ?XTT_X25519_LRSW_ECDSAP256_CHACHA20POLY1305_SHA512,
  group_context,
  handshake_state
}).

%%%===================================================================
%%% API
%%%===================================================================

group_context(Gpk, Credential, Basename, PrivKey) when is_binary(PrivKey); is_tuple(PrivKey)->
  #group_context_inputs{gpk = Gpk, credential = Credential, basename = Basename, priv_key = PrivKey}.

xtt_handshake_reg_name(XttHost, XttPort) when is_integer(XttPort)->
  xtt_handshake_reg_name(XttHost, integer_to_list(XttPort));
xtt_handshake_reg_name( XttHost, XttPort) when is_list(XttPort)->
  list_to_atom(lists:flatten(["XTT_", XttHost, ":", XttPort])).

start_handshake(
    XttServerHost, XttServerPort,
    RequestedClientId, IntendedServerId,
    XttVersion, XttSuite,
    GroupContext) ->
 gen_server:start_link(?MODULE,
      [ XttServerHost, XttServerPort,
        RequestedClientId, IntendedServerId,
        XttVersion, XttSuite,
        GroupContext], []).

handshake_complete(HandshakePid)->
  gen_server:stop(HandshakePid).


%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([XttServerHost, XttServerPort,
  RequestedClientId, IntendedServerId,
  XttVersion, XttSuite,
  GroupContext]) ->
  {ok, XttClientHandshakeState} = xtt_nif:xtt_initialize_client_handshake_context(XttVersion, XttSuite),
  {ok, XttServerSocket} = gen_tcp:connect(XttServerHost, XttServerPort, ?TCP_OPTIONS),
  lager:md([{source, XttServerHost ++ ":" ++ integer_to_list(XttServerPort) ++ "_" ++ binary_to_list(RequestedClientId)}]),
  gen_server:cast(self(), start_handshake),
  {ok, #state{
    handshake_status = initialized,
    xtt_server_host = XttServerHost,
    xtt_server_port = XttServerPort,
    xtt_server_socket = XttServerSocket,
    requested_client_id = RequestedClientId,
    intended_server_id = IntendedServerId,
    xtt_version = XttVersion,
    xtt_suite = XttSuite,
    group_context = GroupContext,
    handshake_state = XttClientHandshakeState
    }}.

handle_call(get_handshake_context, _From, #state{handshake_status=success, handshake_state = HandshakeState} = State) ->
  {reply, {ok, HandshakeState}, State};
handle_call(get_handshake_context, _From, #state{handshake_status=AnythingOtherThanSuccess, handshake_state = HandshakeState} = State) ->
  {reply, {error, {in_progress, AnythingOtherThanSuccess}}, State}.

handle_cast(start_handshake, #state{handshake_state = HandshakeState} = State) ->
  Result = xtt_nif:xtt_start_client_handshake(HandshakeState),
  lager:debug("Result of start_client_handshake ~p", [Result]),
  gen_server:cast(self(), Result),
  {noreply, State#state{handshake_status = starting}};

handle_cast({want_read, BytesRequested},
    #state{xtt_server_socket = Socket, handshake_state = HandshakeState} = State)->
  lager:info("XTT_RETURN_WANT_READ"),
  lager:debug("~b bytes", [BytesRequested]),
  {ok, Bin} = gen_tcp:recv(Socket, BytesRequested),
  Result = xtt_nif:xtt_client_handshake(HandshakeState, 0, Bin),
  gen_server:cast(self(), Result),
  {noreply, State#state{handshake_status = want_read_finished}};

handle_cast({want_write, BinToWrite},
    #state{xtt_server_socket = XttServerSocket, handshake_state = HandshakeState} = State)->
  lager:info("XTT_RETURN_WANT_WRITE"),
  lager:debug("~p bytes", [BinToWrite]),
  ok = gen_tcp:send(XttServerSocket, BinToWrite),
  Result = xtt_nif:xtt_client_handshake(HandshakeState, size(BinToWrite), <<>>),
  gen_server:cast(self(), Result),
  {noreply, State#state{handshake_status = want_write_finished}};


handle_cast({want_preparseserverattest},
    #state{handshake_state = HandshakeState} = State) ->
  lager:info("XTT_RETURN_WANT_PREPARSESERVERATTEST"),
  Result = xtt_nif:xtt_handshake_preparse_serverattest(HandshakeState),
  gen_server:cast(self(), Result),
  {noreply, State#state{handshake_status = preparseserverattest_finished}};

handle_cast({want_buildidclientattest, ClaimedRootId},
    #state{handshake_state = HandshakeState,
      requested_client_id = RequestedClientId,
      intended_server_id = IntendedServerId,
      group_context = GroupContext,
      xtt_version = XttVersion,
      xtt_server_socket = XttServerSocket} = State)->
  lager:info("XTT_RETURN_WANT_BUILDIDCLIENTATTEST claimedRootId ~p", [ClaimedRootId]),
  case xtt_utils:lookup_cert(ClaimedRootId) of
    {ClaimedRootId, ServerCert} ->
        {ok, GroupCtx} = xtt_utils:maybe_init_group_context(GroupContext),
        Result = xtt_nif:xtt_handshake_build_idclientattest(ServerCert, RequestedClientId, IntendedServerId, GroupCtx, HandshakeState),
        gen_server:cast(self(), Result),
        {noreply, State#state{handshake_status = buildidclientattest_finished}};
    {error, Error} ->
      lager:error("Failed to lookup cert context by claimed root id ~p due to error ~p", [ClaimedRootId, Error]),
      ErrorMsg = xtt_nif:xtt_client_build_error_msg_nif(XttVersion),
      ok = gen_tcp:send(XttServerSocket, ErrorMsg),
      {stop, cert_lookup_failure, State#state{handshake_status = cert_lookup_failure}}
  end;

handle_cast({want_parseidserverfinished},
  #state{handshake_state = HandshakeState} = State)->
  lager:info("XTT_RETURN_WANT_PARSEIDSERVERFINISHED"),
  Result = xtt_nif:xtt_handshake_parse_idserverfinished(HandshakeState),
  gen_server:cast(self(), Result),
  {noreply, State#state{handshake_status = parseidserver_finished}};

handle_cast({DefaultError, ErrMsg},
    #state{xtt_server_socket = XttServerSocket} = State)->
  lager:error("Encountered error during client handshake: ~p sending error ~p to server", [DefaultError, ErrMsg]),
  case gen_tcp:send(XttServerSocket, ErrMsg) of
    ok ->
      lager:info("Sent error ~p to server", [ErrMsg]);
    {error, Reason} ->
      lager:error("Filed to send error message ~p to server due to TCP send error ~p", [ErrMsg, Reason])
  end,
  {stop, ?XTT_RETURN_FAILURE, State#state{handshake_status = client_error}};

handle_cast({handshake_finished}, State)->
  lager:info("SUCCESS!"),
  {noreply, State#state{handshake_status = success}};

handle_cast(Unexpected, State)->
  lager:error("Unexpected result during handshake: ~p", [Unexpected]),
  {stop, ?XTT_RETURN_FAILURE, State#state{handshake_status = unexpected_result}}.

handle_info(_Info, State) ->
  {noreply, State}.

terminate(_Reason, #state{handshake_status=success}) ->
  ok;
terminate(_Rason, #state{handshake_status = NotSuccess}) ->
  lager:error("Abnormal termination of handshake during status ~p", [NotSuccess]),
  ok.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

