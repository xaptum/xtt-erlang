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

-include("../include/xtt.hrl").
%% API
-export([start_link/8,
  priv_key/2,
  priv_key/3,
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
  status,
  xtt_server_host, xtt_server_port, xtt_server_socket,
  requested_client_id, intended_server_id,
  xtt_version = ?XTT_VERSION_ONE,  xtt_suite = XTT_X25519_LRSW_ED25519_AES256GCM_SHA512,
  group_context,
  handshake_state
}).

%%%===================================================================
%%% API
%%%===================================================================

priv_key(KeyHandle, TctiContext) when is_integer(KeyHandle)->
  priv_key_info(KeyHandle, _TpmPassword = "", TctiContext).

priv_key(KeyHandle, TpmPassword, TctiContext) when is_integer(KeyHandle), is_list(TpmPassword), is_reference(TctiContext)->
  #priv_key_tpm{key_handle = KeyHandle, tpm_password = TpmPassword, tcti_context = TctiContext};
priv_key(KeyHandle, TpmPassword, {TpmHostname, TpmPort} = _TctiContextCredentials) when is_integer(KeyHandle), is_list(TpmPassword) ->
  {ok, TctiContext} = xaptum_tpm:tss2_tcti_initialize_socket(TpmHostname, TpmPort),
  priv_key(KeyHandle, TpmPassword, TctiContext).

group_context(Gpk, Credential, Basename, PrivKey) when is_binary(PrivKey); is_tuple(PrivKey)->
  #group_context_inputs{gpk = Gpk, credential = Credential, basename = Basename, priv_key = PrivKey}.

start_link(HandshakeId,
    XttServerHost,
    XttServerPort,
    RequestedClientId,
    IntendedServerId,
    XttVersion,
    XttSuite,
    GroupContext) when is_atom(HandshakeId) ->
  gen_server:start_link({local, HandshakeId}, ?MODULE,
    [ XttServerHost, XttServerPort,
      RequestedClientId, IntendedServerId,
      XttVersion, XttSuite,
      GroupContext], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([XttServerHost, XttServerPort,
  RequestedClientId, IntendedServerId,
  XttVersion, XttSuite,
  GroupContext]) ->
  {ok, XttClientHandshakeState} = xtt_erlang:xtt_init_client_handshake_context(XttVersion, XttSuite),
  {ok, XttServerSocket} = gen_tcp:connect(XttServerHost, XttServerPort, ?TCP_OPTIONS),
  gen_server:cast(self(), start_handshake),
  {ok, #state{
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

handle_call(get_handshake_context, _From, #state{handshake_state = HandshakeState} = State) ->
  {reply, {ok, HandshakeState}, State}.

handle_cast(start_handshake, #state{handshake_state = HandshakeState} = State) ->
  Result = xtt_start_client_handshake(HandshakeState),
  lager:info("Result of start_client_handshake ~p", [Result]),
  gen_server:cast(self(), Result),
  {noreply, State};

handle_cast({?XTT_RETURN_WANT_READ, BytesRequested},
    #state{xtt_server_socket = Socket, handshake_state = HandshakeState} = State)->
  lager:info("XTT_RETURN_WANT_READ ~b bytes", [BytesRequested]),
  {ok, Bin} = gen_tcp:recv(Socket, BytesRequested),
  Result = xtt_client_handshake(HandshakeState, 0, Bin),
  gen_server:cast(self(), Result),
  {noreply, State};

handle_cast({?XTT_RETURN_WANT_WRITE, BinToWrite},
    #state{xtt_server_socket = XttServerSocket, handshake_state = HandshakeState} = State)->
  lager:info("XTT_RETURN_WANT_WRITE ~p bytes", [BinToWrite]),
  ok = gen_tcp:send(XttServerSocket, BinToWrite),
  Result = xtt_client_handshake(HandshakeState, size(BinToWrite), <<>>),
  gen_server:cast(self(), Result),
  {noreply, State};


handle_cast({?XTT_RETURN_WANT_PREPARSESERVERATTEST},
    #state{handshake_state = HandshakeState} = State) ->
  lager:info("XTT_RETURN_WANT_PREPARSESERVERATTEST"),
  Result = xtt_handshake_preparse_serverattest(HandshakeState),
  gen_server:cast(self(), Result),
  {noreply, State};

handle_cast({?XTT_RETURN_WANT_BUILDIDCLIENTATTEST, ClaimedRootId},
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
        Result = xtt_handshake_build_idclientattest(ServerCert, RequestedClientId, IntendedServerId, GroupCtx, HandshakeState),
        gen_server:cast(self(), Result),
        {noreply, State};
    {error, Error} ->
      lager:error("Failed to lookup cert context by claimed root id ~p due to error ~p", [ClaimedRootId, Error]),
      ErrorMsg = xtt_erlang:xtt_build_error_msg(XttVersion),
      ok = gen_tcp:send(XttServerSocket, ErrorMsg),
      {stop, cert_lookup_failure, State}
  end;



handle_cast({?XTT_RETURN_WANT_PARSEIDSERVERFINISHED},
  #state{handshake_state = HandshakeState} = State)->
  lager:info("XTT_RETURN_WANT_PARSEIDSERVERFINISHED"),
  Result = xtt_handshake_parse_idserverfinished(HandshakeState),
  gen_server:cast(self(), Result),
  {noreply, State};

handle_cast({?XTT_RETURN_RECEIVED_ERROR_MSG}, State)->
  lager:error("Received error message from server"),
  {stop, ?XTT_RETURN_FAILURE, State};

handle_cast({DefaultError, ErrMsg},
    #state{xtt_server_socket = XttServerSocket} = State)->
  lager:error("Encountered error during client handshake: ~p sending error ~p to server", [DefaultError, ErrMsg]),
  case gen_tcp:send(XttServerSocket, ErrMsg) of
    ok ->
      lager:info("Sent error ~p to server", [ErrMsg]);
    {error, Reason} ->
      lager:error("Filed to send error message ~p to server due to TCP send error ~p", [ErrMsg, Reason])
  end,
  {stop, ?XTT_RETURN_FAILURE, State};

handle_cast({?XTT_RETURN_HANDSHAKE_FINISHED}, State)->
  lager:info("SUCCESS!"),
  {noreply, State};

handle_cast(Unexpected, State)->
  lager:error("Unexpected result during handshake: ~p", [Unexpected]),
  {stop, ?XTT_RETURN_FAILURE, State}.

handle_info(_Info, State) ->
  {noreply, State}.

terminate(_Reason, _State) ->
  ok.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

