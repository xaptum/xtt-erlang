-module(xtt_erlang).

%% API exports
-export([
  init/0,
  xtt_client_handshake/1,
  xtt_init_client_handshake_context/2,
  xtt_init_client_group_context/4,
  xtt_init_server_root_certificate_context/2,
  xtt_start_client_handshake/1,
  xtt_client_handshake/3,
  xtt_handshake_preparse_serverattest/1,
  xtt_handshake_build_idclientattest/5,
  xtt_handshake_parse_idserverfinished/1,
  xtt_build_error_msg/1]).

-export([priv_dir/0]).

-include("xtt.hrl").

-define(APPNAME, xtt_erlang).
-define(LIBNAME, 'xtt-erlang').

-define(TCP_OPTIONS, [binary, {packet, 2}, {keepalive, true}]).

-define(DEFAULT_ETS_OPTS, [named_table, set, public, {write_concurrency, true}, {read_concurrency, true}]).

-define(CERT_TABLE, cert).

init() ->
  SoName = filename:join([priv_dir(), ?LIBNAME]),
  io:format("Loading NIFs from ~p", [SoName]),
  ok = erlang:load_nif(SoName, 0).

priv_dir() ->
  case code:priv_dir(?APPNAME) of
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

xtt_client_handshake(PropertyFileName) when is_list(PropertyFileName)->
  {ok, PropertiesBin} = file:read_file(PropertyFileName),
  xtt_client_handshake(convert_to_map(PropertiesBin));
xtt_client_handshake(#{ server := ServerName,
                        port := Port,
                        xtt_version := XttVersion,
                        xtt_suite := XttSuite} = ParameterMap) ->

  init(),

  UseTpm = maps:get(use_tpm, ParameterMap, false),
  DataDir = maps:get(data_dir, ParameterMap, "."),

  io:format("Performing client handshake with TPM ~p~n", [UseTpm]),

  {RequestedClientId, IntendedServerId} = initialize_ids(DataDir, ParameterMap),

  io:format("Initialized RequestedClientId to ~p and IntendedServerId to ~p~n", [RequestedClientId, IntendedServerId]),

  GroupContext = initialize_daa(UseTpm, DataDir, ParameterMap),

  io:format("Initialized Group Context ~p~n", [GroupContext]),

  initialize_certs(UseTpm, DataDir, ParameterMap),

  io:format("Initialized Certificates in ~p: ~p~n", [?CERT_TABLE, ets:tab2list(?CERT_TABLE)]),

  XttClientHandshakeStatus = xtt_init_client_handshake_context(XttVersion, XttSuite),

  io:format("Initialized Handshake Context ~p~n", [XttClientHandshakeStatus]),

  io:format("Connecting to ~p:~b.....", [ServerName, Port]),
  {ok, Socket} = gen_tcp:connect(ServerName, Port, ?TCP_OPTIONS),
  io:format("DONE~n"),

  OutputBuffer = do_handshake(Socket, RequestedClientId, IntendedServerId, GroupContext, XttClientHandshakeStatus),

  io:format("do_handshake result: ~p~n", [OutputBuffer]),

  {ok, RespBuffer} = gen_tcp:recv(Socket, 0),
  io:format("Finished client init!  Received buffer ~p from server ~p", [RespBuffer, ServerName]).


%%====================================================================
%% NIFs
%%====================================================================

xtt_init_client_group_context(_Gid, _PrivKey, _Credential, _Basename)->
  erlang:nif_error(?LINE).

xtt_init_server_root_certificate_context(_RootId, _RootPubKey)->
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

xtt_build_error_msg(_XttVersion)->
  erlang:nif_error(?LINE).


%%====================================================================
%% Internal functions
%%====================================================================

convert_to_map(PropertiesBin) when is_binary(PropertiesBin)->
  ok.


initialize_ids(DataDir, ParameterMap)->
  RequestedClientIdFile = maps:get(requested_client_id_file, ParameterMap, filename:join([DataDir, ?REQUESTED_CLIENT_ID_FILE])),
  IntendedServerIdFile = maps:get(server_id_file, ParameterMap, filename:join([DataDir, ?SERVER_ID_FILE])),

  {ok, RequestedClientId} = file:read_file(RequestedClientIdFile),
  %% TODO move check to NIF %% true = lists:member(size(RequestedClientId), [1, ?XTT_IDENTITY_SIZE]),

    {ok, IntendedServerId} = file:read_file(IntendedServerIdFile),

 {RequestedClientId, IntendedServerId}.


initialize_daa(UseTpm, DataDir, ParameterMap) ->
  BasenameFile = maps:get(base_filename, ParameterMap, filename:join([DataDir, ?BASENAME_FILE])),
  {ok, Basename} = file:read_file(BasenameFile),
  io:format("Basename: ~p~n", [Basename]),
  initialize_daa(UseTpm, DataDir, Basename, ParameterMap).

initialize_daa(false = _UseTpm, DataDir, Basename, ParameterMap)->
  GpkFile = maps:get(gpk_filename, ParameterMap, filename:join([DataDir, ?DAA_GPK_FILE])),
  CredFile = maps:get(cred_filename, ParameterMap, filename:join([DataDir, ?DAA_CRED_FILE])),
  PrivKeyFile = maps:get(priv_key_filename, ParameterMap, filename:join([DataDir, ?DAA_SECRETKEY_FILE])),

  {ok, Gpk} = file:read_file(GpkFile),

  {ok, Credential} = file:read_file(CredFile),

  {ok, PrivKey} = file:read_file(PrivKeyFile),

  initialize_client_group_context(Gpk, PrivKey, Credential, Basename);
initialize_daa(true = _UseTpm, _DataDir, Basename, _ParameterMap)->
  {ok, Gpk} = read_nvram(gpk),
  {ok, Credential} = read_nvram(cred),
  {ok, PrivKey} = read_nvram(priv_key),

  initialize_client_group_context(Gpk, PrivKey, Credential, Basename).

initialize_client_group_context(Gpk, PrivKey, Credential, Basename)->
  Gid = crypto:hash(sha256, Gpk),
  io:format("STARTing xtt_initialize_client_group_context(~p, ~p, ~p, ~p)~n",
    [print_bin(Gid), print_bin(PrivKey), print_bin(Credential), Basename]),
  GroupCtx = xtt_init_client_group_context(Gid,PrivKey,Credential, Basename),
  io:format("Resulting GroupCtx: ~p~n", [GroupCtx]),
  GroupCtx.

print_bin(Bin) when size(Bin) > 5->
  ?PRINT_BIN(Bin);
print_bin(Bin) ->
  Bin.

initialize_certs(false = _UseTpm, DataDir, ParameterMap)->
  RootIdFilename = maps:get(root_id_filename, ParameterMap, filename:join(DataDir, ?ROOT_ID_FILE)),
  RootPubkeyFilename = maps:get(root_pubkey_filename, ParameterMap, filename:join(DataDir, ?ROOT_PUBKEY_FILE)),

  io:format("Getting RootId from  ~p and RootPubKey from ~p~n", [RootIdFilename, RootPubkeyFilename]),

  {ok, RootId} = file:read_file(RootIdFilename),
  {ok, RootPubKey} = file:read_file(RootPubkeyFilename),

  io:format("Initializing cert db with RootId ~p and RootPubKey ~p~n", [RootId, print_bin(RootPubKey)]),

  init_cert_db(RootId, RootPubKey);
initialize_certs(true = _UseTpm, _DataDir, ParameterMap)->
  RootId = read_nvram(root_id),
  RootPubKey = read_nvram(root_pub_key),
  init_cert_db(RootId, RootPubKey).

init_cert_db(RootId, RootPubkey)->
  CertContext = xtt_init_server_root_certificate_context(RootId, RootPubkey),
  ets:new(?CERT_TABLE, ?DEFAULT_ETS_OPTS),
  ets:insert(?CERT_TABLE, {RootId, CertContext}). %% TODO DB: Should replace file reading stuff with write ets to disk?

%% Should be NIF(s)
read_nvram(root_id)-> todo;
read_nvram(root_pub_key)->todo;
read_nvram(gpk)->todo;
read_nvram(cred)-> todo;
read_nvram(priv_key)->todo.

do_handshake(Socket, RequestedClientId, IntendedServerId, GroupCtx, HandshakeState)->
  Result = xtt_start_client_handshake(HandshakeState),
  handshake_advance(Socket, RequestedClientId, IntendedServerId, GroupCtx, Result).

handshake_advance(Socket,  _RequestedClientId, _IntendedServerId, _GroupCtx,
    {?XTT_RETURN_WANT_READ, BytesRequested, HandshakeState})->
  io:format("handshake WANT_READ ~b bytes~n", [BytesRequested]),
  case gen_tcp:recv(Socket, BytesRequested) of
    {ok, Bin} ->
      io:format("Read ~p~n", [Bin]),
      Result = xtt_client_handshake(HandshakeState, 0, Bin),
      handshake_advance(Socket, _RequestedClientId, _IntendedServerId, _GroupCtx, Result);
    {error, Reason} ->
      io:format("FAILED: Handshake TCP receive error ~p (BytesRequested: ~p)~n", [Reason, BytesRequested])
  end;
handshake_advance(Socket, _RequestedClientId, _IntendedServerId, _GroupCtx,
    {?XTT_RETURN_WANT_WRITE, BinToWrite, HandshakeState})->
  io:format("Handshake WANT_WRITE ~p~n", [BinToWrite]),
  case gen_tcp:send(Socket, BinToWrite) of
    ok ->
      io:format("Write SUCCESS!~n"),
      Result = xtt_client_handshake(HandshakeState, size(BinToWrite), <<>>),
      handshake_advance(Socket, _RequestedClientId, _IntendedServerId, _GroupCtx, Result);
    {error, Reason} ->
      io:format("FAILED: Handshake TCP send error ~p (BinToWrite ~p) ~n", [Reason, BinToWrite])
  end;
handshake_advance(Socket,  RequestedClientId, IntendedServerId, GroupCtx,
    {?XTT_RETURN_WANT_PREPARSESERVERATTEST, HandshakeState})->
  Result = xtt_handshake_preparse_serverattest(HandshakeState),
  handshake_advance(Socket, RequestedClientId, IntendedServerId, GroupCtx, Result);
handshake_advance(Socket,  RequestedClientId, IntendedServerId, GroupCtx,
    {?XTT_RETURN_WANT_BUILDIDCLIENTATTEST, ClaimedRootId, HandshakeState})->
    io:format("Looking up server's certificate from its claimed root_id ~p~n", [ClaimedRootId]),
    ServerCert = lookup_cert(ClaimedRootId),
    Result = xtt_handshake_build_idclientattest(ServerCert, RequestedClientId, IntendedServerId, GroupCtx, HandshakeState),
    handshake_advance(Socket, RequestedClientId, ClaimedRootId, GroupCtx, Result);
handshake_advance(Socket, RequestedClientId, IntendedServerId, GroupCtx,
    {?XTT_RETURN_WANT_PARSEIDSERVERFINISHED, HandshakeState})->
    Result = xtt_handshake_parse_idserverfinished(HandshakeState),
    handshake_advance(Socket, RequestedClientId, IntendedServerId, GroupCtx, Result);
handshake_advance(_Socket, _RequestedClientId, _IntendedServerId, _GroupCtx,
    {?XTT_RETURN_HANDSHAKE_FINISHED, _HandshakeState})->
  io:format("Handshake complete!~n");
handshake_advance(_Socket, _RequestedClientId, _IntendedServerId, _GroupCtx,
    {?XTT_RETURN_RECEIVED_ERROR_MSG, _HandshakeState})->
  io:format("Received error message from server~n");
handshake_advance(_Socket, _RequestedClientId, _IntendedServerId, _GroupCtx,
    DefaultErrorResult)->
  io:format("Encountered error during client handshake: ~p~n", [DefaultErrorResult]).
  %% TODO (void)write(socket, io_ptr, bytes_requested) need a NIF just to get that buffer?

lookup_cert(ClaimedRootId)->
  case ets:lookup(?CERT_TABLE, ClaimedRootId) of
    [CertCtx] -> CertCtx;
    [] -> %% TODO TEMP HACK
      RootId = ets:last(?CERT_TABLE),  %% TODO verify ClaimedRootId with
%%int cmp_ret = xtt_crypto_memcmp(certificate_db[i].root_id.data,   %%%% NEED TO UPDATE enacl to have this NIF
%%claimed_root_id->data,
%%sizeof(xtt_certificate_root_id));
%% IF not verified call xtt_build_error_msg NIF and send to server
      case ets:lookup(?CERT_TABLE, RootId) of
        [CertCtx] -> CertCtx;
        _Other -> io:format("ERROR: cert table is empty!~n")
      end
  end.
