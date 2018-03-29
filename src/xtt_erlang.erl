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

-define(TCP_OPTIONS, [binary, {packet, 0}, {keepalive, true}, {active, false}]).

-define(DEFAULT_ETS_OPTS, [named_table, set, public, {write_concurrency, true}, {read_concurrency, true}]).

-define(CERT_TABLE, cert).

init() ->
  SoName = filename:join([priv_dir(), ?LIBNAME]),
  lager:info("Loading NIFs from ~p", [SoName]),
  application:ensure_all_started(lager),
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

  lager:info("Performing client handshake with TPM ~p", [UseTpm]),

  {RequestedClientId, IntendedServerId} = initialize_ids(DataDir, ParameterMap),

  lager:info("Initialized RequestedClientId to ~p and IntendedServerId to ~p", [RequestedClientId, IntendedServerId]),

  GroupContext = initialize_daa(UseTpm, DataDir, ParameterMap),

  lager:info("Initialized Group Context ~p", [GroupContext]),

  initialize_certs(UseTpm, DataDir, ParameterMap),

  lager:info("Initialized Certificates in ~p: ~p", [?CERT_TABLE, ets:tab2list(?CERT_TABLE)]),

  XttClientHandshakeStatus = xtt_init_client_handshake_context(XttVersion, XttSuite),

  lager:info("Initialized Handshake Context ~p", [XttClientHandshakeStatus]),

  lager:info("Connecting to ~p:~b.....", [ServerName, Port]),
  {ok, Socket} = gen_tcp:connect(ServerName, Port, ?TCP_OPTIONS),
  lager:info("DONE"),

  RC = do_handshake(Socket, RequestedClientId, IntendedServerId, GroupContext, XttClientHandshakeStatus),

  lager:info("do_handshake result: ~p", [RC]),

  RC.
%%
%%  {ok, RespBuffer} = gen_tcp:recv(Socket, 0),
%%  lager:info("Finished client init!  Received buffer ~p from server ~p", [RespBuffer, ServerName]).


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

  RequestedClientId =
  case file:read_file(RequestedClientIdFile) of
    {ok, ?XTT_REQUEST_ID_FROM_SERVER} -> ?XTT_NULL_IDENTITY;
    {ok, ClientId} when size(ClientId) =/= ?XTT_IDENTITY_SIZE ->
      lager:error("Invalid requested client id ~p of size ~b while expecting size ~b in file ~p",
        [ClientId, size(ClientId), ?XTT_IDENTITY_SIZE, ?REQUESTED_CLIENT_ID_FILE]),
      false = true;
    {ok, ClientId} when size(ClientId) =:= ?XTT_IDENTITY_SIZE -> ClientId
  end,

  {ok, IntendedServerId} = file:read_file(IntendedServerIdFile),

 {RequestedClientId, IntendedServerId}.


initialize_daa(UseTpm, DataDir, ParameterMap) ->
  BasenameFile = maps:get(base_filename, ParameterMap, filename:join([DataDir, ?BASENAME_FILE])),
  {ok, Basename} = file:read_file(BasenameFile),
  lager:info("Basename: ~p", [Basename]),
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
  %%Gid = crypto:hash(sha256, Gpk),
  lager:info("STARTing xtt_initialize_client_group_context(~p, ~p, ~p, ~p)",
    [print_bin(Gpk), print_bin(PrivKey), print_bin(Credential), Basename]),
  GroupCtx = xtt_init_client_group_context(Gpk,PrivKey,Credential, Basename),
  lager:info("Resulting GroupCtx: ~p", [GroupCtx]),
  GroupCtx.

print_bin(Bin) when size(Bin) > 5->
  ?PRINT_BIN(Bin);
print_bin(Bin) ->
  Bin.

initialize_certs(false = _UseTpm, DataDir, ParameterMap)->
  RootIdFilename = maps:get(root_id_filename, ParameterMap, filename:join(DataDir, ?ROOT_ID_FILE)),
  RootPubkeyFilename = maps:get(root_pubkey_filename, ParameterMap, filename:join(DataDir, ?ROOT_PUBKEY_FILE)),

  lager:info("Getting RootId from  ~p and RootPubKey from ~p", [RootIdFilename, RootPubkeyFilename]),

  {ok, RootId} = file:read_file(RootIdFilename),
  {ok, RootPubKey} = file:read_file(RootPubkeyFilename),

  lager:info("Initializing cert db with RootId ~p and RootPubKey ~p", [RootId, print_bin(RootPubKey)]),

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
  lager:info("Result of start_client_handshake ~p", [Result]),
  handshake_advance(Socket, RequestedClientId, IntendedServerId, GroupCtx, Result).

handshake_advance(Socket,  _RequestedClientId, _IntendedServerId, _GroupCtx,
    {?XTT_RETURN_WANT_READ, BytesRequested, HandshakeState})->
  lager:info("handshake_advance at XTT_RETURN_WANT_READ ~b bytes", [BytesRequested]),
  case gen_tcp:recv(Socket, BytesRequested) of
    {ok, Bin} ->
      lager:info("Read ~p", [Bin]),
      Result = xtt_client_handshake(HandshakeState, 0, Bin),
      handshake_advance(Socket, _RequestedClientId, _IntendedServerId, _GroupCtx, Result);
    {error, Reason} ->
      lager:error("Handshake TCP receive error ~p (BytesRequested: ~p)", [Reason, BytesRequested])
  end;
handshake_advance(Socket, _RequestedClientId, _IntendedServerId, _GroupCtx,
    {?XTT_RETURN_WANT_WRITE, BinToWrite, HandshakeState})->
  lager:info("handshake_advance at XTT_RETURN_WANT_WRITE ~p", [BinToWrite]),
  case gen_tcp:send(Socket, BinToWrite) of
    ok ->
      lager:info("Write SUCCESS!"),
      Result = xtt_client_handshake(HandshakeState, size(BinToWrite), <<>>),
      handshake_advance(Socket, _RequestedClientId, _IntendedServerId, _GroupCtx, Result);
    {error, Reason} ->
      lager:error("Handshake TCP send error ~p (BinToWrite ~p) ", [Reason, BinToWrite])
  end;
handshake_advance(Socket,  RequestedClientId, IntendedServerId, GroupCtx,
    {?XTT_RETURN_WANT_PREPARSESERVERATTEST, HandshakeState})->
  lager:info("handshake_advance at XTT_RETURN_WANT_PREPARSESERVERATTEST"),
  Result = xtt_handshake_preparse_serverattest(HandshakeState),
  handshake_advance(Socket, RequestedClientId, IntendedServerId, GroupCtx, Result);
handshake_advance(Socket,  RequestedClientId, IntendedServerId, GroupCtx,
    {?XTT_RETURN_WANT_BUILDIDCLIENTATTEST, ClaimedRootId, HandshakeState})->
    lager:info("handshake_advance at XTT_RETURN_WANT_BUILDIDCLIENTATTEST"),
    lager:info("Looking up server's certificate from its claimed root_id ~p", [ClaimedRootId]),
    {ClaimedRootId, ServerCert} = lookup_cert(ClaimedRootId),
    lager:info("Running xtt_handshake_build_idclientattest(~p, ~p, ~p, ~p, ~p)", [ServerCert, RequestedClientId, IntendedServerId, GroupCtx, HandshakeState]),
    Result = xtt_handshake_build_idclientattest(ServerCert, RequestedClientId, IntendedServerId, GroupCtx, HandshakeState),
    handshake_advance(Socket, RequestedClientId, ClaimedRootId, GroupCtx, Result);
handshake_advance(Socket, RequestedClientId, IntendedServerId, GroupCtx,
    {?XTT_RETURN_WANT_PARSEIDSERVERFINISHED, HandshakeState})->
    lager:info("handshake_advance at XTT_RETURN_WANT_PARSEIDSERVERFINISHED"),
    Result = xtt_handshake_parse_idserverfinished(HandshakeState),
    handshake_advance(Socket, RequestedClientId, IntendedServerId, GroupCtx, Result);
handshake_advance(_Socket, _RequestedClientId, _IntendedServerId, _GroupCtx,
    {?XTT_RETURN_HANDSHAKE_FINISHED, _HandshakeState})->
  lager:info("Handshake FINISHED!"),
  ?XTT_RETURN_SUCCESS;
handshake_advance(_Socket, _RequestedClientId, _IntendedServerId, _GroupCtx,
    {?XTT_RETURN_RECEIVED_ERROR_MSG, _HandshakeState})->
  lager:error("Received error message from server"),
  ?XTT_RETURN_RECEIVED_ERROR_MSG;
handshake_advance(Socket, _RequestedClientId, _IntendedServerId, _GroupCtx,
    {DefaultError, ErrToSend, _HandshakeState})->
  lager:error("Encountered error during client handshake: ~p sending error ~p to server", [DefaultError, ErrToSend]),
  case gen_tcp:send(Socket, ErrToSend) of
    ok ->
      lager:info("Sent error ~p to server", [ErrToSend]);
    {error, Reason} ->
      lager:error("Filed to send error message ~p to server due to TCP send error ~p", [ErrToSend, Reason])
  end,
  ?XTT_RETURN_FAILURE.

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
        _Other -> lager:error("ERROR: cert table is empty!")
      end
  end.
