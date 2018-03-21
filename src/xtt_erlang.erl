-module(xtt_erlang).

%% API exports
-export([
  init/0,
  xtt_client_handshake/1,
  xtt_client_handshake_context/2,
  xtt_initialize_client_group_context/4,
  xtt_initialize_server_root_certificate_context/2,
  xtt_build_client_init/1,
  xtt_build_error_msg/0]).

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

  XttHandshakeContext = xtt_client_handshake_context(XttVersion, XttSuite),

  io:format("Initialized Handshake Context ~p~n", [XttHandshakeContext]),

  io:format("Connecting to ~p:~b.....", [ServerName, Port]),
  {ok, Socket} = gen_tcp:connect(ServerName, Port, ?TCP_OPTIONS),
  io:format("DONE~n"),

  OutputBuffer = do_handshake(Socket, RequestedClientId, IntendedServerId, GroupContext, XttHandshakeContext),

  io:format("do_handshake result: ~p~n", [OutputBuffer]),

  {ok, RespBuffer} = gen_tcp:recv(Socket, 0),
  io:format("Finished client init!  Received buffer ~p from server ~p", [RespBuffer, ServerName]).


%%====================================================================
%% NIFs
%%====================================================================

xtt_client_handshake_context(_XttVersion, _XttSuite)->
  erlang:nif_error(?LINE).

xtt_initialize_client_group_context(_Gid, _PrivKey, _Credential, _Basename)->
  erlang:nif_error(?LINE).

xtt_initialize_server_root_certificate_context(_RootId, _RootPubKey)->
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
  io:format("STARTing xtt_initialize_client_group_context(~p, ~p, ~p, ~p)~n", [binary:part(Gid, {0, 5}),binary:part(PrivKey, {0, 5}),Credential, Basename]),
  GroupCtx = xtt_initialize_client_group_context(Gid,PrivKey,Credential, Basename),
  io:format("GroupCtx: ~p~n", [GroupCtx]),
  GroupCtx.

initialize_certs(false = _UseTpm, DataDir, ParameterMap)->
  RootIdFilename = maps:get(root_id_filename, ParameterMap, filename:join(DataDir, ?ROOT_ID_FILE)),
  RootPubkeyFilename = maps:get(root_pubkey_filename, ParameterMap, filename:join(DataDir, ?ROOT_PUBKEY_FILE)),

  {ok, RootId} = file:read_file(RootIdFilename),
  {ok, RootPubKey} = file:read_file(RootPubkeyFilename),

  init_cert_db(RootId, RootPubKey);
initialize_certs(true = _UseTpm, _DataDir, ParameterMap)->
  RootId = read_nvram(root_id),
  RootPubKey = read_nvram(root_pub_key),
  init_cert_db(RootId, RootPubKey).

init_cert_db(RootId, RootPubkey)->
  CertContext = xtt_initialize_server_root_certificate_context(RootId, RootPubkey),
  ets:new(?CERT_TABLE, ?DEFAULT_ETS_OPTS),
  ets:insert(?CERT_TABLE, RootId, CertContext). %% TODO DB: Should replace file reading stuff with write ets to disk?

%% Should be NIF(s)
read_nvram(root_id)-> todo;
read_nvram(root_pub_key)->todo;
read_nvram(gpk)->todo;
read_nvram(cred)-> todo;
read_nvram(priv_key)->todo.

do_handshake(Socket, RequestedClientId, IntendedServerId, GroupCtx, XttClientHandshakeCtx)->
  ok.
