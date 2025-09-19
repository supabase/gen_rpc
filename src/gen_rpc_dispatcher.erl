%%% -*-mode:erlang;coding:utf-8;tab-width:4;c-basic-offset:4;indent-tabs-mode:()-*-
%%% ex: set ft=erlang fenc=utf-8 sts=4 ts=4 sw=4 et:
%%%
%%% Copyright 2015 Panagiotis Papadomitsos. All Rights Reserved.
%%%
%%% Dispatcher is a serialization trick to prevent starting up
%%% multiple children for one connection

-module(gen_rpc_dispatcher).

%%% Behaviour
-behaviour(gen_server).

-include("logger.hrl").
-include_lib("snabbkaffe/include/trace.hrl").
%%% Include this library's name macro
-include("app.hrl").
%%% Include helpful guard macros
-include("guards.hrl").
%%% Include helpful guard macros
-include("types.hrl").

%%% Supervisor functions
-export([start_link/1, stop/1]).

%%% Server functions
-export([start_client/1]).

%%% Behaviour callbacks
-export([init/1, handle_call/3, handle_cast/2,
        handle_info/2, terminate/2, code_change/3]).

%%% ===================================================
%%% Public API
%%% ===================================================
-spec start_link(Name :: atom) -> gen_server:start_ret().
start_link(Name) ->
    gen_server:start_link({local,Name}, ?MODULE, [], []).

-spec stop(Name :: atom) -> ok.
stop(Name) ->
    gen_server:stop(Name, normal, infinity).

-spec start_client(node_or_tuple()) -> {ok, pid()} | {error, any()}.
start_client(NodeOrTuple) when ?is_node_or_tuple(NodeOrTuple) ->
    case valid_node(NodeOrTuple) of
        true ->
            Dispatcher = gen_rpc_dispatcher_sup:dispatcher(NodeOrTuple),
            gen_server:call(Dispatcher, {start_client,NodeOrTuple}, infinity);
        false -> {error, {badrpc, badnode}}
    end.

valid_node({Node, _Tag}) when Node =:= node() -> true;
valid_node({Node, _Tag}) -> lists:member(Node, nodes());
valid_node(Node) when Node =:= node() -> true;
valid_node(Node) -> lists:member(Node, nodes()).

%%% ===================================================
%%% Behaviour callbacks
%%% ===================================================
init([]) ->
    ?tp(info, gen_rpc_dispatcher_start, #{}),
    {ok, undefined}.

%% Simply launch a connection to a node through the appropriate
%% supervisor. This is a serialization interface.
handle_call({start_client, NodeOrTuple}, _Caller, undefined) ->
    PidName = {client, NodeOrTuple},
    Reply = case valid_node(NodeOrTuple) of
                false -> {error, {badrpc, badnode}};
                true ->
                    case gen_rpc_registry:whereis_name(PidName) of
                        undefined ->
                            ?tp(debug, gen_rpc_start_client, #{target => NodeOrTuple}),
                            gen_rpc_client_sup:start_child(NodeOrTuple);
                        Pid ->
                            ?tp(debug, gen_rpc_client_already_stated, #{target => NodeOrTuple}),
                            {ok, Pid}
                    end
            end,
    {reply, Reply, undefined};

%% Catch-all for calls - die if we get a message we don't expect
handle_call(Msg, _Caller, undefined) ->
    ?log(error, "event=uknown_call_received message=\"~p\" action=stopping", [Msg]),
    {stop, {unknown_call, Msg}, undefined}.

%% Catch-all for casts - die if we get a message we don't expect
handle_cast(Msg, undefined) ->
    ?log(error, "event=uknown_cast_received message=\"~p\" action=stopping", [Msg]),
    {stop, {unknown_cast, Msg}, undefined}.

%% Catch-all for info - our protocol is strict so die!
handle_info(Msg, undefined) ->
    ?log(error, "event=uknown_message_received message=\"~p\" action=stopping", [Msg]),
    {stop, {unknown_info, Msg}, undefined}.

code_change(_OldVersion, undefined, _Extra) ->
    {ok, undefined}.

terminate(_Reason, undefined) ->
    ok.
