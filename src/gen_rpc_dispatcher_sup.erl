%%% -*-mode:erlang;coding:utf-8;tab-width:4;c-basic-offset:4;indent-tabs-mode:()-*-
%%% ex: set ft=erlang fenc=utf-8 sts=4 ts=4 sw=4 et:
%%%

-module(gen_rpc_dispatcher_sup).

%%% Behaviour
-behaviour(supervisor).

-include_lib("snabbkaffe/include/trace.hrl").

%%% Include helpful guard macros
-include("types.hrl").

%%% Supervisor functions
-export([start_link/0]).

%%% Supervisor callbacks
-export([init/1]).

%%% Dispatcher function
-export([dispatcher/1]).

-spec dispatcher(node_or_tuple()) -> atom().
dispatcher(NodeOrTuple) ->
    Names = persistent_term:get(?MODULE),
    element(erlang:phash2(NodeOrTuple, tuple_size(Names)) + 1, Names).

%%% ===================================================
%%% Supervisor functions
%%% ===================================================
-spec start_link() -> supervisor:startlink_ret().
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%%% ===================================================
%%% Supervisor callbacks
%%% ===================================================
-spec init([]) -> {ok, {{supervisor:strategy(), non_neg_integer(), pos_integer()}, [supervisor:child_spec()]}}.
init([]) ->
    Names = [list_to_atom("gen_rpc_dispatcher_" ++ integer_to_list(Number)) || Number <- lists:seq(1, dispatchers_size())],
    Children = [dispatcher_child_spec(Name) || Name <- Names],
     persistent_term:put(?MODULE, list_to_tuple(Names)),
    {ok, {{one_for_one, 10, 10}, Children}}.

-spec dispatcher_child_spec(Name :: atom()) -> supervisor:child_spec().
dispatcher_child_spec(Name) ->
    #{
        id => {gen_rpc_dispatcher, Name},
        start => {gen_rpc_dispatcher, start_link, [Name]},
        type => worker,
        shutdown => 10000,
        restart => permanent,
        modules => [gen_rpc_dispatcher]
    }.

-spec dispatchers_size() -> pos_integer().
dispatchers_size() ->
    Dispatchers = application:get_env(gen_rpc, dispatcher_pool_size, 10),
    if is_integer(Dispatchers), Dispatchers > 0 -> Dispatchers;
       true -> erlang:error({bad_config, {dispatchers_size, Dispatchers}})
    end.
