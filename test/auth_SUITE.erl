%%--------------------------------------------------------------------
%% Copyright (c) 2022-2023 EMQ Technologies Co., Ltd. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-module(auth_SUITE).

%%% CT Macros
-include_lib("test/include/ct.hrl").
-include_lib("snabbkaffe/include/snabbkaffe.hrl").
-include_lib("stdlib/include/assert.hrl").

%%% No need to export anything, everything is automatically exported
%%% as part of the test profile

%%% ===================================================
%%% CT callback functions
%%% ===================================================
all() ->
    [{group, tcp}, {group, ssl}].

suite() ->
    [{timetrap, {minutes, 1}}].

groups() ->
    {Compat, Regular} =
        lists:foldl(
          fun({Fun, _Arity}, {Comp, Reg}) ->
                  case atom_to_list(Fun) of
                      "t_compat_" ++ _ -> {[Fun|Comp], Reg};
                      "t_"        ++ _ -> {Comp, [Fun|Reg]};
                      _                -> {Comp, Reg}
                  end
          end,
          {[], []},
          ?MODULE:module_info(exports)),
    CompatGroups = [{'compat-suite-2.8.2', [], Compat}, {'compat-suite-3.0.1', [], Compat}],
    [{tcp, [], Regular ++ CompatGroups}, {ssl, [], Regular ++ CompatGroups}].

init_per_suite(Config) ->
    %% Build old versions of gen_rpc to test backward/forward compatibility:
    Config.

end_per_suite(Config) ->
    Config.

init_per_group(Group, Config) when Group =:= tcp; Group =:= ssl ->
    % Our group name is the name of the driver
    Driver = Group,
    %% Starting Distributed Erlang on local node
    {ok, _Pid} = gen_rpc_test_helper:start_distribution(?MASTER),
    %% Save the driver in the state
    gen_rpc_test_helper:store_driver_in_config(Driver, Config);
init_per_group(CompatGroupTag, Config) ->
    Dir = build_old_rel(CompatGroupTag, Config),
    [{old_rel_dir, Dir}, {old_tag, CompatGroupTag} | Config].

end_per_group(_Driver, Config) ->
    Config.

init_per_testcase(Testcase, Config) ->
    snabbkaffe:fix_ct_logging(),
    logger:notice("Running ~p", [Testcase]),
    application:load(?APP),
    PrevEnv = application:get_all_env(?APP),
    %% Save environment variables, so they can be restored later:
    [{prev_env, PrevEnv}|Config].

end_per_testcase(_Testcase, Config) ->
    %% Restore environment variables:
    ok = gen_rpc_test_helper:stop_slave(),
    ok = application:stop(?APP),
    snabbkaffe:stop(),
    meck:unload(),
    %% Reset application env:
    OldEnv = proplists:get_value(prev_env, Config),
    lists:foreach(fun({K, V}) -> application:set_env(?APP, K, V) end, OldEnv),
    NewKeys = proplists:get_keys(application:get_all_env(?APP)) --
         proplists:get_keys(OldEnv),
    lists:foreach(fun(K) -> application:unset_env(?APP, K) end, NewKeys),
    ok.

%%% ===================================================
%%% Test cases
%%% ===================================================
%% Test main functions

%% Check normal flow:
t_challenge_response_ok(Config) ->
    Driver = gen_rpc_test_helper:get_driver_from_config(Config),
    ?check_trace(
       #{timetrap => 5000},
       begin
           ok = gen_rpc_test_helper:start_master(Driver),
           ok = gen_rpc_test_helper:start_slave(Driver),
           ?assertMatch(?SLAVE, gen_rpc:call(?SLAVE, erlang, node, [])),
           ?assertMatch(?SLAVE, gen_rpc:call({?SLAVE, destination}, erlang, node, []))
       end,
       fun(Trace) ->
               ?assertMatch([], ?of_kind(gen_rpc_insecure_fallback, Trace)),
               Stages = ?of_kind(gen_rpc_authentication_stage, Trace),
               ?assertMatch([1, 2, 3, 4, 1, 2, 3, 4], ?projection(stage, Stages))
       end).

%% In this testcase we don't test auth, but the rest of the gen_rpc library.
%%
%% We mock authentication to always fail and verify that it prevents access.
t_auth_server_fail(Config) ->
    Driver = gen_rpc_test_helper:get_driver_from_config(Config),
    ?check_trace(
       #{timetrap => 5000},
       begin
           meck:new(gen_rpc_auth, [passthrough]),
           meck:expect(gen_rpc_auth, connect_with_auth,
                       fun(_Driver, _Node, _Port) ->
                               {error, {badrpc, invalid_cookie}}
                       end),
           ok = gen_rpc_test_helper:start_master(Driver),
           ok = gen_rpc_test_helper:start_slave(Driver),
           ?assertMatch({badrpc, invalid_cookie}, gen_rpc:call(?SLAVE, ?MODULE, canary, []))
       end,
       [ fun ?MODULE:prop_canary/1
       ]).

%% In this testcase we don't test auth, but the rest of the gen_rpc library.
%%
%% We mock authentication to always fail and verify that it prevents access.
t_auth_client_fail(Config) ->
    Driver = gen_rpc_test_helper:get_driver_from_config(Config),
    ?check_trace(
       #{timetrap => 5000},
       begin
           meck:new(gen_rpc_auth, [passthrough]),
           meck:expect(gen_rpc_auth, authenticate_client,
                       fun(_Driver, _Socket, _Peer) ->
                               {error, {badrpc, invalid_cookie}}
                       end),
           ok = gen_rpc_test_helper:start_master(Driver),
           ok = gen_rpc_test_helper:start_slave(Driver),
           Node = node(),
           ?assertNotMatch(canary_is_dead,
                           erpc:call(?SLAVE,
                                     fun() ->
                                             gen_rpc:call(Node, ?MODULE, canary, [])
                                     end))
       end,
       [ fun ?MODULE:prop_canary/1
       ]).

%% The client has invalid cookie:
t_challenge_response_invalid_cookie_client(Config) ->
    Driver = gen_rpc_test_helper:get_driver_from_config(Config),
    ?check_trace(
       #{timetrap => 5000},
       try
           application:set_env(?APP, secret_cookie, <<"wrong">>),
           ok = gen_rpc_test_helper:start_master(Driver),
           ok = gen_rpc_test_helper:start_slave(Driver),
           ?assertMatch({badrpc, invalid_cookie}, gen_rpc:call(?SLAVE, ?MODULE, canary, []))
       after
           application:unset_env(?APP, secret_cookie)
       end,
       [ fun ?MODULE:prop_canary/1
       , fun ?MODULE:prop_no_fallback/1
       ]).

%% The server has invalid cookie:
t_challenge_response_invalid_cookie_server(Config) ->
    Driver = gen_rpc_test_helper:get_driver_from_config(Config),
    ?check_trace(
       #{timetrap => 5000},
       begin
           ok = gen_rpc_test_helper:start_master(Driver),
           ok = gen_rpc_test_helper:start_slave(Driver),
           erpc:call(?SLAVE,
                     fun() ->
                             application:set_env(?APP, secret_cookie, <<"wrong">>)
                     end),
           ?assertMatch({badrpc, invalid_cookie},
                        gen_rpc:call(?SLAVE, ?MODULE, canary, []))
       end,
       [ fun ?MODULE:prop_canary/1
       , fun ?MODULE:prop_no_fallback/1
       ]).

%% Invalid client port mapping configuration that points to the wrong node:
t_cr_invalid_server(Config) ->
    application:set_env(?APP, port_discovery, manual),
    Driver = gen_rpc_test_helper:get_driver_from_config(Config),
    ?check_trace(
       #{timetrap => 5000},
       begin
           ok = gen_rpc_test_helper:start_master(Driver),
           ok = gen_rpc_test_helper:start_slave(Driver),
           ?assertMatch({badrpc, badnode},
                        gen_rpc:call(?BAD_NODE, ?MODULE, canary, [])),
           %% Check with destination:
           ?assertMatch({badrpc, badnode},
                        gen_rpc:call({?BAD_NODE, foo}, ?MODULE, canary, []))
       end,
       [ fun ?MODULE:prop_canary/1
       , fun ?MODULE:prop_no_fallback/1
       ]).

%% Compatibility (happy case)
t_compat_old_server_ok(Config) ->
    Driver = gen_rpc_test_helper:get_driver_from_config(Config),
    application:set_env(?APP, insecure_auth_fallback_allowed, true),
    ?check_trace(
       #{timetrap => 5000},
       begin
           ok = gen_rpc_test_helper:start_master(Driver),
           ok = gen_rpc_test_helper:start_slave(Driver, old_path(Config)),
           ?assertMatch(?SLAVE, gen_rpc:call(?SLAVE, erlang, node, [])),
           Config
       end,
       [fun ?MODULE:prop_fallback/2]).

%% Compatibility (happy case)
t_compat_old_client_ok(Config) ->
    Driver = gen_rpc_test_helper:get_driver_from_config(Config),
    application:set_env(?APP, insecure_auth_fallback_allowed, true),
    ?check_trace(
       #{timetrap => 5000},
       begin
           ok = gen_rpc_test_helper:start_master(Driver),
           ok = gen_rpc_test_helper:start_slave(Driver, old_path(Config)),
           Result = erpc:call(?SLAVE, fun() ->
                                              gen_rpc:call(?MASTER, erlang, node, [])
                                      end),
           ?assertMatch(?MASTER, Result),
           Config
       end,
       [fun ?MODULE:prop_fallback/2]).

%% Compatibility (bad cookie)
t_compat_old_client_invalid_cookie(Config) ->
    Driver = gen_rpc_test_helper:get_driver_from_config(Config),
    application:set_env(?APP, insecure_auth_fallback_allowed, true),
    ?check_trace(
       #{timetrap => 5000},
       begin
           application:set_env(?APP, secret_cookie, <<"wrong">>),
           ok = gen_rpc_test_helper:start_master(Driver),
           ok = gen_rpc_test_helper:start_slave(Driver, old_path(Config)),
           Result = erpc:call(?SLAVE, fun() ->
                                              gen_rpc:call(?MASTER, erlang, node, [])
                                      end),
           ?assertMatch({badrpc, invalid_cookie}, Result),
           Config
       end,
       [ fun ?MODULE:prop_canary/1
       , fun ?MODULE:prop_fallback/2
       ]).

%% Compatibility (bad cookie)
t_compat_old_server_invalid_cookie(Config) ->
    Driver = gen_rpc_test_helper:get_driver_from_config(Config),
    application:set_env(?APP, insecure_auth_fallback_allowed, true),
    ?check_trace(
       #{timetrap => 5000},
       begin
           application:set_env(?APP, secret_cookie, <<"baaaaaad_cookie">>),
           ok = gen_rpc_test_helper:start_master(Driver),
           ok = gen_rpc_test_helper:start_slave(Driver, old_path(Config)),
           rpc:call(?SLAVE, application, set_env, [?APP, insecure_auth_fallback_allowed, true]),
           %% Assuming fallback:
           case gen_rpc:call(?SLAVE, ?MODULE, canary, []) of
               {badrpc, invalid_cookie} ->
                   %% Very old server version use _unsafe_
                   %% binary_to_term and actually check the cookie
                   %% atom:
                   ok;
               {badtcp, closed} ->
                   %% Newer servers use safe `binary_to_term', which
                   %% means they don't return bad cookie error and
                   %% just treat insecure fallback message with wrong
                   %% cookie as malformed packet and just close
                   %% connection. This is also acceptable:
                   ok
           end,
           Config
       end,
       [ fun ?MODULE:prop_canary/1
       ]).

%%% ===================================================
%%% Auxiliary functions for test cases
%%% ===================================================

canary() ->
    ?tp(gen_rpc_canary, #{}),
    canary_is_dead.

prop_canary(Trace) ->
    ?assertMatch([], ?of_kind(gen_rpc_canary, Trace)).

prop_no_fallback(Trace) ->
    ?assertMatch([], ?of_kind([gen_rpc_insecure_fallback, gen_rpc_auth_cr_v1_fallback], Trace)).

prop_fallback(Config, Trace) ->
    Tag = proplists:get_value(old_tag, Config),
    case Tag of
        'compat-suite-2.8.2' ->
            ?assertMatch([_|_], ?of_kind([gen_rpc_insecure_fallback], Trace));
        _ ->
            ?assertMatch([], ?of_kind([gen_rpc_insecure_fallback], Trace))
    end.

old_path(Config) ->
    OldRelDir = proplists:get_value(old_rel_dir, Config),
    %% TODO: different releases could use different versions of the
    %% dependencies, so it's safer to just use all ebin paths from the
    %% old rel.
    Paths = lists:filter(fun(Path) -> not lists:suffix("gen_rpc/ebin", Path) end,
                         code:get_path()),
    [OldRelDir|Paths].

build_old_rel(Tag, Config) ->
    DataDir = filename:join(proplists:get_value(data_dir, Config), Tag),
    Ret = os:cmd("mkdir -p '" ++ DataDir ++ "' &&
                  cd '" ++ DataDir ++ "' &&
                  git clone https://github.com/emqx/gen_rpc.git || true &&
                  cd gen_rpc &&
                  git checkout '" ++ atom_to_list(Tag) ++ "' &&
                  rebar3 compile &&
                  echo 'DONE'"),
    case lists:suffix("DONE\n", Ret) of
        true ->
            ok;
        false ->
            erlang:display(Ret),
            error(compilation_failed)
    end,
    filename:join(DataDir, "gen_rpc/_build/test/lib/gen_rpc/ebin").
