%%--------------------------------------------------------------------
%% Copyright (c) 2022 EMQ Technologies Co., Ltd. All Rights Reserved.
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
-module(gen_rpc_auth).

-ifdef(TEST).
-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").
-endif.

%% API:
-export([stage1/0, stage2/2, stage2/1, stage3/3, stage3/2, stage4/3, stage4/2]).

%%================================================================================
%% Types
%%================================================================================

-type secret() :: binary().

-type challenge() :: binary().

-type packet() :: binary().

%% Packets
-record(gen_rpc_authenticate_c,
        { challenge :: binary()
        }).

-record(gen_rpc_authenticate_cr,
        { response  :: binary()
        , challenge :: binary()
        }).

-record(gen_rpc_authenticate_r,
        { response  :: binary()
        }).

%%================================================================================
%% API funcions
%%================================================================================

-spec stage1() -> {challenge(), packet()}.
stage1() ->
    make_c().

-spec stage2(packet()) -> {ok, {challenge(), packet()}} | {error, _}.
stage2(Packet) ->
    stage2(erlang:get_cookie(), Packet).

-spec stage3(challenge(), packet()) -> {ok, packet()} | {error, _}.
stage3(MyChallenge, Packet) ->
    stage3(erlang:get_cookie(), MyChallenge, Packet).

-spec stage4(challenge(), packet()) -> ok | {error, _}.
stage4(MyChallenge, Packet) ->
    stage4(erlang:get_cookie(), MyChallenge, Packet).

-spec stage2(secret(), packet()) -> {ok, {challenge(), packet()}} | {error, _}.
stage2(Secret, Packet) ->
    try erlang:binary_to_term(Packet, [safe]) of
        #gen_rpc_authenticate_c{challenge = Challenge} ->
            {ok, make_cr(Secret, Challenge)};
        Badterm ->
            {error, {badpacket, Badterm}}
    catch
        _:_ ->
            {error, {badpacket, Packet}}
    end.

-spec stage3(secret(), challenge(), packet()) -> {ok, packet()} | {error, _}.
stage3(Secret, MyChallenge, Packet) ->
    case check_cr(Secret, MyChallenge, Packet) of
        {ok, NewChallenge} ->
            {ok, make_r(Secret, NewChallenge)};
        Err ->
            Err
    end.

-spec stage4(secret(), challenge(), packet()) -> ok | {error, _}.
stage4(Secret, MyChallenge, Packet) ->
    check_r(Secret, MyChallenge, Packet).

%%================================================================================
%% Internal functions
%%================================================================================


-spec make_c() -> {challenge(), packet()}.
make_c() ->
    Challenge = rand_bytes(),
    Term = #gen_rpc_authenticate_c{challenge = Challenge},
    {Challenge, erlang:term_to_binary(Term)}.

-spec make_cr(secret(), challenge()) -> {challenge(), packet()}.
make_cr(Secret, Challenge) ->
    NewChallenge = rand_bytes(),
    Term = #gen_rpc_authenticate_cr{
              challenge = NewChallenge,
              response  = response(Secret, Challenge)
             },
    {NewChallenge, erlang:term_to_binary(Term)}.

-spec check_cr(secret(), challenge(), packet()) -> {ok, challenge()} | {error, _}.
check_cr(Secret, MyChallenge, Packet) ->
    try erlang:binary_to_term(Packet, [safe]) of
        #gen_rpc_authenticate_cr{response = Response, challenge = NewChallenge} ->
            case check_response(Secret, MyChallenge, Response) of
                true ->
                    {ok, NewChallenge};
                false ->
                    {error, badresponse}
            end;
        Badarg ->
            {error, {badarg, Badarg}}
    catch
        _:_ ->
            {error, badpacket}
    end.

-spec make_r(binary(), binary()) -> binary().
make_r(Secret, Challenge) ->
    Term = #gen_rpc_authenticate_r{
              response = response(Secret, Challenge)
             },
    erlang:term_to_binary(Term).

-spec check_r(binary(), binary(), binary()) -> ok | {error, _}.
check_r(Secret, Challenge, Packet) ->
    try erlang:binary_to_term(Packet, [safe]) of
        #gen_rpc_authenticate_r{response = Response} ->
            case check_response(Secret, Challenge, Response) of
                true ->
                    ok;
                false ->
                    {error, badresponse}
            end;
        Badarg ->
            {error, {badarg, Badarg}}
    catch
        _:_ ->
            {error, badpacket}
    end.

-spec response(binary(), binary()) -> binary().
response(Secret, Challenge) ->
    crypto:hash(sha256, [Secret, Challenge]).

-spec check_response(binary(), binary(), binary()) -> boolean().
check_response(Secret, Challenge, Response) ->
    Expected = response(Secret, Challenge),
    compare_binaries(Response, Expected).

-spec rand_bytes() -> binary().
rand_bytes() ->
    Size = application:get_env(gen_rpc, challenge_size, 8),
    crypto:strong_rand_bytes(Size).

-spec compare_binaries(binary(), binary()) -> boolean().
compare_binaries(A, B) ->
    case do_compare_binaries(binary_to_list(A), binary_to_list(B), 0) of
        0 -> true;
        _ -> false
    end.

-spec do_compare_binaries([byte()], [byte()], byte()) -> byte().
do_compare_binaries([A|L1], [B|L2], Acc) ->
    do_compare_binaries(L1, L2, Acc bor (A bxor B));
do_compare_binaries(_, _, Acc) ->
    Acc.

-ifdef(TEST).

rand_bytes_test() ->
    ?assert(is_binary(rand_bytes())).

compare_binaries_test() ->
    A1 = crypto:hash(sha256, <<"a">>),
    A2 = crypto:hash(sha256, <<"ab">>),
    ?assert(compare_binaries(A1, A1)),
    ?assert(compare_binaries(A2, A2)),
    ?assertNot(compare_binaries(A1, A2)),
    ?assertNot(compare_binaries(A2, A1)),
    ?assertNot(compare_binaries(<<"abcdef">>, A1)),
    ?assertNot(compare_binaries(A1, <<"abcdef">>)).

%% Check response created with a valid secret
check_response_ok_prop() ->
    ?FORALL({Secret, Challenge}, {binary(), binary()},
            begin
                Response = response(Secret, Challenge),
                check_response(Secret, Challenge, Response)
            end).

check_response_ok_test() ->
    ?assert(proper:quickcheck(check_response_ok_prop(), 100)).

%% Check response created with invalid secret
check_response_fail_prop() ->
    ?FORALL({Secret1, Secret2, Challenge}, {binary(), binary(), binary()},
            ?IMPLIES(Secret1 =/= Secret2,
                     begin
                         Response = response(Secret2, Challenge),
                         not check_response(Secret1, Challenge, Response)
                     end)).

check_response_fail_test() ->
    ?assert(proper:quickcheck(check_response_fail_prop(), 100)).

%% Check normal flow of authentication (same shared secret)
auth_flow_ok_prop() ->
    ?FORALL(Secret, binary(),
            begin
                {ClientChallenge, P1} = stage1(),
                {ok, {ServerChallenge, P2}} = stage2(Secret, P1),
                {ok, P3} = stage3(Secret, ClientChallenge, P2),
                ok =:= stage4(Secret, ServerChallenge, P3)
            end).

auth_flow_ok_test() ->
    ?assert(proper:quickcheck(auth_flow_ok_prop(), 100)).

%% Check exceptional flow when the server's secret is incorrect:
auth_flow_server_fail_prop() ->
    ?FORALL({Secret1, Secret2}, {binary(), binary()},
            ?IMPLIES(Secret1 =/= Secret2,
                     begin
                         {ClientChallenge, P1} = stage1(),
                         {ok, {_ServerChallenge, P2}} = stage2(Secret1, P1),
                         ?assertMatch({error, _}, stage3(Secret2, ClientChallenge, P2)),
                         true
                     end)).

auth_flow_server_fail_test() ->
    ?assert(proper:quickcheck(auth_flow_server_fail_prop(), 100)).

%% Check exceptional flow when the client's secret is incorrect:
auth_flow_client_fail_prop() ->
    ?FORALL({Secret1, Secret2}, {binary(), binary()},
            ?IMPLIES(Secret1 =/= Secret2,
                     begin
                         {ClientChallenge, P1} = stage1(),
                         {ok, {ServerChallenge, P2}} = stage2(Secret1, P1),
                         {ok, P3} = stage3(Secret1, ClientChallenge, P2),
                         ?assertMatch({error, _}, stage4(Secret2, ServerChallenge, P3)),
                         true
                     end)).

auth_flow_client_fail_test() ->
    ?assert(proper:quickcheck(auth_flow_client_fail_prop(), 100)).

-endif.
