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

-include("logger.hrl").
-include_lib("snabbkaffe/include/trace.hrl").

-ifdef(TEST).
-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").
-endif.

%% API:
-export([authenticate_server/2, authenticate_client/3, get_cookie/0]).

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
%% API
%%================================================================================

-spec authenticate_server(module(), term()) ->  ok | {error, {badtcp | badrpc, term()}}.
authenticate_server(Driver, Socket) ->
    ok = Driver:set_send_timeout(Socket, gen_rpc_helper:get_send_timeout(undefined)),
    Fallback = insecure_fallback(),
    Peer = Driver:get_peer(Socket),
    case authenticate_server_cr(Driver, Socket) of
        old when Fallback ->
            ?tp(warning, gen_rpc_insecure_fallback, #{peer => Peer}),
            authenticate_server_insecure(Driver, Socket);
        Result ->
            Result
    end.

-spec authenticate_client(module(), term(), tuple()) -> ok | {error, {badtcp | badrpc, term()}}.
authenticate_client(Driver, Socket, Peer) ->
    ok = Driver:set_send_timeout(Socket, gen_rpc_helper:get_send_timeout(undefined)),
    RecvTimeout = gen_rpc_helper:get_call_receive_timeout(undefined),
    Fallback = insecure_fallback(),
    case Driver:recv(Socket, 0, RecvTimeout) of
        {ok, Data} ->
            case authenticate_client_cr(Driver, Socket, Data) of
                {error, {badarg, _}} when Fallback ->
                    ?tp(warning, gen_rpc_insecure_fallback, #{peer => Peer}),
                    authenticate_client_insecure(Driver, Socket, Peer, Data);
                Result ->
                    Result
            end;
        {error, Reason} ->
            ?tp(error, gen_rpc_client_auth_timeout, #{peer => Peer, error => Reason}),
            {error, {badtcp, Reason}}
    end.

%%================================================================================
%% Challenge-response
%%================================================================================

-spec authenticate_server_cr(module(), port()) -> ok | {error, {badtcp | badrpc, term()}}.
authenticate_server_cr(Driver, Socket) ->
    Peer = Driver:get_peer(Socket),
    try
        %% Send challenge:
        {ClientChallenge, Packet} = stage1(),
        ?tp(debug, gen_rpc_authentication_stage, #{stage => 1, socket => Socket, peer => Peer}),
        send(Driver, Socket, Packet, challenge),
        %% Receive response to our challenge and a new challenge:
        RecvPacket = recv(Driver, Socket, challenge_response),
        Result = stage3(ClientChallenge, RecvPacket),
        ?tp(debug, gen_rpc_authentication_stage, #{stage => 3, socket => Socket, peer => Peer, result => Result}),
        case Result of
            {ok, Packet2} ->
                %% Send the final response to the client:
                send(Driver, Socket, Packet2, response);
            {error, Error} ->
                ?tp(error, gen_rpc_authentication_bad_cookie, #{socket => Socket, error => Error, peer => Peer}),
                {error, {badrpc, Error}}
        end
    catch
        {badtcp, Action, Meta, Reason} ->
            ?tp(error, gen_rpc_authentication_badtcp,
                #{ packet => Meta
                 , reason => Reason
                 , peer => Peer
                 , socket => Socket
                 , action => Action
                 }),
            {error, {badtcp, Reason}}
    end.

-spec authenticate_client_cr(module(), port(), binary()) -> ok | {error, {badtcp | badrpc, term()}}.
authenticate_client_cr(Driver, Socket, Data) ->
    Peer = Driver:get_peer(Socket),
    Result2 = stage2(Data),
    ?tp(debug, gen_rpc_authentication_stage, #{stage => 2, socket => Socket, peer => Peer, result => Result2}),
    try
        case Result2 of
            {ok, {ServerChallenge, Packet}} ->
                send(Driver, Socket, Packet, challenge_response),
                RecvPacket = recv(Driver, Socket, response),
                Result = stage4(ServerChallenge, RecvPacket),
                ?tp(debug, gen_rpc_authentication_stage, #{stage => 4, socket => Socket, peer => Peer, result => Result}),
                Result;
            Error ->
                Error
        end
    catch
        {badtcp, Action, Meta, Reason} ->
            ?tp(error, gen_rpc_authentication_badtcp,
                #{ packet => Meta
                 , reason => Reason
                 , peer => Peer
                 , socket => Socket
                 , action => Action
                 }),
            {error, {badtcp, Reason}}
    end.

%%================================================================================
%% Insecure fallback
%%================================================================================

-spec authenticate_server_insecure(module(), term()) -> ok | {error, {badtcp | badrpc, term()}}.
authenticate_server_insecure(Driver, Socket) ->
    Peer = Driver:get_peer(Socket),
    try
        %% Send cookie to the remote server:
        Cookie = erlang:get_cookie(),
        Packet = erlang:term_to_binary({gen_rpc_authenticate_connection, Cookie}),
        send(Driver, Socket, Packet, insecure_cookie),
        %% Wait for the reply:
        RecvPacket = recv(Driver, Socket, insecure_response),
        try erlang:binary_to_term(RecvPacket) of
            gen_rpc_connection_authenticated ->
                ?log(debug, "event=connection_authenticated socket=\"~s\"", [gen_rpc_helper:socket_to_string(Socket)]),
                ok;
            {gen_rpc_connection_rejected, invalid_cookie} ->
                ?log(error, "event=authentication_rejected socket=\"~s\" reason=\"invalid_cookie\"",
                     [gen_rpc_helper:socket_to_string(Socket)]),
                {error, {badrpc,invalid_cookie}};
            _Else ->
                ?log(error, "event=authentication_reception_error socket=\"~s\" reason=\"invalid_payload\"",
                     [gen_rpc_helper:socket_to_string(Socket)]),
                {error, {badrpc,invalid_message}}
        catch
            error:badarg ->
                {error, {badtcp,corrupt_data}}
        end
    catch
        {badtcp, Action, Meta, Reason} ->
            ?tp(error, gen_rpc_server_auth_fallback_badtcp,
                #{ packet => Meta
                 , reason => Reason
                 , peer => Peer
                 , socket => Socket
                 , action => Action
                 }),
            {error, {badtcp, Reason}}
    end.

-spec authenticate_client_insecure(module(), port(), tuple(), binary()) -> ok | {error, {badtcp | badrpc, term()}}.
authenticate_client_insecure(Driver, Socket, Peer, Data) ->
    Cookie = erlang:get_cookie(),
    CheckResult =
        try erlang:binary_to_term(Data) of
            {gen_rpc_authenticate_connection, Cookie} ->
                ok;
            {gen_rpc_authenticate_connection, _Node, Cookie} ->
                %% Old authentication packet sent by SSL driver
                ok;
            {gen_rpc_authenticate_connection, _InvalidCookie} ->
                invalid_cookie;
            {gen_rpc_authenticate_connection, _Node, _InvalidCookie} ->
                %% Old authentication packet sent by SSL driver
                invalid_cookie;
            _ ->
                erroneous_data
        catch
            error:badarg ->
                corrupt_data
        end,
    LogLevel = case CheckResult of
                   ok -> debug;
                   _  -> error
               end,
    ?tp(LogLevel, gen_rpc_client_auth_fallback, #{peer => Peer, socket => Socket, result => CheckResult}),
    try
        case CheckResult of
            ok ->
                Packet = erlang:term_to_binary(gen_rpc_connection_authenticated),
                send(Driver, Socket, Packet, reply),
                ok;
            invalid_cookie ->
                Packet = erlang:term_to_binary({gen_rpc_connection_rejected, invalid_cookie}),
                send(Driver, Socket, Packet, reply),
                {error, {badrpc,invalid_cookie}};
            Err ->
                {error, Err}
        end
    catch
        {badtcp, Action, Meta, Reason} ->
            ?tp(error, gen_rpc_client_auth_fallback_badtcp,
                #{ packet => Meta
                 , reason => Reason
                 , peer => Peer
                 , socket => Socket
                 , action => Action
                 }),
            {error, {badtcp, Reason}}
    end.

%%================================================================================
%% Wrapper functions for network (throwing)
%%================================================================================

recv(Driver, Socket, Meta) ->
    RecvTimeout = gen_rpc_helper:get_call_receive_timeout(undefined),
    case Driver:recv(Socket, 0, RecvTimeout) of
        {ok, Packet} ->
            Packet;
        {error, Reason} ->
            throw({badtcp, recv, Meta, Reason})
    end.

send(Driver, Socket, Packet, Meta) ->
    case Driver:send(Socket, Packet) of
        ok ->
            ok;
        {error, Reason} ->
            throw({badtcp, send, Meta, Reason})
    end.

%%================================================================================
%% Challenge-response stages (pure functions)
%%================================================================================

-spec stage1() -> {challenge(), packet()}.
stage1() ->
    make_c().

-spec stage2(packet()) -> {ok, {challenge(), packet()}} | {error, _}.
stage2(Packet) ->
    stage2(get_cookie(), Packet).

-spec stage3(challenge(), packet()) -> {ok, packet()} | {error, _}.
stage3(MyChallenge, Packet) ->
    stage3(get_cookie(), MyChallenge, Packet).

-spec stage4(challenge(), packet()) -> ok | {error, badpacket | {badarg, _} | unauthorized}.
stage4(MyChallenge, Packet) ->
    stage4(get_cookie(), MyChallenge, Packet).

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

-spec stage4(secret(), challenge(), packet()) -> ok | {error, badpacket | {badarg, _} | unauthorized}.
stage4(Secret, MyChallenge, Packet) ->
    check_r(Secret, MyChallenge, Packet).

%%================================================================================
%% Internal pure functions
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
                    {error, unauthorized}
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

-spec check_r(binary(), binary(), binary()) -> ok | {error, badpacket | {badarg, _} | unauthorized}.
check_r(Secret, Challenge, Packet) ->
    try erlang:binary_to_term(Packet, [safe]) of
        #gen_rpc_authenticate_r{response = Response} ->
            case check_response(Secret, Challenge, Response) of
                true ->
                    ok;
                false ->
                    {error, unauthorized}
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

insecure_fallback() ->
    application:get_env(gen_rpc, insecure_auth_fallback, false).

get_cookie() ->
    case application:get_env(gen_rpc, secret_cookie) of
        {ok, Cookie} ->
            Cookie;
        undefined ->
            atom_to_binary(erlang:get_cookie(), latin1)
    end.

%%================================================================================
%% Unit tests
%%================================================================================

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
