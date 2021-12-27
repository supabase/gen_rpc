-module(gen_rpc_trace_props).

-export([common_bundle/0, cast_bundle/0]).

-export([client_receive_all_casts/1, no_known_error_reports/1, no_reordering_on_client_side/1,
         transport_delivery/1, all_casts_are_executed/1]).

-include_lib("stdlib/include/assert.hrl").
-include_lib("snabbkaffe/include/test_macros.hrl").

cast_bundle() ->
    [ fun ?MODULE:client_receive_all_casts/1
    , fun ?MODULE:all_casts_are_executed/1
    , fun ?MODULE:no_reordering_on_client_side/1
    | common_bundle()
    ].

common_bundle() ->
    [ fun ?MODULE:no_known_error_reports/1
    , fun ?MODULE:transport_delivery/1
    ].

%%% Common trace specs:

no_known_error_reports(Trace) ->
    ?assertMatch([], ?of_kind(gen_rpc_error, Trace)).

transport_delivery(Trace) ->
    %% Check that packets are not lost:
    ?assert(
       ?strict_causality( #{?snk_kind := gen_rpc_send_packet, packet := _Packet}
                        , #{?snk_kind := gen_rpc_acceptor_receive, packet := _Packet}
                        , Trace
                        )).


%% TODO: Make this check more generic, so it can be safely bundled
no_reordering_on_client_side(Trace) ->
    snabbkaffe:strictly_increasing(?projection(packet, ?of_kind(gen_rpc_send_packet, Trace))).

%%% Checks related to cast messages:

%% Check that all test casts were received by a local client process before sending over net:
client_receive_all_casts(Trace) ->
    ?assert(
       ?strict_causality( #{?snk_kind := test_cast, seqno := _SeqNo}
                        , #{?snk_kind := gen_rpc_input, input := {_cast, gen_rpc_test_helper, test_call, [_SeqNo]}}
                        , Trace
                        )),
    ?assert(
       ?strict_causality( #{?snk_kind := gen_rpc_input,       input  := _Msg}
                        , #{?snk_kind := gen_rpc_send_packet, packet := _Msg}
                        , Trace
                        )).

%% Check that all casts initiated by the testcase were executed on the remote side:
all_casts_are_executed(Trace) ->
    ?strict_causality( #{?snk_kind := test_cast,    seqno := _SeqNo}
                     , #{?snk_kind := do_test_call, seqno := _SeqNo}
                     , Trace
                     ).
