%%--------------------------------------------------------------------
%% Copyright (c) 2026 EMQ Technologies Co., Ltd. All Rights Reserved.
%%--------------------------------------------------------------------

-module(gen_rpc_helper_tests).

-include_lib("eunit/include/eunit.hrl").

-define(APP, gen_rpc).

set_extra_process_flags_empty_test() ->
    with_env(#{extra_process_flags => []}, fun() ->
        ?assertEqual(ok, gen_rpc_helper:set_extra_process_flags())
    end).

set_extra_process_flags_multiple_test() ->
    with_env(#{extra_process_flags => [{fullsweep_after, 10}, {message_queue_data, on_heap}]}, fun() ->
        ok = gen_rpc_helper:set_extra_process_flags(),
        ?assertMatch({fullsweep_after, 10}, erlang:process_info(self(), fullsweep_after)),
        ?assertMatch({message_queue_data, on_heap}, erlang:process_info(self(), message_queue_data))
    end).

set_extra_process_flags_not_configured_test() ->
    Saved = application:get_env(?APP, extra_process_flags),
    try
        application:unset_env(?APP, extra_process_flags),
        ?assertEqual(ok, gen_rpc_helper:set_extra_process_flags())
    after
        case Saved of
            undefined -> application:unset_env(?APP, extra_process_flags);
            {ok, V}   -> application:set_env(?APP, extra_process_flags, V)
        end
    end.

%%% Helpers

with_env(Overrides, Fun) ->
    Saved = #{ Key => application:get_env(?APP, Key) || Key <- maps:keys(Overrides) },
    try
        maps:foreach(fun(Key, Value) -> ok = application:set_env(?APP, Key, Value) end, Overrides),
        Fun()
    after
        maps:foreach(
            fun
                (Key, undefined) -> application:unset_env(?APP, Key);
                (Key, {ok, Value}) -> ok = application:set_env(?APP, Key, Value)
            end,
            Saved
        )
    end.
