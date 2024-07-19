#!/usr/bin/env bash

set -euo pipefail

NODE_NAME="$1"

rebar3 as test compile
erl -noshell -name ${NODE_NAME} -pa _build/test/lib/*/ebin -pa _build/test/lib/gen_rpc/test -eval 'ok = gen_rpc_test_helper:init_integration_test_config(), {ok, _} = application:ensure_all_started(gen_rpc), io:format(user, "running...~n", []).'
