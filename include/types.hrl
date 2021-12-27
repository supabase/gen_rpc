%%% -*-mode:erlang;coding:utf-8;tab-width:4;c-basic-offset:4;indent-tabs-mode:()-*-
%%% ex: set ft=erlang fenc=utf-8 sts=4 ts=4 sw=4 et:
%%%
%%% Copyright 2015 Panagiotis Papadomitsos. All Rights Reserved.
%%%

%%% Node type
-type destination() :: {node(), _Tag}.

-type node_or_tuple() :: node() | destination().

%% `gen_rpc' doesn't take advantage of atom indexing, so using short
%% atom names saves a bit of bandwidth.
-define(CAST(M, F, A), {cast, M, F, A}).
-define(ORDERED_CAST(M, F, A), {oc, M, F, A}).
