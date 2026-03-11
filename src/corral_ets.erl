%% Copyright (c) Loïc Hoguin <essen@ninenines.eu>
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-module(corral_ets).

-export([init/0]).
-export([set_port_and_backend/3]).
-export([get_port/1]).
-export([get_backend/1]).
-export([set_new_protocol_opts/2]).
-export([get_protocol_opts/1]).
-export([cleanup_listener/1]).

-spec init() -> ok.

init() ->
	?MODULE = ets:new(?MODULE, [ordered_set, public, named_table]),
	ok.

-spec set_port_and_backend(corral:ref(), inet:port_number(), module()) -> ok.

%% @todo It would be good to have the full address rather than just the port.
set_port_and_backend(Ref, Port, QuicBackend) ->
	ets:insert(?MODULE, {{port, Ref}, Port}),
	ets:insert(?MODULE, {{backend, Ref}, QuicBackend}),
	ok.

-spec get_port(corral:ref()) -> inet:port_number().

get_port(Ref) ->
	ets:lookup_element(?MODULE, {port, Ref}, 2).

-spec get_backend(corral:ref()) -> module().

get_backend(Ref) ->
	ets:lookup_element(?MODULE, {backend, Ref}, 2).

-spec set_new_protocol_opts(corral:ref(), corral:protocol_opts()) -> ok.

set_new_protocol_opts(Ref, ProtoOpts) ->
	ets:insert_new(?MODULE, {{protocol_opts, Ref}, ProtoOpts}),
	ok.

-spec get_protocol_opts(corral:ref())
	-> {ok, corral:protocol_opts()}.

get_protocol_opts(Ref) ->
	ets:lookup_element(?MODULE, {protocol_opts, Ref}, 2).

-spec cleanup_listener(corral:ref()) -> ok.

cleanup_listener(Ref) ->
	_ = ets:delete(?MODULE, {backend, Ref}),
	_ = ets:delete(?MODULE, {port, Ref}),
	_ = ets:delete(?MODULE, {protocol_opts, Ref}),
	ok.
