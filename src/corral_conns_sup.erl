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

-module(corral_conns_sup).
-behaviour(supervisor).

-export([start_link/2]).
-export([start_protocol/4]).
-export([init/1]).

start_link(Ref, Protocol) ->
	supervisor:start_link(?MODULE, [Ref, Protocol]).

start_protocol(SupPid, QuicBackend, Conn, ProtoOpts) ->
	supervisor:start_child(SupPid, [QuicBackend, Conn, ProtoOpts]).

init([Ref, Protocol]) ->
	Procs = [#{
		id => Protocol,
		start => {Protocol, start_link, [Ref]}
	}],
	{ok, {{simple_one_for_one, 1, 5}, Procs}}.
