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

-export([start_link/3]).
-export([start_protocol/4]).
-export([init/1]).

start_link(Ref, ConnType, Protocol) ->
	supervisor:start_link(?MODULE, [Ref, ConnType, Protocol]).

start_protocol(SupPid, QuicBackend, Conn, ProtoOpts) ->
	supervisor:start_child(SupPid, [QuicBackend, Conn, ProtoOpts]).

init([Ref, ConnType, Protocol]) ->
	%% @todo connection_type
	%% @todo shutdown_timeout
	Flags = #{
		strategy => simple_one_for_one,
		%% This supervisor should never go down.
		intensity => 1000000000,
		period => 1
	},
	Procs = [#{
		id => Protocol,
		start => {Protocol, start_link, [Ref]},
		type => ConnType
	}],
	{ok, {Flags, Procs}}.
