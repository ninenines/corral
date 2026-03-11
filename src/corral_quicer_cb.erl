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

%% This module receives the Conn from quicer and performs the handshake.
%% It uses the start of the quicer_connection behavior to bootstrap the
%% connection and hand it off to the Corral protocol process which will
%% then receive messages directly.

-module(corral_quicer_cb).

-export([init/1]).
-export([new_conn/3]).

-type cb_opts() :: #{
	ref := corral:ref(),
	conns_sup := pid()
}.

-spec init(#{user_opts := UserOpts})
	-> {ok, UserOpts} when UserOpts :: cb_opts().

init(ConnOpts) ->
	{ok, maps:get(user_opts, ConnOpts)}.

new_conn(Conn, _Props, State=#{ref := Ref, conns_sup := ConnsSup}) ->
	%% @todo This should probably be made configurable.
	ok = quicer:setopt(Conn, datagram_receive_enabled, true),
	ProtoOpts = corral_ets:get_protocol_opts(Ref),
	{ok, Pid} = corral_conns_sup:start_protocol(ConnsSup, corral_quicer, Conn, ProtoOpts),
	ok = quicer:controlling_process(Conn, Pid),
	ok = quicer:async_handshake(Conn),
	{ok, State#{pid => Pid}}.
