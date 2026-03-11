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

-module(corral_echo_protocol).

-export([start_link/4]).
-export([connection_process/5]).

-define(DEBUG, 1).
-ifdef(DEBUG).
-define(LOG(Fmt, Args), ct:pal(Fmt, Args)).
-else.
-define(LOG(Fmt, Args), _ = Fmt, _ = Args, ok).
-endif.

start_link(Ref, QuicBackend, Conn, ProtoOpts) ->
	Pid = proc_lib:spawn_link(?MODULE, connection_process,
		[self(), Ref, QuicBackend, Conn, ProtoOpts]),
	{ok, Pid}.

connection_process(Parent, Ref, QuicBackend, Conn, Opts) ->
	?LOG("~p: ~p ~p ~p ~p", [?FUNCTION_NAME, Parent, Ref, QuicBackend, Opts]),
	{ok, Info} = corral:handshake(QuicBackend, Conn),
	?LOG("~p handshake: ~p ~0p", [?FUNCTION_NAME, Conn, Info]),
	loop(#{backend => QuicBackend, conn => Conn}).

loop(State=#{backend := QuicBackend}) ->
	%% @todo Need the common message handling module to continue.
	receive
		Msg when element(1, Msg) =:= quic ->
			case QuicBackend:make_event(Msg) of
				unknown ->
					?LOG("UNKNOWN MESSAGE: ~p", [Msg]),
					loop(State);
				Event ->
					handle(Event, State)
			end;
		Msg ->
			?LOG("STRAY MESSAGE: ~p", [Msg]),
			loop(State)
	end.

handle(Event = {stream_started, StreamID, bidi}, State) ->
	?LOG("QUIC handle ~p~n", [Event]),
	loop(State#{StreamID => bidi});
handle(Event = {stream_started, StreamID, unidi}, State=#{backend := QuicBackend, conn := Conn}) ->
	?LOG("QUIC handle ~p~n", [Event]),
	{ok, OpenStreamID} = QuicBackend:start_unidi_stream(Conn, <<>>),
	loop(State#{
		StreamID => {unidi_remote, OpenStreamID},
		OpenStreamID => {unidi_local, StreamID}
	});
%% @todo Equivalent tests.
handle(Event = {stream_data, _StreamID, _IsFin, <<"TEST:", Test/bits>>}, State=#{backend := QuicBackend, conn := Conn}) ->
	?LOG("QUIC handle ~p~n", [Event]),
	case Test of
		<<"open_bidi">> ->
			{ok, OpenStreamID} = QuicBackend:start_bidi_stream(Conn, <<>>),
			loop(State#{OpenStreamID => bidi})%;
%		<<"initiate_close">> ->
%			{[initiate_close], Streams};
%		<<"close">> ->
%			{[close], Streams};
%		<<"close_app_code">> ->
%			{[{close, 1234567890}], Streams};
%		<<"close_app_code_msg">> ->
%			{[{close, 1234567890, <<"onetwothreefourfivesixseveneightnineten">>}], Streams};
%		<<"event_pid:", EventPidBin/bits>> ->
%			{[{send, StreamID, nofin, <<"event_pid_received">>}],
%				Streams#{event_pid => binary_to_term(EventPidBin)}}
	end;
handle(Event = {stream_data, StreamID, IsFin, Data}, State=#{backend := QuicBackend, conn := Conn}) ->
	?LOG("QUIC handle ~p~n", [Event]),
	case State of
		#{StreamID := bidi} ->
			ok = QuicBackend:send(Conn, StreamID, Data, IsFin),
			loop(State);
		#{StreamID := {unidi_remote, LocalStreamID}} ->
			ok = QuicBackend:send(Conn, LocalStreamID, Data, IsFin),
			loop(State);
		#{} -> %% @todo erlang_quic difference.
			ok = QuicBackend:send(Conn, StreamID, Data, IsFin),
			loop(State#{StreamID => bidi})
	end;
%% @todo
%handle(Event = {datagram, Data}, Streams) ->
%	?LOG("QUIC handle ~p~n", [Event]),
%	{[{send, datagram, Data}], Streams};
%handle(Event = close_initiated, Streams) ->
%	?LOG("QUIC handle ~p~n", [Event]),
%	{[{send, datagram, <<"TEST:close_initiated">>}], Streams};
handle(Event, Streams) ->
	?LOG("QUIC handle ignore ~p~n", [Event]),
	{[], Streams}.
