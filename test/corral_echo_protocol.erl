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
	{ok, Info} = QuicBackend:handshake(Conn),
	?LOG("~p handshake: ~p ~0p", [?FUNCTION_NAME, Conn, Info]),
	loop(#{backend => QuicBackend, conn => Conn}).

loop(State=#{backend := QuicBackend}) ->
	%% @todo Need the common message handling module to continue.
	receive
		Msg when element(1, Msg) =:= quic ->
			?LOG("QUIC msg ~0p", [Msg]),
			case QuicBackend:make_event(Msg) of
				unknown_msg ->
					?LOG("UNKNOWN MESSAGE: ~p", [Msg]),
					loop(State);
				no_event ->
					loop(State);
				Event ->
					handle(Event, State)
			end;
		Msg ->
			?LOG("STRAY MESSAGE: ~p", [Msg]),
			loop(State)
	end.

handle(Event, State=#{forwarding := Pid}) ->
	?LOG("QUIC forwarding ~p~n", [Event]),
	Pid ! {forwarding, Event},
	loop(State);
handle(Event = {stream_opened, StreamID, bidi}, State) ->
	?LOG("QUIC handle ~p~n", [Event]),
	loop(State#{StreamID => bidi});
handle(Event = {stream_opened, StreamID, unidi}, State=#{backend := QuicBackend, conn := Conn}) ->
	?LOG("QUIC handle ~p~n", [Event]),
	{ok, OpenStreamID} = QuicBackend:open_unidi_stream(Conn, <<>>),
	loop(State#{
		StreamID => {unidi_remote, OpenStreamID},
		OpenStreamID => {unidi_local, StreamID}
	});
%% @todo Equivalent tests.
handle(Event = {stream_data, StreamID, _IsFin, <<"TEST:", Test/bits>>}, State=#{backend := QuicBackend, conn := Conn}) ->
	?LOG("QUIC handle ~p~n", [Event]),
	case Test of
		<<"close_0">> ->
			QuicBackend:close(Conn, 0);
		<<"close_256">> ->
			QuicBackend:close(Conn, 256);
		<<"close_stream">> ->
			ok = QuicBackend:close_stream(Conn, StreamID, 456),
			loop(State);
		<<"forwarding ", PidBin/bits>> ->
			Pid = list_to_pid(binary_to_list(PidBin)),
			ok = QuicBackend:send(Conn, StreamID, <<"Forwarding enabled.">>),
			loop(State#{forwarding => Pid});
		<<"open_bidi">> ->
			{ok, OpenStreamID} = QuicBackend:open_bidi_stream(Conn, <<"Hello">>),
			loop(State#{OpenStreamID => bidi});
		<<"peercert">> ->
			Peercert = term_to_binary(QuicBackend:peercert(Conn)),
			ok = QuicBackend:send(Conn, StreamID, Peercert),
			loop(State);
		<<"peername">> ->
			PeernameBin = term_to_binary(QuicBackend:peername(Conn)),
			ok = QuicBackend:send(Conn, StreamID, PeernameBin),
			loop(State);
		<<"ping_me ", PidBin/bits>> ->
			Pid = list_to_pid(binary_to_list(PidBin)),
			Pid ! ping_me,
			loop(State);
		<<"reset_stream">> ->
			ok = QuicBackend:reset_stream(Conn, StreamID, 456),
			loop(State);
		<<"sockname">> ->
			SocknameBin = term_to_binary(QuicBackend:sockname(Conn)),
			ok = QuicBackend:send(Conn, StreamID, SocknameBin),
			loop(State);
		<<"stop_sending">> ->
			ok = QuicBackend:stop_sending(Conn, StreamID, 456),
			ok = QuicBackend:send(Conn, StreamID, <<"More data.">>),
			loop(State)
	end;
handle(Event = {stream_data, StreamID, IsFin, Data}, State=#{backend := QuicBackend, conn := Conn}) ->
	?LOG("QUIC handle ~p~n", [Event]),
	case State of
		#{StreamID := bidi} ->
			ok = QuicBackend:send(Conn, StreamID, IsFin, Data),
			loop(State);
		#{StreamID := {unidi_remote, LocalStreamID}} ->
			ok = QuicBackend:send(Conn, LocalStreamID, IsFin, Data),
			loop(State)
	end;
handle(Event = {stream_reset, StreamID, AppErrno}, State=#{backend := QuicBackend, conn := Conn}) ->
	?LOG("QUIC handle ~p~n", [Event]),
	case QuicBackend:send(Conn, StreamID, nofin, [<<"stream_reset:">>, integer_to_list(AppErrno)]) of
		ok -> ok;
		%% Some tests may fully close the stream.
		{error, closed} -> ok
	end,
	loop(State);
handle(Event = {stream_stop_sending, _StreamID, _AppErrno}, State) ->
	?LOG("QUIC handle ~p~n", [Event]),
	%% We do not need to send an explicit RESET_STREAM, we expect the backend to do it.
%	ok = QuicBackend:reset_stream(Conn, StreamID, AppErrno),
	loop(State);
handle(Event = {datagram, Data}, State=#{backend := QuicBackend, conn := Conn}) ->
	?LOG("QUIC handle ~p~n", [Event]),
	ok = QuicBackend:send_datagram(Conn, Data),
	loop(State);
handle(Event, State) ->
	?LOG("QUIC handle ignore ~p~n", [Event]),
	loop(State).
