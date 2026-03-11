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

-module(corral_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-import(ct_helper, [config/2]).
-import(ct_helper, [doc/1]).

-define(CLIENT, corral_quicer).

all() ->
	[
		{group, corral_quic},
		{group, corral_quicer}
	].

groups() ->
	[
		{corral_quic, [], ct_helper:all(?MODULE)},
		{corral_quicer, [], ct_helper:all(?MODULE)}
	].

init_per_suite(Config) ->
	{ok, _} = application:ensure_all_started(corral),
	case os:type() of
		{win32, _} ->
			{skip, "Quicer not currently available on Windows."};
		_ ->
			Config
	end.

end_per_suite(_Config) ->
	ok.

%% Listener tests.

start_stop(Config) ->
	doc("Start a listener, client opens a bidi stream, sends data echoed back by server, stop the listener."),
	try
		QuicOpts = #{
			alpn => [<<"corral">>],
			backend => do_get_backend(Config),
			certfile => do_get_certs("server.crt"),
			keyfile => do_get_certs("server.key")
		},
		{ok, _} = corral:start_listener(
			?FUNCTION_NAME,
			QuicOpts,
			corral_echo_protocol,
			opts),
		_ = corral:get_port(?FUNCTION_NAME),
		%% @todo Note that using "localhost" currently fails to connect for me
		%%       (seems to default to ipv6) when using erlang_quic listener.
		%%       Need to make separate v4/v6 tests to make sure it works for both.
		{ok, Conn} = do_connect(?FUNCTION_NAME, Config),
		{ok, BidiStreamID} = ?CLIENT:open_bidi_stream(Conn, <<"Hello">>),
		{nofin, <<"Hello">>} = do_receive_data(BidiStreamID),
		?CLIENT:close(Conn),
		ok = corral:stop_listener(?FUNCTION_NAME)
	after
		%% Test may have failed. We still stop the listener if needed.
		_ = corral:stop_listener(?FUNCTION_NAME)
	end.

%% Backend tests.
%%
%% Note that most events and make_event/1 are tested
%% alongside the corresponding functions.
%%
%% @todo The conn_closed (transport) event needs a test. (How?)

close_0(Config) ->
	doc("Start a listener, client makes server close the connection with code 0 (undefined error code)."),
	do_test(do_close_0_test, Config).

do_close_0_test(Config) ->
	do_start_listener(?FUNCTION_NAME, Config),
	{ok, Conn} = do_connect(?FUNCTION_NAME, Config),
	{ok, _LocalBidiStreamID} = ?CLIENT:open_bidi_stream(Conn, <<"TEST:close_0">>),
	{conn_closed, application, 0} = do_await_conn_closed(),
	?CLIENT:close(Conn).

close_256(Config) ->
	doc("Start a listener, client makes server close the connection with code 256 (e.g. H3_NO_ERROR)."),
	do_test(do_close_256_test, Config).

do_close_256_test(Config) ->
	do_start_listener(?FUNCTION_NAME, Config),
	{ok, Conn} = do_connect(?FUNCTION_NAME, Config),
	{ok, _LocalBidiStreamID} = ?CLIENT:open_bidi_stream(Conn, <<"TEST:close_256">>),
	{conn_closed, application, 256} = do_await_conn_closed(),
	?CLIENT:close(Conn).

close_stream_client(Config) ->
	doc("Start a listener, client opens stream and closes it."),
	do_test(do_close_stream_client_test, Config).

do_close_stream_client_test(Config) ->
	do_start_listener(?FUNCTION_NAME, Config),
	{ok, Conn} = do_connect(?FUNCTION_NAME, Config),
	{ok, BidiStreamID} = ?CLIENT:open_bidi_stream(Conn, <<"Initial data.">>),
	{nofin, <<"Initial data.">>} = do_receive_data(BidiStreamID),
	%% Provide pid to server then close the stream.
	ok = ?CLIENT:send(Conn, BidiStreamID, nofin, [<<"TEST:forwarding ">>, pid_to_list(self())]),
	{nofin, <<"Forwarding enabled.">>} = do_receive_data(BidiStreamID),
	ok = ?CLIENT:close_stream(Conn, BidiStreamID, 123),
	%% Server received both stop_sending and stream_reset (in any order).
	receive {forwarding, {stream_reset, BidiStreamID, 123}} -> ok after 5000 -> error(timeout) end,
	receive {forwarding, {stream_stop_sending, BidiStreamID, 123}} -> ok after 5000 -> error(timeout) end,
	?CLIENT:close(Conn).

close_stream_server(Config) ->
	doc("Start a listener, client opens stream, server closes it."),
	do_test(do_close_stream_server_test, Config).

do_close_stream_server_test(Config) ->
	do_start_listener(?FUNCTION_NAME, Config),
	{ok, Conn} = do_connect(?FUNCTION_NAME, Config),
	{ok, BidiStreamID} = ?CLIENT:open_bidi_stream(Conn, <<"TEST:close_stream">>),
	Event1 = do_await_stream_event(BidiStreamID),
	Event2 = do_await_stream_event(BidiStreamID),
	[
		{stream_reset, BidiStreamID, 456},
		{stream_stop_sending, BidiStreamID, 456}
	] = lists:sort([Event1, Event2]),
	?CLIENT:close(Conn).

open_bidi_stream(Config) ->
	doc("Start a listener, client makes server open a bidi stream that sends data."),
	do_test(do_open_bidi_stream_test, Config).

do_open_bidi_stream_test(Config) ->
	do_start_listener(?FUNCTION_NAME, Config),
	{ok, Conn} = do_connect(?FUNCTION_NAME, Config),
	{ok, _LocalBidiStreamID} = ?CLIENT:open_bidi_stream(Conn, <<"TEST:open_bidi">>),
	{bidi, PeerBidiStreamID} = do_await_stream_opened(),
	{nofin, <<"Hello">>} = do_receive_data(PeerBidiStreamID),
	?CLIENT:close(Conn).

open_unidi_stream(Config) ->
	doc("Start a listener, client opens a unidi stream with data, server opens a unidi stream back and echoes data."),
	do_test(do_open_unidi_stream_test, Config).

do_open_unidi_stream_test(Config) ->
	do_start_listener(?FUNCTION_NAME, Config),
	{ok, Conn} = do_connect(?FUNCTION_NAME, Config),
	{ok, _LocalUnidiStreamID} = ?CLIENT:open_unidi_stream(Conn, <<"Hello">>),
	{unidi, PeerUnidiStreamID} = do_await_stream_opened(),
	{nofin, <<"Hello">>} = do_receive_data(PeerUnidiStreamID),
	?CLIENT:close(Conn).

peercert(Config) ->
	doc("Confirm QuicBackend:peercert/1 works as intended."),
	do_test(do_peercert_test, Config).

do_peercert_test(Config) ->
	do_start_listener(?FUNCTION_NAME, #{
		cacertfile => do_get_certs("ca.crt"),
		verify => peer
	}, Config),
	{ok, Conn} = do_connect(?FUNCTION_NAME, #{
		certfile => do_get_certs("client.crt"),
		keyfile => do_get_certs("client.key"),
		verify => peer
	}, Config),
	{ok, BidiStreamID} = ?CLIENT:open_bidi_stream(Conn, <<"TEST:peercert">>),
	{nofin, PeercertBin} = do_receive_data(BidiStreamID),
	Peercert = binary_to_term(PeercertBin),
	{ok, PemBin} = file:read_file(do_get_certs("client.crt")),
	PemEntries = public_key:pem_decode(PemBin),
	[ClientDer] = [Der || {'Certificate', Der, not_encrypted} <- PemEntries],
	true = Peercert =:= {ok, ClientDer},
	?CLIENT:close(Conn).

peername(Config) ->
	doc("Confirm QuicBackend:peername/1 works as intended."),
	do_test(do_peername_test, Config).

do_peername_test(Config) ->
	do_start_listener(?FUNCTION_NAME, Config),
	{ok, Conn} = do_connect(?FUNCTION_NAME, Config),
	{ok, BidiStreamID} = ?CLIENT:open_bidi_stream(Conn, <<"TEST:peername">>),
	{nofin, PeernameBin} = do_receive_data(BidiStreamID),
	Peername = binary_to_term(PeernameBin),
	Sockname = ?CLIENT:sockname(Conn),
	%% We currently can't bind the client socket in erlang_quic
	%% so quic:sockname/1 returns an IP of {0,0,0,0}. It won't
	%% match what the server sees. To work around that, we test
	%% IP/Port separately and only check that the IP the server
	%% sees is non-zeroes.
	%% @todo Note that this only applies to erlang_quic, quicer behaves differently.
	{ok, {PeerAddr, PeerPort}} = Peername,
	{ok, {_, SockPort}} = Sockname,
	true = PeerAddr =/= {0,0,0,0},
	true = PeerPort =:= SockPort,
	?CLIENT:close(Conn).

reset_stream_client(Config) ->
	doc("Start a listener, client opens stream and resets its side."),
	do_test(do_reset_stream_client_test, Config).

do_reset_stream_client_test(Config) ->
	do_start_listener(?FUNCTION_NAME, Config),
	{ok, Conn} = do_connect(?FUNCTION_NAME, Config),
	{ok, BidiStreamID} = ?CLIENT:open_bidi_stream(Conn, <<"Initial data.">>),
	{nofin, <<"Initial data.">>} = do_receive_data(BidiStreamID),
	ok = ?CLIENT:reset_stream(Conn, BidiStreamID, 123),
	%% Server can still send data.
	{nofin, <<"stream_reset:123">>} = do_receive_data(BidiStreamID),
	?CLIENT:close(Conn).

reset_stream_server(Config) ->
	doc("Start a listener, client opens stream, server resets its side."),
	do_test(do_reset_stream_server_test, Config).

do_reset_stream_server_test(Config) ->
	do_start_listener(?FUNCTION_NAME, Config),
	{ok, Conn} = do_connect(?FUNCTION_NAME, Config),
	{ok, BidiStreamID} = ?CLIENT:open_bidi_stream(Conn, <<"TEST:reset_stream">>),
	{stream_reset, BidiStreamID, 456} = do_await_stream_event(BidiStreamID),
	%% We can still send data.
	ok = ?CLIENT:send(Conn, BidiStreamID, [<<"TEST:ping_me ">>, pid_to_list(self())]),
	receive ping_me -> ok after 5000 -> error(timeout) end,
	?CLIENT:close(Conn).

send(Config) ->
	doc("Start a listener, client sends data to streams, server echoes it back."),
	do_test(do_send_test, Config).

do_send_test(Config) ->
	do_start_listener(?FUNCTION_NAME, Config),
	{ok, Conn} = do_connect(?FUNCTION_NAME, Config),
	{ok, BidiStreamID} = ?CLIENT:open_bidi_stream(Conn, <<"Initial data.">>),
	do_send_test1(Conn, BidiStreamID, BidiStreamID),
	%% @todo Figure out why this occasionally fails with quicer on the server without the timeout (race?).
	timer:sleep(100),
	{ok, LocalUnidiStreamID} = ?CLIENT:open_unidi_stream(Conn, <<"Initial data.">>),
	{unidi, PeerUnidiStreamID} = do_await_stream_opened(),
	do_send_test1(Conn, LocalUnidiStreamID, PeerUnidiStreamID),
	?CLIENT:close(Conn).

do_send_test1(Conn, SendStreamID, RecvStreamID) ->
	{nofin, <<"Initial data.">>} = do_receive_data(RecvStreamID),
	ok = ?CLIENT:send(Conn, SendStreamID, <<"Data sent by QuicBackend:send/3.">>),
	{nofin, <<"Data sent by QuicBackend:send/3.">>} = do_receive_data(RecvStreamID),
	ok = ?CLIENT:send(Conn, SendStreamID, nofin, <<"Data sent by QuicBackend:send/4 (nofin).">>),
	{nofin, <<"Data sent by QuicBackend:send/4 (nofin).">>} = do_receive_data(RecvStreamID),
	ok = ?CLIENT:send(Conn, SendStreamID, fin, <<"Data sent by QuicBackend:send/4 (fin).">>),
	{fin, <<"Data sent by QuicBackend:send/4 (fin).">>} = do_receive_data(RecvStreamID),
	ok.

send_datagram(Config) ->
	doc("Start a listener, client sends a datagram, server echoes it back."),
	do_test(do_send_datagram_test, Config).

do_send_datagram_test(Config) ->
	do_start_listener(?FUNCTION_NAME, #{
		max_datagram_frame_size => 1024
	}, Config),
	{ok, Conn} = do_connect(?FUNCTION_NAME, #{
		max_datagram_frame_size => 1024
	}, Config),
	ok = ?CLIENT:send_datagram(Conn, <<"Hello">>),
	{datagram, <<"Hello">>} = do_receive_datagram(),
	?CLIENT:close(Conn).

sockname(Config) ->
	doc("Confirm QuicBackend:sockname/1 works as intended."),
	do_test(do_sockname_test, Config).

do_sockname_test(Config) ->
	do_start_listener(?FUNCTION_NAME, Config),
	{ok, Conn} = do_connect(?FUNCTION_NAME, Config),
	{ok, BidiStreamID} = ?CLIENT:open_bidi_stream(Conn, <<"TEST:sockname">>),
	{nofin, SocknameBin} = do_receive_data(BidiStreamID),
	Sockname = binary_to_term(SocknameBin),
	Peername = ?CLIENT:peername(Conn),
	%% We currently don't configure an interface for the listener
	%% so quic:sockname/1 returns an IP of {0,0,0,0}. It won't
	%% match what the client sees. To work around that, we can
	%% only confirm that the Port matches.
	%% @todo Note that this only applies to erlang_quic, quicer behaves differently.
	{ok, {_, SockPort}} = Sockname,
	{ok, {_, PeerPort}} = Peername,
	true = SockPort =:= PeerPort,
	?CLIENT:close(Conn).

stop_sending_client(Config) ->
	doc("Start a listener, client opens stream and asks server to stop sending."),
	do_test(do_stop_sending_client_test, Config).

do_stop_sending_client_test(Config) ->
	do_start_listener(?FUNCTION_NAME, Config),
	{ok, Conn} = do_connect(?FUNCTION_NAME, Config),
	{ok, BidiStreamID} = ?CLIENT:open_bidi_stream(Conn, <<"Initial data.">>),
	{nofin, <<"Initial data.">>} = do_receive_data(BidiStreamID),
	ok = ?CLIENT:stop_sending(Conn, BidiStreamID, 123),
	%% Server sends a RESET_STREAM back but we do not expect the backend to forward it.
%	{stream_reset, BidiStreamID, 123} = do_await_stream_event(BidiStreamID),
	%% We can still send data.
	ok = ?CLIENT:send(Conn, BidiStreamID, [<<"TEST:ping_me ">>, pid_to_list(self())]),
	receive ping_me -> ok after 5000 -> error(timeout) end,
	?CLIENT:close(Conn).

stop_sending_server(Config) ->
	doc("Start a listener, client opens stream, server asks client to stop sending."),
	do_test(do_stop_sending_server_test, Config).

do_stop_sending_server_test(Config) ->
	do_start_listener(?FUNCTION_NAME, Config),
	{ok, Conn} = do_connect(?FUNCTION_NAME, Config),
	{ok, BidiStreamID} = ?CLIENT:open_bidi_stream(Conn, <<"TEST:stop_sending">>),
	%% Server sends STOP_SENDING. We can't send data anymore.
	{stream_stop_sending, BidiStreamID, 456} = do_await_stream_event(BidiStreamID),
	%% Server can still send data.
	{nofin, <<"More data.">>} = do_receive_data(BidiStreamID),
	?CLIENT:close(Conn).

%% Helpers.

do_test(TestCase, Config) ->
	try
		?MODULE:TestCase(Config)
	after
		_ = corral:stop_listener(TestCase)
	end.

do_start_listener(Ref, Config) ->
	do_start_listener(Ref, #{}, Config).

do_start_listener(Ref, QuicOpts, Config) ->
	DefaultOpts = #{
		alpn => [<<"corral">>],
		backend => do_get_backend(Config),
		certfile => do_get_certs("server.crt"),
		keyfile => do_get_certs("server.key")
	},
	{ok, _} = corral:start_listener(
		Ref,
		maps:merge(DefaultOpts, QuicOpts),
		corral_echo_protocol,
		opts),
	ok.

do_get_backend(Config) ->
	config(name, config(tc_group_properties, Config)).

do_get_certs(File) ->
	os:getenv("ERLANG_MK_TMP") ++ "/certs/" ++ File.

do_connect(Ref, Config) ->
	do_connect(Ref, #{}, Config).

do_connect(Ref, QuicOpts, _Config) ->
	Port = corral:get_port(Ref),
	?CLIENT:connect("127.0.0.1", Port, maps:merge(#{
		alpn => [<<"corral">>],
		cacertfile => do_get_certs("server.crt"),
		verify => none
	}, QuicOpts)).

do_await_stream_opened() ->
	Msg = do_await_quic_msg(),
	case ?CLIENT:make_event(Msg) of
		{stream_opened, StreamID, StreamType} ->
			{StreamType, StreamID};
		Event = {conn_closed, _, _} ->
			error({conn_closed, ?FUNCTION_NAME, Event});
		_ ->
			do_await_stream_opened()
	end.

do_receive_data(StreamID) ->
	Msg = do_await_quic_msg(),
	case ?CLIENT:make_event(Msg) of
		{stream_data, StreamID, IsFin, Data} ->
			{IsFin, Data};
		Event = {conn_closed, _, _} ->
			error({conn_closed, ?FUNCTION_NAME, Event});
		_ ->
			do_receive_data(StreamID)
	end.

do_await_stream_event(StreamID) ->
	Msg = do_await_quic_msg(),
	case ?CLIENT:make_event(Msg) of
		Event = {stream_reset, StreamID, _} ->
			Event;
		Event = {stream_stop_sending, StreamID, _} ->
			Event;
		Event = {conn_closed, _, _} ->
			error({conn_closed, ?FUNCTION_NAME, Event});
		_ ->
			do_await_stream_event(StreamID)
	end.

do_receive_datagram() ->
	Msg = do_await_quic_msg(),
	case ?CLIENT:make_event(Msg) of
		Event = {datagram, _} ->
			Event;
		Event = {conn_closed, _, _} ->
			error({conn_closed, ?FUNCTION_NAME, Event});
		_ ->
			do_receive_datagram()
	end.

do_await_conn_closed() ->
	Msg = do_await_quic_msg(),
	case ?CLIENT:make_event(Msg) of
		Event = {conn_closed, application, _} ->
			Event;
		Event = {conn_closed, transport, _} ->
			error({conn_closed, ?FUNCTION_NAME, Event});
		_ ->
			do_await_conn_closed()
	end.

do_await_quic_msg() ->
	receive Msg when element(1, Msg) =:= quic ->
		Msg
	after 5000 ->
		error({timeout, ?FUNCTION_NAME})
	end.
