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

-ifdef(BACKEND_ERLANG_QUIC).
-define(SKIP_CORRAL_QUIC, false).
-else.
-define(SKIP_CORRAL_QUIC, true).
-endif.

-ifdef(BACKEND_QUICER).
-define(SKIP_CORRAL_QUICER, false).
-else.
-define(SKIP_CORRAL_QUICER, true).
-endif.

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
	Config.

end_per_suite(_Config) ->
	ok.

init_per_group(corral_quic, _) when ?SKIP_CORRAL_QUIC ->
	{skip, "Corral compiled without support for erlang_quic."};
init_per_group(corral_quicer, _) when ?SKIP_CORRAL_QUICER ->
	{skip, "Corral compiled without support for quicer."};
init_per_group(_, Config) ->
	Config.

end_per_group(_, _) ->
	ok.

%% Tests.

start_stop(Config) ->
	try
		{ok, _} = corral:start_listener(
			?FUNCTION_NAME,
			do_get_backend(Config),
			#{
				alpn => [<<"corral">>],
				certfile => do_get_certs("server.crt"),
				keyfile => do_get_certs("server.key")
			},
			corral_echo_protocol,
			opts),
		#{port := Port} = persistent_term:get({corral, ?FUNCTION_NAME}),
		ct:pal("connecting to port ~p", [Port]),
		%% @todo Note that using "localhost" currently fails to connect for me
		%%       (seems to default to ipv6) when using erlang_quic listener.
		%%       Need to make separate v4/v6 tests to make sure it works for both.
		{ok, Conn} = quic:connect("127.0.0.1", Port,
			#{alpn => [<<"corral">>], verify => false
			}, self()),
		do_await_connected(Conn),
		%% Create a bidi stream, send Hello, get Hello back.
		{ok, BidiStreamID} = quic:open_stream(Conn),
		ok = do_send_data(Conn, BidiStreamID, <<"Hello">>, nofin),
		{nofin, <<"Hello">>} = do_receive_data(Conn, BidiStreamID),
		quic:close(Conn, 0)
	after
		ok = corral:stop_listener(?FUNCTION_NAME)
	end.

%% Helpers.

do_get_backend(Config) ->
	config(name, config(tc_group_properties, Config)).

do_get_certs(File) ->
	os:getenv("ERLANG_MK_TMP") ++ "/certs/" ++ File.

do_await_connected(Conn) ->
	receive {quic, Conn, {connected, _}} ->
		ok
	after 5000 ->
		error({timeout, waiting_for_connected})
	end.

do_send_data(Conn, StreamID, Data, IsFin) ->
	quic:send_data(Conn, StreamID, Data, IsFin =:= fin).

do_receive_data(Conn, StreamID) ->
	receive {quic, Conn, {stream_data, StreamID, Data, IsFin0}} ->
		IsFin = case IsFin0 of
			true -> fin;
			_ -> nofin
		end,
		{IsFin, Data}
	after 5000 ->
		error({timeout, waiting_for_data})
	end.
