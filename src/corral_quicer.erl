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

%% QUIC transport using the emqx/quicer NIF.

-module(corral_quicer).

-ifdef(BACKEND_QUICER).

%% Listeners.
-export([start_listener/5]).
-export([stop_listener/1]).
-export([handshake/1]).

%% Connection.
-export([peername/1]).
-export([sockname/1]).
-export([peercert/1]).
-export([shutdown/2]).

%% Streams.
-export([start_bidi_stream/2]).
-export([start_unidi_stream/2]).
-export([setopt/4]).
-export([send/3]).
-export([send/4]).
-export([send_datagram/2]).
-export([shutdown_stream/2]).
-export([shutdown_stream/4]).

%% Messages.
-export([make_event/1]).

%% @todo Make quicer export these types.
-type quicer_connection_handle() :: reference().
-export_type([quicer_connection_handle/0]).

-type quicer_app_errno() :: non_neg_integer().

-include_lib("quicer/include/quicer.hrl").

%% Listeners.

%% @todo QuicOpts so far:
%% #{
%%		port
%%		alpn => ["h3"], %% @todo binary tag
%%		certfile => "/home/essen/ninenines/cowboy/test/rfc9114_SUITE_data/server.pem",
%%		keyfile => "/home/essen/ninenines/cowboy/test/rfc9114_SUITE_data/server.key",
%%		max_streams_bidi,
%%		max_streams_unidi,
%%
%%		cert_chain?
%%		peer_unidi_stream_count => 10,
%%		peer_bidi_stream_count => 10
%%		connection_type?
%%		handshake_timeout?
%% }
%%
%% maps:with all compatible values, then case by case others needing type change etc.
%% BUT we also want to allow any other options like Ranch transports? Ranch transport allows them but they're not typed.
%% Easiest is likely an option field for any other passthrough options, perhaps a separate field (or fields) per backend.
%%
%% OK so standard opts + backend-specific opts such as corral_quic_opts, corral_quicer_listener_opts corral_quicer_stream_opts...
%% We will need a test for each of these options for each backend to ensure they behave the same.

%% @todo ProtoOpts must be in corral_server instead.
start_listener(Ref, ConnsSup, QuicOpts, Protocol, ProtoOpts) ->
	Port0 = maps:get(port, QuicOpts, 0),
	Port = case Port0 of
		0 -> port_0();
		_ -> Port0
	end,
	%% @todo Port must be stored/retrieved.
	persistent_term:put({corral, Ref}, #{port => Port, backend => ?MODULE}),
	{ListenOpts, ConnOpts, StreamOpts} = quic_opts_to_backend_opts(QuicOpts),
	BackendOpts = {
		ListenOpts#{
			conn_acceptors => 16 %% @todo Configurable?
		},
		ConnOpts#{
			conn_callback => corral_quicer_cb,
			user_opts => #{
				ref => Ref,
				conns_sup => ConnsSup,
				protocol => Protocol, %% @todo Used?
				protocol_opts => ProtoOpts %% @todo Take dynamically so it can be updated.
			}
		},
		StreamOpts#{
			active => true
		}
	},
	%% @todo First argument must be atom, really?
	quicer:spawn_listener(Ref, Port, BackendOpts).

quic_opts_to_backend_opts(QuicOpts) ->
	ListenOpts0 = maps:get(corral_quicer_listen_opts, QuicOpts, #{}),
	ConnOpts = maps:get(corral_quicer_conn_opts, QuicOpts, #{}),
	StreamOpts = maps:get(corral_quicer_stream_opts, QuicOpts, #{}),
	ListenOpts1 = maps:with([
		alpn,
		certfile,
		keyfile
	], QuicOpts),
	ListenOpts2 = maps:merge(ListenOpts0, ListenOpts1),
	ListenOpts3 = maybe_fix_alpn(ListenOpts2),
	ListenOpts = ListenOpts3#{
		peer_bidi_stream_count => maps:get(max_streams_bidi, QuicOpts, 100),
		peer_unidi_stream_count => maps:get(max_streams_unidi, QuicOpts, 100)
	},
	{ListenOpts, ConnOpts, StreamOpts}.

%% Quicer expects lists for ALPN tokens.
maybe_fix_alpn(Opts=#{alpn := ALPN}) ->
	Opts#{alpn => [binary_to_list(N) || N <- ALPN]};
maybe_fix_alpn(Opts) ->
	Opts.

%% Select a random UDP port using gen_udp because quicer
%% does not provide equivalent functionality. Taken from
%% quicer test suites.
port_0() ->
	{ok, Socket} = gen_udp:open(0, [{reuseaddr, true}]),
	{ok, {_, Port}} = inet:sockname(Socket),
	gen_udp:close(Socket),
	case os:type() of
		{unix, darwin} ->
			%% Apparently macOS doesn't free the port immediately.
			timer:sleep(500);
		_ ->
			ok
	end,
	Port.

%% @todo -spec stop_listener(ref()) -> ok | {error, not_found}.

-dialyzer([{nowarn_function, stop_listener/1}]).

stop_listener(Ref) ->
	case quicer:terminate_listener(Ref) of
		ok -> ok;
		{error, not_found} -> {error, not_found}
	end.

-spec handshake(quicer_connection_handle())
	-> {ok, #{alpn => binary()}}.

handshake(Conn) ->
	receive
		{quic, connected, Conn, Props} ->
			Info = case Props of
				#{alpns := ALPN} -> #{alpn => ALPN};
				_ -> #{}
			end,
			{ok, Info}
	%% @todo We probably need to have a timeout or to receive errors.
	end.

%% Connection.

-spec peername(quicer_connection_handle())
	-> {ok, {inet:ip_address(), inet:port_number()}}
	| {error, any()}.

peername(Conn) ->
	quicer:peername(Conn).

-spec sockname(quicer_connection_handle())
	-> {ok, {inet:ip_address(), inet:port_number()}}
	| {error, any()}.

sockname(Conn) ->
	quicer:sockname(Conn).

-spec peercert(quicer_connection_handle())
	-> {ok, public_key:der_encoded()}
	| {error, any()}.

peercert(Conn) ->
	quicer_nif:peercert(Conn).

-spec shutdown(quicer_connection_handle(), quicer_app_errno())
	-> ok | {error, any()}.

shutdown(Conn, ErrorCode) ->
	quicer:shutdown_connection(Conn,
		?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
		ErrorCode).

%% Streams.

-spec start_bidi_stream(quicer_connection_handle(), iodata())
	-> {ok, corral:stream_id()}
	| {error, any()}.

start_bidi_stream(Conn, InitialData) ->
	start_stream(Conn, InitialData, ?QUIC_STREAM_OPEN_FLAG_NONE).

-spec start_unidi_stream(quicer_connection_handle(), iodata())
	-> {ok, corral:stream_id()}
	| {error, any()}.

start_unidi_stream(Conn, InitialData) ->
	start_stream(Conn, InitialData, ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL).

start_stream(Conn, InitialData, OpenFlag) ->
	case quicer:start_stream(Conn, #{
			active => true,
			open_flag => OpenFlag}) of
		{ok, StreamRef} ->
			case quicer:send(StreamRef, InitialData) of
				{ok, _} ->
					{ok, StreamID} = quicer:get_stream_id(StreamRef),
					put({quicer_stream, StreamID}, StreamRef),
					{ok, StreamID};
				Error ->
					Error
			end;
		{error, Reason1, Reason2} ->
			{error, {Reason1, Reason2}};
		Error ->
			Error
	end.

-spec setopt(quicer_connection_handle(), corral:stream_id(), active, boolean())
	-> ok | {error, any()}.

setopt(_Conn, StreamID, active, Value) ->
	StreamRef = get({quicer_stream, StreamID}),
	quicer:setopt(StreamRef, active, Value).

-spec send(quicer_connection_handle(), corral:stream_id(), iodata())
	-> ok | {error, any()}.

send(Conn, StreamID, Data) ->
	send(Conn, StreamID, Data, nofin).

-spec send(quicer_connection_handle(), corral:stream_id(), iodata(), corral:fin())
	-> ok | {error, any()}.

send(_Conn, StreamID, Data, IsFin) ->
	StreamRef = get({quicer_stream, StreamID}),
	Size = iolist_size(Data),
	case quicer:send(StreamRef, Data, send_flag(IsFin)) of
		{ok, Size} ->
			ok;
		{error, Reason1, Reason2} ->
			{error, {Reason1, Reason2}};
		Error ->
			Error
	end.

send_flag(nofin) -> ?QUIC_SEND_FLAG_NONE;
send_flag(fin) -> ?QUIC_SEND_FLAG_FIN.

-spec send_datagram(quicer_connection_handle(), iodata())
	-> ok | {error, any()}.

send_datagram(Conn, Data) ->
	%% @todo Fix/ignore the Dialyzer error instead of doing this.
	DataBin = iolist_to_binary(Data),
	Size = byte_size(DataBin),
	case quicer:send_dgram(Conn, DataBin) of
		{ok, Size} ->
			ok;
		%% @todo Handle error cases.
		Error ->
			Error
	end.

-spec shutdown_stream(quicer_connection_handle(), corral:stream_id())
	-> ok.

shutdown_stream(_Conn, StreamID) ->
	StreamRef = get({quicer_stream, StreamID}),
	_ = quicer:shutdown_stream(StreamRef),
	ok.

-spec shutdown_stream(quicer_connection_handle(),
	corral:stream_id(), both | receiving, quicer_app_errno())
	-> ok.

shutdown_stream(_Conn, StreamID, Dir, ErrorCode) ->
	StreamRef = get({quicer_stream, StreamID}),
	_ = quicer:shutdown_stream(StreamRef, shutdown_flag(Dir), ErrorCode, infinity),
	ok.

%% @todo Are these flags correct for what we want?
shutdown_flag(both) -> ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT;
shutdown_flag(receiving) -> ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE.

%% Messages.

-spec make_event({quic, _, _, _})
	-> {stream_data, corral:stream_id(), corral:fin(), binary()}
	| {datagram, binary()}
	| {stream_started, corral:stream_id(), unidi | bidi}
	| {stream_closed, corral:stream_id(), quicer_app_errno()}
	| closed
	| {peer_send_shutdown, corral:stream_id()}
	| ok
	| unknown
	| {socket_error, any()}.

make_event({quic, Data, StreamRef, #{flags := Flags}}) when is_binary(Data) ->
	{ok, StreamID} = quicer:get_stream_id(StreamRef),
	IsFin = case Flags band ?QUIC_RECEIVE_FLAG_FIN of
		?QUIC_RECEIVE_FLAG_FIN -> fin;
		_ -> nofin
	end,
	{stream_data, StreamID, IsFin, Data};
make_event({quic, Data, _Conn, Flags}) when is_binary(Data), is_integer(Flags) ->
	{datagram, Data};
%% QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED.
make_event({quic, new_stream, StreamRef, #{flags := Flags}}) ->
	case quicer:setopt(StreamRef, active, true) of
		ok ->
			{ok, StreamID} = quicer:get_stream_id(StreamRef),
			put({quicer_stream, StreamID}, StreamRef),
			StreamType = case quicer:is_unidirectional(Flags) of
				true -> unidi;
				false -> bidi
			end,
			{stream_started, StreamID, StreamType};
		{error, Reason} ->
			{socket_error, Reason}
	end;
%% QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE.
make_event({quic, stream_closed, StreamRef, #{error := ErrorCode}}) ->
	{ok, StreamID} = quicer:get_stream_id(StreamRef),
	{stream_closed, StreamID, ErrorCode};
%% QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE.
make_event({quic, closed, Conn, _Flags}) ->
	_ = quicer:close_connection(Conn),
	closed;
%% The following events are currently ignored either because
%% I do not know what they do or because we do not need to
%% take action.
make_event({quic, streams_available, _Conn, _Props}) ->
	ok;
make_event({quic, dgram_state_changed, _Conn, _Props}) ->
	ok;
%% QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT
make_event({quic, transport_shutdown, _Conn, _Flags}) ->
	ok;
make_event({quic, peer_send_shutdown, StreamRef, undefined}) ->
	{ok, StreamID} = quicer:get_stream_id(StreamRef),
	{peer_send_shutdown, StreamID};
make_event({quic, send_shutdown_complete, _StreamRef, _IsGraceful}) ->
	ok;
make_event({quic, shutdown, _Conn, success}) ->
	ok;
make_event(_Msg) ->
	unknown.

-endif.
