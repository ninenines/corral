%% Copyright (c) Loic Hoguin <essen@ninenines.eu>
%% Copyright (c) Benoit Chesneau <bchesneau@gmail.com>
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

%% QUIC transport using the pure Erlang erlang_quic library.

-module(corral_quic).

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

-type quic_connection_handle() :: reference().
-export_type([quic_connection_handle/0]).

-type app_errno() :: non_neg_integer().

%% Listeners.

%% @todo Protocol not used I think.
%% @todo ProtoOpts must be in corral_server instead.
start_listener(Ref, ConnsSup, QuicOpts, _Protocol, ProtoOpts) ->
	Port = maps:get(port, QuicOpts, 0),
	BackendOpts0 = quic_opts_to_backend_opts(QuicOpts),
	BackendOpts = BackendOpts0#{
		connection_handler => fun(_, Conn) ->
			corral_conns_sup:start_protocol(ConnsSup, ?MODULE, Conn, ProtoOpts)
		end
	},
	Ret = {ok, _} = quic:start_server(Ref, Port, BackendOpts),
	{ok, RealPort} = quic:get_server_port(Ref),
	persistent_term:put({corral, Ref}, #{port => RealPort, backend => ?MODULE}),
	Ret.

quic_opts_to_backend_opts(QuicOpts) ->
	BackendOpts0 = maps:get(corral_quic_listen_opts, QuicOpts, #{}),
	BackendOpts1 = maps:with([alpn], QuicOpts),
	BackendOpts2 = maps:merge(BackendOpts0, BackendOpts1),
	BackendOpts3 = maybe_cert_and_chain(BackendOpts2, QuicOpts),
	BackendOpts = maybe_key(BackendOpts3, QuicOpts),
	BackendOpts#{
		max_streams_bidi => maps:get(max_streams_bidi, QuicOpts, 100),
		max_streams_uni => maps:get(max_streams_unidi, QuicOpts, 100)
	}.

maybe_cert_and_chain(BackendOpts, #{certfile := Certfile}) ->
	{Cert, CertChain} = read_cert_file(Certfile),
	BackendOpts#{
		cert => Cert,
		cert_chain => CertChain
	};
maybe_cert_and_chain(BackendOpts, _) ->
	BackendOpts.

maybe_key(BackendOpts, #{keyfile := Keyfile}) ->
	BackendOpts#{
		key => read_key_file(Keyfile)
	};
maybe_key(BackendOpts, _) ->
	BackendOpts.

%% Read certificate file (PEM) and convert to DER.
read_cert_file(Filename) ->
	{ok, PemBin} = file:read_file(Filename),
	PemEntries = public_key:pem_decode(PemBin),
	Certs = [Der || {'Certificate', Der, not_encrypted} <- PemEntries],
	case Certs of
		[Cert|Chain] -> {Cert, Chain};
		[] -> {undefined, []}
	end.

%% Read key file (PEM) and return the key.
read_key_file(Filename) ->
	{ok, PemBin} = file:read_file(Filename),
	[PemEntry|_] = public_key:pem_decode(PemBin),
	public_key:pem_entry_decode(PemEntry).

%% @todo -spec stop_listener(ref()) -> ok | {error, not_found}.

stop_listener(Ref) ->
	case quic:stop_server(Ref) of
		ok -> ok;
		{error, {not_found, _}} -> {error, not_found}
	end.

-spec handshake(quic_connection_handle())
	-> {ok, #{alpn => binary()}}.

handshake(Conn) ->
	receive
		{quic, Conn, {connected, Info}} ->
			{ok, maps:with([alpn], Info)}
	%% @todo We probably need to have a timeout or to receive errors.
	end.

%% Connection.

-spec peername(quic_connection_handle())
	-> {ok, {inet:ip_address(), inet:port_number()}}
	| {error, any()}.

peername(Conn) ->
	quic:peername(Conn).

-spec sockname(quic_connection_handle())
	-> {ok, {inet:ip_address(), inet:port_number()}}
	| {error, any()}.

sockname(Conn) ->
	quic:sockname(Conn).

-spec peercert(quic_connection_handle())
	-> {ok, public_key:der_encoded()}
	| {error, any()}.

peercert(Conn) ->
	quic:peercert(Conn).

-spec shutdown(quic_connection_handle(), app_errno())
	-> ok | {error, any()}.

shutdown(Conn, ErrorCode) ->
	quic:close(Conn, ErrorCode).

%% Streams.

-spec start_bidi_stream(quic_connection_handle(), iodata())
	-> {ok, corral:stream_id()}
	| {error, any()}.

start_bidi_stream(Conn, InitialData) ->
	case quic:open_stream(Conn) of
		{ok, StreamID} ->
			case quic:send_data(Conn, StreamID, InitialData, false) of
				ok ->
					{ok, StreamID};
				Error ->
					Error
			end;
		Error ->
			Error
	end.

-spec start_unidi_stream(quic_connection_handle(), iodata())
	-> {ok, corral:stream_id()}
	| {error, any()}.

start_unidi_stream(Conn, InitialData) ->
	case quic:open_unidirectional_stream(Conn) of
		{ok, StreamID} ->
			case quic:send_data(Conn, StreamID, InitialData, false) of
				ok ->
					{ok, StreamID};
				Error ->
					Error
			end;
		Error ->
			Error
	end.

-spec setopt(quic_connection_handle(), corral:stream_id(), active, boolean())
	-> ok | {error, any()}.

setopt(Conn, _StreamID, active, _Value) ->
	%% erlang_quic uses process messages, always active
	%% Set connection-level options if needed
	quic:setopts(Conn, []).

-spec send(quic_connection_handle(), corral:stream_id(), iodata())
	-> ok | {error, any()}.

send(Conn, StreamID, Data) ->
	send(Conn, StreamID, Data, nofin).

-spec send(quic_connection_handle(), corral:stream_id(), iodata(), corral:fin())
	-> ok | {error, any()}.

send(Conn, StreamID, Data, IsFin) ->
	Fin = case IsFin of
		fin -> true;
		nofin -> false
	end,
	quic:send_data(Conn, StreamID, Data, Fin).

-spec send_datagram(quic_connection_handle(), iodata())
	-> ok | {error, any()}.

send_datagram(Conn, Data) ->
	quic:send_datagram(Conn, Data).

-spec shutdown_stream(quic_connection_handle(), corral:stream_id())
	-> ok.

shutdown_stream(Conn, StreamID) ->
	_ = quic:reset_stream(Conn, StreamID, 0),
	ok.

-spec shutdown_stream(quic_connection_handle(),
	corral:stream_id(), both | receiving, app_errno())
	-> ok.

shutdown_stream(Conn, StreamID, _Dir, ErrorCode) ->
	_ = quic:reset_stream(Conn, StreamID, ErrorCode),
	ok.

%% Messages.
%%
%% Translate erlang_quic messages to cowboy_quic format.
%%
%% erlang_quic format:
%%   {quic, ConnRef, {stream_data, StreamId, Data, Fin}}
%%   {quic, ConnRef, {stream_opened, StreamId}}
%%   {quic, ConnRef, {stream_reset, StreamId, ErrorCode}}
%%   {quic, ConnRef, {closed, Reason}}
%%   {quic, ConnRef, {stop_sending, StreamId, ErrorCode}}
%%   {quic, ConnRef, {datagram, Data}}
%%
%% cowboy_quic format:
%%   {data, StreamID, fin|nofin, Data}
%%   {datagram, Data}
%%   {stream_started, StreamID, unidi|bidi}
%%   {stream_closed, StreamID, ErrorCode}
%%   closed
%%   {peer_send_shutdown, StreamID}

-spec make_event({quic, reference(), term()})
	-> {stream_data, corral:stream_id(), corral:fin(), binary()}
	| {datagram, binary()}
	| {stream_started, corral:stream_id(), unidi | bidi}
	| {stream_closed, corral:stream_id(), app_errno()}
	| {goaway, corral:stream_id()}
	| {transport_error, non_neg_integer(), binary()}
	| {send_ready, corral:stream_id()}
	| closed
	| {peer_send_shutdown, corral:stream_id()}
	| ok
	| unknown.

%% Stream data received.
make_event({quic, _ConnRef, {stream_data, StreamID, Data, Fin}}) ->
	IsFin = case Fin of
		true -> fin;
		false -> nofin
	end,
	{stream_data, StreamID, IsFin, Data};

%% Datagram received.
make_event({quic, _ConnRef, {datagram, Data}}) ->
	{datagram, Data};

%% New stream opened by peer.
make_event({quic, _ConnRef, {stream_opened, StreamID}}) ->
	%% Determine stream type from ID (bit 1: 0=bidi, 1=unidi)
	StreamType = case StreamID band 2 of
		0 -> bidi;
		2 -> unidi
	end,
	{stream_started, StreamID, StreamType};

%% Stream reset by peer.
make_event({quic, _ConnRef, {stream_reset, StreamID, ErrorCode}}) ->
	{stream_closed, StreamID, ErrorCode};

%% Connection closed.
make_event({quic, _ConnRef, {closed, _Reason}}) ->
	closed;

%% Peer initiated shutdown of sending.
make_event({quic, _ConnRef, {stop_sending, StreamID, _ErrorCode}}) ->
	{peer_send_shutdown, StreamID};

%% Connection established (server receives this after handshake).
%% This is informational; the connection is already set up.
make_event({quic, _ConnRef, {connected, _Info}}) ->
	ok;

%% Transport error received from peer or detected locally.
%% Forward to cowboy_http3 for proper connection termination.
make_event({quic, _ConnRef, {transport_error, Code, Reason}}) ->
	{transport_error, Code, Reason};

%% GoAway received from peer - graceful shutdown initiated.
make_event({quic, _ConnRef, {goaway, LastStreamID}}) ->
	{goaway, LastStreamID};

%% Session ticket received for 0-RTT resumption.
%% Currently informational; could be stored for client implementations.
make_event({quic, _ConnRef, {session_ticket, _Ticket}}) ->
	ok;

%% Stream ready to send - flow control signal.
%% Forward to allow cowboy_http3 to resume sending on this stream.
make_event({quic, _ConnRef, {send_ready, StreamID}}) ->
	{send_ready, StreamID};

%% Timer notification for internal QUIC timers.
%% Handled internally by erlang_quic.
make_event({quic, _ConnRef, {timer, _NextTimeoutMs}}) ->
	ok;

%% Unknown message - let cowboy_http3 decide how to handle.
make_event(_Msg) ->
	unknown.
