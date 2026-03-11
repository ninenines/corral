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
-behaviour(corral_backend).

%% Servers.
-export([start_listener/3]).
-export([stop_listener/1]).
-export([handshake/1]).

%% Clients.
-export([connect/3]).

%% Connection.
-export([peername/1]).
-export([sockname/1]).
-export([peercert/1]).
-export([close/1]).
-export([close/2]).

%% Streams.
-export([open_bidi_stream/2]).
-export([open_unidi_stream/2]).
-export([send/3]).
-export([send/4]).
-export([send_datagram/2]).
-export([reset_stream/3]).
-export([stop_sending/3]).
-export([close_stream/3]).

%% Messages.
-export([make_event/1]).

-type conn() :: pid().
-export_type([conn/0]).

%% Servers.

-spec start_listener(corral:ref(), pid(), corral:quic_server_opts())
	-> supervisor:startchild_ret().

start_listener(Ref, ConnsSup, QuicOpts) ->
	Port = maps:get(port, QuicOpts, 0),
	BackendOpts0 = quic_server_opts_to_backend_opts(QuicOpts),
	BackendOpts = BackendOpts0#{
		connection_handler => fun(Conn) ->
			ProtoOpts = corral_ets:get_protocol_opts(Ref),
			corral_conns_sup:start_protocol(ConnsSup, ?MODULE, Conn, ProtoOpts)
		end
	},
	Ret = {ok, _} = quic:start_server(Ref, Port, BackendOpts),
	{ok, RealPort} = quic:get_server_port(Ref),
	corral_ets:set_port_and_backend(Ref, RealPort, ?MODULE),
	Ret.

quic_server_opts_to_backend_opts(QuicOpts) ->
	BackendOpts0 = maps:get(corral_quic_listen_opts, QuicOpts, #{}),
	BackendOpts1 = maps:with([alpn], QuicOpts),
	BackendOpts2 = maps:merge(BackendOpts0, BackendOpts1),
	BackendOpts3 = maybe_cert_and_chain(BackendOpts2, QuicOpts),
	BackendOpts4 = maybe_key(BackendOpts3, QuicOpts),
	BackendOpts = maybe_cacerts(BackendOpts4, QuicOpts),
	BackendOpts#{
		max_datagram_frame_size => maps:get(max_datagram_frame_size, QuicOpts, 0),
		max_streams_bidi => maps:get(max_streams_bidi, QuicOpts, 100),
		max_streams_uni => maps:get(max_streams_unidi, QuicOpts, 100),
		verify => maps:get(verify, QuicOpts, peer) =:= peer
	}.

maybe_cert_and_chain(BackendOpts, #{certfile := Certfile}) ->
	{Cert, CertChain} = case read_cert_file(Certfile) of
		[Cert0|CertChain0] -> {Cert0, CertChain0};
		[] -> {undefined, []}
	end,
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

maybe_cacerts(BackendOpts, #{cacertfile := CACertfile}) ->
	CACerts = read_cert_file(CACertfile),
	BackendOpts#{cacerts => CACerts};
maybe_cacerts(BackendOpts, _) ->
	BackendOpts.

%% Read certificate file (PEM) and convert to DER.
read_cert_file(Filename) ->
	{ok, PemBin} = file:read_file(Filename),
	PemEntries = public_key:pem_decode(PemBin),
	[Der || {'Certificate', Der, not_encrypted} <- PemEntries].

%% Read key file (PEM) and return the key.
read_key_file(Filename) ->
	{ok, PemBin} = file:read_file(Filename),
	[PemEntry|_] = public_key:pem_decode(PemBin),
	public_key:pem_entry_decode(PemEntry).

-spec stop_listener(corral:ref())
	-> ok | {error, not_found}.

stop_listener(Ref) ->
	case quic:stop_server(Ref) of
		ok -> ok;
		{error, {not_found, _}} -> {error, not_found}
	end.

-spec handshake(conn())
	-> {ok, #{alpn => binary()}}.

handshake(Conn) ->
	receive
		{quic, Conn, {connected, Info}} ->
			{ok, maps:with([alpn], Info)}
	%% @todo handle errors
	end.

%% Clients.

-spec connect(inet:ip_address() | inet:hostname(), inet:port_number(), corral:quic_client_opts())
	-> {ok, conn()}
	| {error, any()}.

connect(Address, Port, QuicOpts) ->
	BackendOpts = quic_client_opts_to_backend_opts(QuicOpts),
	case quic:connect(Address, Port, BackendOpts, self()) of
		{ok, Conn} ->
			case handshake(Conn) of
				{ok, _} ->
					{ok, Conn}
			end;
		Error ->
			Error
	end.

quic_client_opts_to_backend_opts(QuicOpts) ->
	ConnectOpts0 = maps:with([alpn], QuicOpts),
	ConnectOpts1 = maybe_cert_and_chain(ConnectOpts0, QuicOpts),
	ConnectOpts = maybe_key(ConnectOpts1, QuicOpts),
	ConnectOpts#{
		max_datagram_frame_size => maps:get(max_datagram_frame_size, QuicOpts, 0),
		max_streams_bidi => maps:get(max_streams_bidi, QuicOpts, 100),
		max_streams_unidi => maps:get(max_streams_unidi, QuicOpts, 100),
		verify => maps:get(verify, QuicOpts, peer) =:= peer
	}.

%% Connection.

-spec peername(conn())
	-> {ok, {inet:ip_address(), inet:port_number()}}
	| {error, any()}.

peername(Conn) ->
	quic:peername(Conn).

-spec sockname(conn())
	-> {ok, {inet:ip_address(), inet:port_number()}}
	| {error, any()}.

sockname(Conn) ->
	quic:sockname(Conn).

-spec peercert(conn())
	-> {ok, public_key:der_encoded()}
	| {error, any()}.

peercert(Conn) ->
	quic:peercert(Conn).

-spec close(conn())
	-> ok | {error, any()}.

close(Conn) ->
	close(Conn, 0).

-spec close(conn(), corral_backend:app_errno())
	-> ok | {error, any()}.

close(Conn, AppErrno) ->
	%% Work around an erlang_quic crash when exiting right after calling quic:close/2.
	unlink(Conn),
	quic:close(Conn, AppErrno).

%% Streams.

-spec open_bidi_stream(conn(), iodata())
	-> {ok, corral_backend:stream_id()}
	| {error, any()}.

open_bidi_stream(Conn, InitialData) ->
	case quic:open_stream(Conn) of
		{ok, StreamID} ->
			send_initial_data(Conn, InitialData, StreamID);
		Error ->
			Error
	end.

-spec open_unidi_stream(conn(), iodata())
	-> {ok, corral_backend:stream_id()}
	| {error, any()}.

open_unidi_stream(Conn, InitialData) ->
	case quic:open_unidirectional_stream(Conn) of
		{ok, StreamID} ->
			send_initial_data(Conn, InitialData, StreamID);
		Error ->
			Error
	end.

send_initial_data(Conn, InitialData, StreamID) ->
	case quic:send_data(Conn, StreamID, InitialData, false) of
		ok ->
			{ok, StreamID};
		Error ->
			Error
	end.

-spec send(conn(), corral_backend:stream_id(), iodata())
	-> ok | {error, any()}.

send(Conn, StreamID, Data) ->
	send(Conn, StreamID, nofin, Data).

-spec send(conn(), corral_backend:stream_id(), corral_backend:fin(), iodata())
	-> ok | {error, any()}.

send(Conn, StreamID, IsFin, Data) ->
	Fin = case IsFin of
		fin -> true;
		nofin -> false
	end,
	quic:send_data(Conn, StreamID, Data, Fin).

-spec reset_stream(conn(), corral_backend:stream_id(), corral_backend:app_errno())
	-> ok | {error, any()}.

reset_stream(Conn, StreamID, AppErrno) ->
	quic:reset_stream(Conn, StreamID, AppErrno).

-spec stop_sending(conn(), corral_backend:stream_id(), corral_backend:app_errno())
	-> ok | {error, any()}.

stop_sending(Conn, StreamID, AppErrno) ->
	quic:stop_sending(Conn, StreamID, AppErrno).

-spec close_stream(conn(), corral_backend:stream_id(), corral_backend:app_errno())
	-> ok | {error, any()}.

close_stream(Conn, StreamID, AppErrno) ->
	case quic:reset_stream(Conn, StreamID, AppErrno) of
		ok ->
			quic:stop_sending(Conn, StreamID, AppErrno);
		Error ->
			Error
	end.

%% Datagrams.

-spec send_datagram(conn(), iodata())
	-> ok | {error, any()}.

send_datagram(Conn, Data) ->
	quic:send_datagram(Conn, Data).

%% Messages.

-type quic_msg_event() ::
	{closed, any()}
	| {session_ticket, quic_ticket:session_ticket()}
	| {stream_opened, corral_backend:stream_id()}
	| {stream_data, corral_backend:stream_id(), binary(), boolean()}
	| {stream_reset, corral_backend:stream_id(), corral_backend:app_errno()}
	| {stop_sending, corral_backend:stream_id(), corral_backend:app_errno()}
	| {datagram, binary()}.

-spec make_event({quic, reference(), quic_msg_event()})
	-> {conn_closed, application, corral_backend:app_errno()}
	| {stream_opened, corral_backend:stream_id(), corral_backend:stream_type()} %% @todo Not currently returned. https://github.com/benoitc/erlang_quic/issues/17
	| {stream_data, corral_backend:stream_id(), corral_backend:fin(), binary()}
	| {stream_closed, corral_backend:stream_id(), corral_backend:app_errno()}
	| {datagram, binary()}
	| no_event
	| unknown_msg.

%% Connection closed by application.
make_event({quic, _Conn, {closed, _Reason}}) ->
	{conn_closed, application, undefined}; %% @todo We don't have the AppErrno from erlang_quic.
%% Connection closed by transport.
%% @todo erlang_quic documents a transport_error event but it's not implemented.
%% Session ticket received for 0-RTT resumption.
%% @todo Currently informational; could be stored for client implementations.
make_event({quic, _Conn, {session_ticket, _Ticket}}) ->
	no_event;
%% New stream opened by peer.
make_event({quic, _Conn, {stream_opened, StreamID}}) ->
	%% Determine stream type from ID (bit 1: 0=bidi, 1=unidi)
	StreamType = case StreamID band 2 of
		0 -> bidi;
		2 -> unidi
	end,
	{stream_opened, StreamID, StreamType};
%% Stream data received.
make_event({quic, _Conn, {stream_data, StreamID, Data, Fin}}) ->
	IsFin = case Fin of
		true -> fin;
		false -> nofin
	end,
	{stream_data, StreamID, IsFin, Data};
%% Stream reset by peer.
make_event({quic, _Conn, {stream_reset, StreamID, AppErrno}}) ->
	{stream_reset, StreamID, AppErrno};
%% Peer initiated shutdown of sending.
make_event({quic, _Conn, {stop_sending, StreamID, AppErrno}}) ->
	{stream_stop_sending, StreamID, AppErrno};
%% Datagram received.
make_event({quic, _Conn, {datagram, Data}}) ->
	{datagram, Data};
%% Unknown message.
make_event(_Msg) ->
	unknown_msg.
