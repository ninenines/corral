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
-behaviour(corral_backend).

-ifdef(BACKEND_QUICER).

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

%% @todo Make quicer export these types.
-type conn() :: reference().
-export_type([conn/0]).

-include_lib("quicer/include/quicer.hrl").

%% Servers.

-spec start_listener(corral:ref(), pid(), corral:quic_server_opts())
	-> supervisor:startchild_ret().

start_listener(Ref, ConnsSup, QuicOpts) ->
	Port0 = maps:get(port, QuicOpts, 0),
	Port = case Port0 of
		0 -> port_0();
		_ -> Port0
	end,
	{ListenOpts, ConnOpts, StreamOpts} = quic_server_opts_to_backend_opts(QuicOpts),
	BackendOpts = {
		ListenOpts#{
			conn_acceptors => 16 %% @todo Configurable?
		},
		ConnOpts#{
			conn_callback => corral_quicer_cb,
			user_opts => #{
				ref => Ref,
				conns_sup => ConnsSup
			}
		},
		StreamOpts#{
			active => true
		}
	},
	%% @todo First argument must be atom, really?
	Ret = {ok, _} = quicer:spawn_listener(Ref, Port, BackendOpts),
	corral_ets:set_port_and_backend(Ref, Port, ?MODULE),
	Ret.

quic_server_opts_to_backend_opts(QuicOpts) ->
	ListenOpts0 = maps:get(corral_quicer_listen_opts, QuicOpts, #{}),
	ConnOpts = maps:get(corral_quicer_conn_opts, QuicOpts, #{}),
	StreamOpts = maps:get(corral_quicer_stream_opts, QuicOpts, #{}),
	ListenOpts1 = maps:with([
		alpn,
		cacertfile,
		certfile,
		keyfile
	], QuicOpts),
	ListenOpts2 = maps:merge(ListenOpts0, ListenOpts1),
	ListenOpts3 = maybe_fix_alpn(ListenOpts2),
	ListenOpts = ListenOpts3#{
		%% @todo Figure out how to configure a size.
		datagram_receive_enabled => datagram_receive_enabled(QuicOpts),
		peer_bidi_stream_count => maps:get(max_streams_bidi, QuicOpts, 100),
		peer_unidi_stream_count => maps:get(max_streams_unidi, QuicOpts, 100),
		verify => maps:get(verify, QuicOpts, peer)
	},
	{ListenOpts, ConnOpts, StreamOpts}.

%% Quicer expects lists for ALPN tokens.
maybe_fix_alpn(Opts=#{alpn := ALPN}) ->
	Opts#{alpn => [binary_to_list(N) || N <- ALPN]};
maybe_fix_alpn(Opts) ->
	Opts.

datagram_receive_enabled(#{max_datagram_frame_size := Size}) when Size > 0 ->
	1;
datagram_receive_enabled(_) ->
	0.

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

-spec stop_listener(corral:ref())
	-> ok | {error, not_found}.

-dialyzer([{nowarn_function, stop_listener/1}]).

stop_listener(Ref) ->
	case quicer:terminate_listener(Ref) of
		ok -> ok;
		{error, not_found} -> {error, not_found}
	end.

-spec handshake(conn())
	-> {ok, #{alpn => binary()}}.

handshake(Conn) ->
	receive
		{quic, connected, Conn, Props} ->
			Info = case Props of
				#{alpns := ALPN} -> #{alpn => ALPN};
				_ -> #{}
			end,
			{ok, Info}
	%% @todo handle errors
	end.

%% Clients.

-spec connect(inet:ip_address() | inet:hostname(), inet:port_number(), corral:quic_client_opts())
	-> {ok, conn()}
	| {error, any()}.

connect(Address, Port, QuicOpts) ->
	BackendOpts = quic_client_opts_to_backend_opts(QuicOpts),
	Timeout = maps:get(connect_timeout, QuicOpts, infinity),
	case quicer:connect(Address, Port, BackendOpts, Timeout) of
		{ok, Conn} ->
			%% @todo How to get the ALPN back? We should also return it.
			{ok, Conn};
		{error, Reason} ->
			{error, Reason};
		{error, transport_down, #{error := 2, status := connection_refused}} ->
			{error, econnrefused};
		{error, Reason, Flags} ->
			{error, {Reason, Flags}}
	end.

quic_client_opts_to_backend_opts(QuicOpts) ->
	ConnectOpts0 = maps:with([
		alpn,
		cacertfile,
		certfile,
		keyfile
	], QuicOpts),
	ConnectOpts = maybe_fix_alpn(ConnectOpts0),
	ConnectOpts#{
		%% @todo Figure out how to configure a size.
		datagram_receive_enabled => datagram_receive_enabled(QuicOpts),
		peer_bidi_stream_count => maps:get(max_streams_bidi, QuicOpts, 100),
		peer_unidi_stream_count => maps:get(max_streams_unidi, QuicOpts, 100),
		verify => maps:get(verify, QuicOpts, peer)
	}.

%% Connection.

-spec peername(conn())
	-> {ok, {inet:ip_address(), inet:port_number()}}
	| {error, any()}.

peername(Conn) ->
	quicer:peername(Conn).

-spec sockname(conn())
	-> {ok, {inet:ip_address(), inet:port_number()}}
	| {error, any()}.

sockname(Conn) ->
	quicer:sockname(Conn).

-spec peercert(conn())
	-> {ok, public_key:der_encoded()}
	| {error, any()}.

peercert(Conn) ->
	quicer_nif:peercert(Conn).

-spec close(conn())
	-> ok | {error, any()}.

close(Conn) ->
	close(Conn, 0).

-spec close(conn(), corral_backend:app_errno())
	-> ok | {error, any()}.

close(Conn, AppErrno) ->
	quicer:shutdown_connection(Conn,
		?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
		AppErrno).

%% Streams.

-spec open_bidi_stream(conn(), iodata())
	-> {ok, corral_backend:stream_id()}
	| {error, any()}.

open_bidi_stream(Conn, InitialData) ->
	start_stream(Conn, InitialData, ?QUIC_STREAM_OPEN_FLAG_NONE).

-spec open_unidi_stream(conn(), iodata())
	-> {ok, corral_backend:stream_id()}
	| {error, any()}.

open_unidi_stream(Conn, InitialData) ->
	start_stream(Conn, InitialData, ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL).

start_stream(Conn, InitialData, OpenFlag) ->
	case quicer:start_stream(Conn, #{
			active => true,
			open_flag => OpenFlag}) of
		{ok, StreamRef} ->
			case quicer:send(StreamRef, InitialData) of
				{ok, _} ->
					{ok, StreamID} = quicer:get_stream_id(StreamRef),
					put({?MODULE, StreamID}, StreamRef),
					{ok, StreamID};
				Error ->
					Error
			end;
		{error, Reason1, Reason2} ->
			{error, {Reason1, Reason2}};
		Error ->
			Error
	end.

-spec send(conn(), corral_backend:stream_id(), iodata())
	-> ok | {error, any()}.

send(Conn, StreamID, Data) ->
	send(Conn, StreamID, nofin, Data).

-spec send(conn(), corral_backend:stream_id(), corral_backend:fin(), iodata())
	-> ok | {error, any()}.

send(_Conn, StreamID, IsFin, Data) ->
	StreamRef = get({?MODULE, StreamID}),
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

-spec reset_stream(conn(), corral_backend:stream_id(), corral_backend:app_errno())
	-> ok | {error, any()}.

reset_stream(_Conn, StreamID, AppErrno) ->
	StreamRef = get({?MODULE, StreamID}),
	quicer:async_shutdown_stream(StreamRef,
		?QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND,
		AppErrno).

-spec stop_sending(conn(), corral_backend:stream_id(), corral_backend:app_errno())
	-> ok | {error, any()}.

stop_sending(_Conn, StreamID, AppErrno) ->
	StreamRef = get({?MODULE, StreamID}),
	quicer:async_shutdown_stream(StreamRef,
		?QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
		AppErrno).

-spec close_stream(conn(), corral_backend:stream_id(), corral_backend:app_errno())
	-> ok | {error, any()}.

close_stream(_Conn, StreamID, AppErrno) ->
	StreamRef = get({?MODULE, StreamID}),
	quicer:async_shutdown_stream(StreamRef,
		?QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
		AppErrno).

%% Datagrams.

-spec send_datagram(conn(), iodata())
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

%% Messages.

-type quicer_msg() :: {quic, _, _, _}. %% @todo Be more precise.

-spec make_event(quicer_msg())
	-> {conn_closed, transport, non_neg_integer()} %% @todo Better error type? QUIC error.
	| {conn_closed, application, corral_backend:app_errno()}
	| {stream_opened, corral_backend:stream_id(), corral_backend:stream_type()}
	| {stream_data, corral_backend:stream_id(), corral_backend:fin(), binary()}
	| {stream_reset, corral_backend:stream_id(), corral_backend:app_errno()}
	| {stream_stop_sending, corral_backend:stream_id(), corral_backend:app_errno()}
	| {datagram, binary()}
	| no_event
	| unknown_msg
	| {error, any()}. %% @todo We may want to be more precise about some errors.

%% QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED.
make_event({quic, new_stream, StreamRef, #{flags := Flags}}) ->
	case quicer:setopt(StreamRef, active, true) of
		ok ->
			{ok, StreamID} = quicer:get_stream_id(StreamRef),
			put({?MODULE, StreamID}, StreamRef),
			StreamType = case quicer:is_unidirectional(Flags) of
				true -> unidi;
				false -> bidi
			end,
			{stream_opened, StreamID, StreamType};
		{error, Reason} ->
			{error, {setopt_error, Reason}}
	end;
%% QUIC_STREAM_EVENT_RECEIVE.
make_event({quic, Data, StreamRef, #{flags := Flags}}) when is_binary(Data) ->
	{ok, StreamID} = quicer:get_stream_id(StreamRef),
	IsFin = case Flags band ?QUIC_RECEIVE_FLAG_FIN of
		?QUIC_RECEIVE_FLAG_FIN -> fin;
		_ -> nofin
	end,
	{stream_data, StreamID, IsFin, Data};
%% QUIC_STREAM_EVENT_PEER_SEND_ABORTED.
make_event({quic, peer_send_aborted, StreamRef, AppErrno}) ->
	{ok, StreamID} = quicer:get_stream_id(StreamRef),
	{stream_reset, StreamID, AppErrno};
%% QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED.
make_event({quic, peer_receive_aborted, StreamRef, AppErrno}) ->
	{ok, StreamID} = quicer:get_stream_id(StreamRef),
	{stream_stop_sending, StreamID, AppErrno};
%% QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE.
make_event({quic, stream_closed, _StreamRef, _Props}) ->
	no_event;
%% QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED.
make_event({quic, Data, _Conn, Flags}) when is_binary(Data), is_integer(Flags) ->
	{datagram, Data};
%% QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED.
make_event({quic, dgram_state_changed, _Conn, _Props}) ->
	no_event;
%% QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN.
make_event({quic, peer_send_shutdown, _StreamRef, undefined}) ->
	no_event;
%% QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE.
make_event({quic, send_shutdown_complete, _StreamRef, _IsGraceful}) ->
	no_event;
%% QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE / flow control update.
make_event({quic, streams_available, _Conn, _Props}) ->
	no_event;
%% QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT.
make_event({quic, transport_shutdown, _Conn, #{error := QuicErrno}}) ->
	{conn_closed, transport, QuicErrno};
%% QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER.
make_event({quic, shutdown, _Conn, AppErrno}) ->
	{conn_closed, application, AppErrno};
%% QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE.
make_event({quic, closed, Conn, _Flags}) ->
	_ = quicer:close_connection(Conn), %% @todo Is this necessary?
	no_event;
make_event(_Msg) ->
	unknown_msg.

-endif.
