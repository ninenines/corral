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

-module(corral_backend).

%% Types.

-type app_errno() :: non_neg_integer().
-export_type([app_errno/0]).

-type conn() :: any().

%% The timing of events may vary between the different
%% backends. For example a backend may or may not send
%% a stream_opened event when receiving a STREAM frame
%% with empty data, waiting for further frames first.
-type event() ::
	%% Connection.
	%% @todo It makes sense to have a function map the QUIC error to an atom (but not app_errno()).
	{conn_closed, transport, non_neg_integer()} %% @todo Better error type? QUIC error.
	| {conn_closed, application, app_errno()}
	%% Streams.
	| {stream_opened, stream_id(), stream_type()}
	| {stream_data, stream_id(), fin(), binary()}
	| {stream_reset, stream_id(), app_errno()}
	| {stream_stop_sending, stream_id(), app_errno()}
	%% Datagrams.
	| {datagram, binary()}
	%% No event.
	| no_event
	| unknown_msg
	%% Error while processing events.
	| {error, any()}.
-export_type([event/0]).

-type fin() :: fin | nofin.
-export_type([fin/0]).

-type stream_id() :: non_neg_integer().
-export_type([stream_id/0]).

-type stream_type() :: unidi | bidi.
-export_type([stream_type/0]).

%% Servers.

-callback start_listener(corral:ref(), pid(), corral:quic_server_opts())
	-> supervisor:startchild_ret().

-callback stop_listener(corral:ref())
	-> ok | {error, not_found}.

-callback handshake(conn())
	-> {ok, #{alpn => binary()}}.

%% Clients.

-callback connect(inet:ip_address() | inet:hostname(), inet:port_number(), corral:quic_client_opts())
	-> {ok, conn()} | {error, any()}.

%% Connection.

-callback peername(conn())
	-> {ok, {inet:ip_address(), inet:port_number()}}
	| {error, any()}.

-callback sockname(conn())
	-> {ok, {inet:ip_address(), inet:port_number()}}
	| {error, any()}.

-callback peercert(conn())
	-> {ok, public_key:der_encoded()}
	| {error, any()}. %% @todo Must have a specific error when peer cert wasn't sent.

-callback close(conn())
	-> ok | {error, any()}.

-callback close(conn(), app_errno())
	-> ok | {error, any()}.

%% Streams.

-callback open_bidi_stream(conn(), iodata())
	-> {ok, stream_id()}
	| {error, any()}.

-callback open_unidi_stream(conn(), iodata())
	-> {ok, stream_id()}
	| {error, any()}.

-callback send(conn(), stream_id(), iodata())
	-> ok | {error, any()}.

-callback send(conn(), stream_id(), fin(), iodata())
	-> ok | {error, any()}.

-callback reset_stream(conn(), stream_id(), app_errno())
	-> ok | {error, any()}.

-callback stop_sending(conn(), stream_id(), app_errno())
	-> ok | {error, any()}.

-callback close_stream(conn(), stream_id(), app_errno())
	-> ok | {error, any()}.

%% Datagrams.

-callback send_datagram(conn(), iodata())
	-> ok | {error, any()}.

%% Messages.

-callback make_event(tuple()) -> event().
