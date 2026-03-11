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

-module(corral).

%% Start/stop.
-export([start_listener/4]).
-export([start_listener/5]).
-export([stop_listener/1]).
%% @todo -export([child_spec/5]).

%% Suspend/resume.
%% @todo Do this by keeping the conns_sup running but stopping the backend.
%% @todo -export([suspend_listener/1]).
%% @todo -export([resume_listener/1]).
%% @todo -export([get_status/1]).

%% Handshake.
-export([handshake/2]).

%% Options.
%% @todo -export([get_backend_options/1]).
%% @todo -export([set_backend_options/2]).
%% @todo -export([get_protocol_options/1]).
%% @todo -export([set_protocol_options/2]).

%% Introspection.
%% @todo -export([get_addr/1]).
%% @todo -export([get_port/1]).
%% @todo -export([info/0]).
%% @todo -export([info/1]).
%% @todo -export([procs/2]).
%% @todo -export([wait_for_connections/3]).
%% @todo -export([wait_for_connections/4]).

-type fin() :: fin | nofin.
-export_type([fin/0]).

-type quic_conn() :: any().
-export_type([quic_conn/0]).

%% @todo Double check all opts are actually used.
-type quic_opts() :: #{
	alpn => [binary()],
	%% @todo cacert/cacertfile for mTLS.
	certfile => file:filename(),
	connection_type => worker | supervisor,
	handshake_timeout => timeout(),
	keyfile => file:filename(),
	%% @todo Useful? logger => module(),
	%% @todo password for password-protected key files.
	port => inet:port_number(),
	%% @todo For connection processes. shutdown => timeout() | brutal_kill,
	verify => verify_none | verify_peer
}.
-export_type([quic_opts/0]).

-type ref() :: any().
-export_type([ref/0]).

-type stream_id() :: non_neg_integer().
-export_type([stream_id/0]).

%% Start/stop.

-spec start_listener(ref(), quic_opts(), module(), any())
	-> supervisor:startchild_ret().

start_listener(Ref, QuicOpts, Protocol, ProtoOpts) ->
	start_listener(Ref, corral_quic, QuicOpts, Protocol, ProtoOpts).

-spec start_listener(ref(), module(), quic_opts(), module(), any())
	-> supervisor:startchild_ret().

start_listener(Ref, QuicBackend, QuicOpts, Protocol, ProtoOpts)
		when is_atom(QuicBackend), is_atom(Protocol) ->
	_ = code:ensure_loaded(QuicBackend),
	case {erlang:function_exported(QuicBackend, start_listener, 5), validate_quic_opts(QuicOpts)} of
		{true, ok} ->
			{ok, ConnsSup} = corral_sup:start_conns_sup(Ref, Protocol),
			%% @todo If this fails we probably don't want to leave ConnsSup started.
			QuicBackend:start_listener(Ref, ConnsSup, QuicOpts, Protocol, ProtoOpts);
		{false, _} ->
			{error, {bad_backend, QuicBackend}};
		{_, QuicOptsError} ->
			QuicOptsError
	end.

%% @todo Full opts validation.
validate_quic_opts(Opts) when is_map(Opts) ->
	ok;
validate_quic_opts(_) ->
	{error, badarg}.

-spec stop_listener(ref()) -> ok | {error, not_found}.

stop_listener(Ref) ->
	#{backend := QuicBackend} = persistent_term:get({corral, Ref}),
	case QuicBackend:stop_listener(Ref) of
		ok ->
			corral_sup:stop_conns_sup(Ref);
		Error ->
			Error
	end.

%% Handshake.

-spec handshake(module(), any()) -> {ok, quic_conn(), #{alpn => binary()}}.

handshake(QuicBackend, Conn) ->
	QuicBackend:handshake(Conn).
