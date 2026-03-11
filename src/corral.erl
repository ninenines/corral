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
-export([stop_listener/1]).
%% @todo -export([child_spec/5]).

%% Suspend/resume.
%% @todo Do this by keeping the conns_sup running but stopping the backend.
%% @todo -export([suspend_listener/1]).
%% @todo -export([resume_listener/1]).
%% @todo -export([get_status/1]).

%% Options.
%% @todo -export([get_backend_options/1]).
%% @todo -export([set_backend_options/2]).
%% @todo -export([get_protocol_options/1]).
%% @todo -export([set_protocol_options/2]).

%% Introspection.
%% @todo -export([get_addr/1]).
-export([get_port/1]).
%% @todo -export([info/0]).
%% @todo -export([info/1]).
%% @todo -export([procs/2]).
%% @todo -export([wait_for_connections/3]).
%% @todo -export([wait_for_connections/4]).

-type protocol_opts() :: any().
-export_type([protocol_opts/0]).

-type quic_client_opts() :: #{
	alpn => [binary()],
	cacertfile => file:filename(),
	certfile => file:filename(),
	connect_timeout => timeout(), %% Default infinity.
	keyfile => file:filename(),
	max_datagram_frame_size => non_neg_integer(), %% Default 0.
	max_streams_bidi => non_neg_integer(), %% Default 100.
	max_streams_unidi => non_neg_integer(), %% Default 100.
	verify => peer | none %% Default peer.
}.
-export_type([quic_client_opts/0]).

-type quic_conn() :: any().
-export_type([quic_conn/0]).

-type quic_server_opts() :: #{
	alpn => [binary()],
	backend => module(), %% Default corral_quic (not a NIF).
	cacertfile => file:filename(),
	certfile => file:filename(),
	connection_type => worker | supervisor, %% Default worker.
	keyfile => file:filename(),
	max_datagram_frame_size => non_neg_integer(), %% Default 0.
	max_streams_bidi => non_neg_integer(), %% Default 100.
	max_streams_unidi => non_neg_integer(), %% Default 100.
	port => inet:port_number(), %% Default 0.
	verify => peer | none %% Default peer.
}.
-export_type([quic_server_opts/0]).

-type ref() :: any().
-export_type([ref/0]).

%% Start/stop.

-spec start_listener(ref(), quic_server_opts(), module(), protocol_opts())
	-> supervisor:startchild_ret().

start_listener(Ref, QuicOpts0, Protocol, ProtoOpts) when is_atom(Protocol) ->
	{QuicBackend, QuicOpts} = case maps:take(backend, QuicOpts0) of
		error -> {corral_quic, QuicOpts0};
		TakeRes -> TakeRes
	end,
	_ = code:ensure_loaded(QuicBackend),
	case {erlang:function_exported(QuicBackend, start_listener, 3), validate_quic_server_opts(QuicOpts)} of
		{true, ok} ->
			ConnType = maps:get(connection_type, QuicOpts, worker),
			{ok, ConnsSup} = corral_sup:start_conns_sup(Ref, ConnType, Protocol),
			corral_ets:set_new_protocol_opts(Ref, ProtoOpts),
			Ret = QuicBackend:start_listener(Ref, ConnsSup, QuicOpts),
			case Ret of
				{ok, _} ->
					Ret;
				_ ->
					ok = corral_sup:stop_conns_sup(Ref),
					corral_ets:cleanup_listener(Ref),
					Ret
			end;
		{false, _} ->
			{error, {bad_backend, QuicBackend}};
		{_, QuicOptsError} ->
			QuicOptsError
	end.

validate_quic_server_opts(Opts) ->
	maps:fold(fun
		(Key, Value, ok) ->
			case validate_quic_server_opt(Key, Value, Opts) of
				true ->
					ok;
				false ->
					{error, {bad_option, Key}}
			end;
		(_, _, Acc) ->
			Acc
	end, ok, Opts).

validate_quic_server_opt(alpn, BinList, _) ->
	lists:all(fun(Token) -> is_binary(Token) end, BinList);
%% We expect that the file currently exists.
validate_quic_server_opt(cacertfile, Filename, _) ->
	filelib:is_file(Filename);
%% We expect that the file currently exists.
validate_quic_server_opt(certfile, Filename, _) ->
	filelib:is_file(Filename);
validate_quic_server_opt(connection_type, worker, _) ->
	true;
validate_quic_server_opt(connection_type, supervisor, _) ->
	true;
%% We expect that the file currently exists.
validate_quic_server_opt(keyfile, Filename, _) ->
	filelib:is_file(Filename);
validate_quic_server_opt(max_datagram_frame_size, Int, _) ->
	is_integer(Int) andalso Int >= 0;
validate_quic_server_opt(max_streams_bidi, Int, _) ->
	is_integer(Int) andalso Int >= 0;
validate_quic_server_opt(max_streams_unidi, Int, _) ->
	is_integer(Int) andalso Int >= 0;
validate_quic_server_opt(port, Int, _) ->
	(Int >= 0) andalso (Int =< 65535);
validate_quic_server_opt(verify, Value, _) ->
	(Value =:= peer) orelse (Value =:= none);
validate_quic_server_opt(_, _, _) ->
	false.

-spec stop_listener(ref()) -> ok | {error, not_found}.

stop_listener(Ref) ->
	try corral_ets:get_backend(Ref) of
		QuicBackend ->
			case QuicBackend:stop_listener(Ref) of
				ok ->
					corral_ets:cleanup_listener(Ref),
					corral_sup:stop_conns_sup(Ref);
				Error ->
					Error
			end
	catch error:badarg ->
		{error, not_found}
	end.

%% Introspection.

-spec get_port(ref()) -> inet:port_number().

get_port(Ref) ->
	corral_ets:get_port(Ref).
