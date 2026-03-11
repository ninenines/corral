{application, 'corral', [
	{description, "QUIC backends for Erlang/OTP."},
	{vsn, "0.1.0"},
	{modules, ['corral','corral_app','corral_backend','corral_conns_sup','corral_ets','corral_quic','corral_quicer','corral_quicer_cb','corral_sup']},
	{registered, [corral_sup]},
	{applications, [kernel,stdlib,public_key,quic,quicer]},
	{optional_applications, []},
	{mod, {'corral_app', []}},
	{env, []}
]}.