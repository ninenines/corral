# See LICENSE for licensing information.

PROJECT = corral
PROJECT_DESCRIPTION = QUIC backends for Erlang/OTP.
PROJECT_VERSION = 0.1.0

# Dependencies.

LOCAL_DEPS = public_key

# @todo Make sure it still works if using CORRAL_DEPS=quicer or with both.
# @todo And then remove quicer by default?
CORRAL_DEPS ?= quic quicer
export CORRAL_DEPS

DEPS = $(CORRAL_DEPS)
TEST_DEPS = quic

dep_quic = git https://github.com/benoitc/erlang_quic main
dep_quicer = git https://github.com/emqx/quic main

ifeq ($(filter quic,$(CORRAL_DEPS)),quic)
ERLC_OPTS += -D BACKEND_ERLANG_QUIC=1
TEST_ERLC_OPTS += -D BACKEND_ERLANG_QUIC=1
endif

ifeq ($(filter quicer,$(CORRAL_DEPS)),quicer)
ERLC_OPTS += -D BACKEND_QUICER=1
TEST_ERLC_OPTS += -D BACKEND_QUICER=1
endif

TEST_DEPS = ct_helper
dep_ct_helper = git https://github.com/extend/ct_helper master

# CI configuration.

dep_ci.erlang.mk = git https://github.com/ninenines/ci.erlang.mk master
DEP_EARLY_PLUGINS = ci.erlang.mk

AUTO_CI_OTP ?= OTP-LATEST-26+
AUTO_CI_WINDOWS ?= OTP-LATEST-26+

include erlang.mk

# Fix quicer compilation.

autopatch-quicer::
	$(verbose) printf "%s\n" "all: ;" > $(DEPS_DIR)/quicer/c_src/Makefile.erlang.mk

# Generate certificates for testing.

$(ERLANG_MK_TMP)/certs:
	$(verbose) mkdir -p $@
	$(gen_verbose) openssl req -x509 -nodes \
		-days 365 \
		-newkey rsa:2048 \
		-subj "/CN=localhost" \
		-addext "subjectAltName = DNS:localhost, DNS:127.0.0.1" \
		-keyout $@/server.key \
		-out $@/server.crt \
		2>/dev/null

test-build:: $(ERLANG_MK_TMP)/certs
