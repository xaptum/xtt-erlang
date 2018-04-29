PROJECT = xtt-erlang
REBAR = rebar3
BASEDIR = $(shell pwd)

compile:
	$(REBAR) compile

xref:
	$(REBAR) xref

eunit: compile
	$(REBAR) eunit

ct: compile
	$(REBAR) ct --dir $(BASEDIR)/ct --logdir $(BASEDIR)/ct/logs

clean:
	rm -rf _build
	rm -rf priv/xtt-erlang.so
