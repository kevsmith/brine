LIBBRINE_URL = git://github.com/rlipscombe/libbrine.git

deps: libbrine/libbrine_s.a

libbrine/libbrine_s.a: libbrine
	make -C libbrine -f Makefile.embed libbrine_s.a

libbrine:
	git clone $(LIBBRINE_URL)
