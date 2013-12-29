deps: ed25519/src blake2/sse apply-patches

ed25519/src:
	cd .. && git submodule init
	cd .. && git submodule update

blake2/src:
	cd .. && git submodule init
	cd .. && git submodule update

apply-patches: patches/ed25519-seed.c.patch.applied patches/ed25519-sha512.c.patch.applied

%.applied:
	patch -p0 < $* && touch $@
