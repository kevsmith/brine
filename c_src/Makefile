deps: ed25519 blake2 apply-patches

ed25519:
	git submodule init
	git submodule update

blake2:
	git submodule init
	git submodule update

apply-patches: patches/ed25519-seed.c.patch.applied patches/ed25519-sha512.c.patch.applied

%.applied:
	patch -p0 < $* && touch $@
