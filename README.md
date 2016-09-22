# Brine

brine is a set of Erlang NIFs supplying ed25519 key generation, message signing, signature verification and key pair serialization. brine aspires to provide a simple API coupled with robust performance.

# Build

```
rebar3 compile
```

# Usage

## Signing

```
rebar3 shell

1> KeyPair = brine:new_keypair().
#{handle => <<>>,
  public => <<148,198,94,170,223,215,144,194,243,155,174,242,52,86,
    247,249,222,216,252,186,43,238,218,137,159,131,85,...>>,
  secret => <<216,75,223,188,86,26,228,125,200,190,176,251,225,197,
    236,149,110,7,58,117,11,109,240,63,255,63,...>>}

2> Sig = brine:sign_message(KeyPair, <<"Hello">>).
<<202,34,75,107,117,99,27,229,155,136,250,191,237,231,45,
  114,11,128,254,48,247,9,105,111,2,187,102,40,166,...>>

3> brine:verify_signature(maps:get(public,KeyPair), Sig, <<"Hello">>).
true
```

## Serialization

```
rebar3 shell

1> KeyPair = brine:new_keypair().
#{handle => <<>>,
  public => <<112,116,97,16,182,61,130,25,98,68,206,26,174,127,172,13,
    212,112,192,169,36,10,180,163,127,181,70,...>>,
  secret => <<168,115,218,94,104,56,48,85,110,133,86,112,146,250,252,
    183,80,215,29,29,107,145,144,121,2,64,...>>}

2> Blob = brine:keypair_to_binary(KeyPair).
<<0,1,20,67,98,138,248,191,101,254,94,218,115,168,85,48,
  56,104,112,86,133,110,183,252,250,146,29,29,215,...>>

3> brine:binary_to_keypair(Blob).
#{handle => <<>>,
  public => <<112,116,97,16,182,61,130,25,98,68,206,26,174,127,172,13,
    212,112,192,169,36,10,180,163,127,181,70,...>>,
  secret => <<168,115,218,94,104,56,48,85,110,133,86,112,146,250,252,
    183,80,215,29,29,107,145,144,121,2,64,...>>}
```

# Benchmarks

Benchmark results (as of Dec 30 2013):

```
===== Key Generation =====
Iterations: 1000000
Total runtime: 216s
Keys per sec: 4630
===== Message Signing =====
Iterations: 1000000
Message size: 4096 bytes
Total runtime: 23s
Signatures per sec: 43478
===== Key Pair Serialization  =====
Iterations: 1000000
Total runtime: 69s
Roundtrips per sec: 14493
Note: 1 roundtrip converts a key pair to a binary blob and back to an Erlang record
```

Test server: Intel Core i7-4770 (Haswell, hyperthreading enabled) @ 3.4 GHz CPU w/32 GB DDR3 RAM

Test environment: Ubuntu 13.10, gcc 4.8.1, Erlang R16B03

Special tuning: rngd and timer_entropyd used to increase available entropy

Thanks to the following folks for making brine possible:

* Jean-Phillips Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian Winnerlein for BLAKE2
* Orson Peters for the clean and easy-to-use ed25519 implementation
* Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter Schwabe, and Bo-Yin Yang for designing ed25519

TODO:
* Document brine's serialization format
* Refactor brine into libbrine w/NIF adapter to simplify writing bindings for other languages
