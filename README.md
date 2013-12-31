brine is a set of Erlang NIFs supplying ed25519 key generation, message signing, signature verification and key pair serialization. brine aspires to provide a simple API coupled with robust performance.

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
