-module(serialize_test).

-include_lib("brine/include/brine.hrl").
-include_lib("eunit/include/eunit.hrl").

blob_test() ->
    KeyPair = brine:new_keypair(),
    Secret = maps:get(secret, KeyPair),
    Public = maps:get(public, KeyPair),
    Blob = brine:keypair_to_binary(KeyPair),
    KeyPair1 = brine:binary_to_keypair(Blob),
    Secret1 = maps:get(secret, KeyPair1),
    Public1 = maps:get(public, KeyPair1),
    ?assertMatch(Secret, Secret1),
    ?assertMatch(Public, Public1).
