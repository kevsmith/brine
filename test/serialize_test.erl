-module(serialize_test).

-include_lib("brine/include/brine.hrl").
-include_lib("eunit/include/eunit.hrl").

blob_test() ->
    {ok, KeyPair} = brine:new_keypair(),
    {ok, Blob} = brine:keypair_to_binary(KeyPair),
    {ok, KeyPair1} = brine:binary_to_keypair(Blob),
    ?assertMatch(KeyPair, KeyPair1).
