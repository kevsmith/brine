-module(keypair_test).

-include_lib("brine/include/brine.hrl").
-include_lib("eunit/include/eunit.hrl").

-define(MESSAGE, <<"How now brown cow?">>).

creation_test() ->
    KeyPair = brine:new_keypair(),
    ?assert(is_map(KeyPair)),
    KeyPair1 = brine:new_keypair(),
    ?assertNot(KeyPair =:= KeyPair1).

sign_test() ->
    KeyPair = brine:new_keypair(),
    Sig1 = brine:sign_message(KeyPair, ?MESSAGE),
    Sig2 = brine:sign_message(KeyPair, ?MESSAGE),
    ?assert(is_binary(Sig1)),
    ?assert(is_binary(Sig2)),
    ?assertMatch(Sig1, Sig2).

verify_test() ->
    KeyPair = brine:new_keypair(),
    KeyPair1 = brine:new_keypair(),
    Sig1 = brine:sign_message(KeyPair, ?MESSAGE),
    ?assert(brine:verify_signature(maps:get(public,KeyPair), Sig1, ?MESSAGE)),
    ?assertNot(brine:verify_signature(maps:get(public,KeyPair1), Sig1, ?MESSAGE)).
