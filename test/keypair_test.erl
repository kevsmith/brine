-module(keypair_test).

-include_lib("brine/include/brine.hrl").
-include_lib("eunit/include/eunit.hrl").

-define(MESSAGE, <<"How now brown cow?">>).

creation_test() ->
    {ok, KeyPair} = brine:new_keypair(),
    ?assert(is_record(KeyPair, brine_keypair)),
    {ok, KeyPair1} = brine:new_keypair(),
    ?assertNot(KeyPair =:= KeyPair1).

sign_test() ->
    {ok, KeyPair} = brine:new_keypair(),
    {ok, Sig1} = brine:sign_message(KeyPair, ?MESSAGE),
    {ok, Sig2} = brine:sign_message(KeyPair, ?MESSAGE),
    ?assert(is_binary(Sig1)),
    ?assert(is_binary(Sig2)),
    ?assertMatch(Sig1, Sig2).

verify_test() ->
    {ok, KeyPair} = brine:new_keypair(),
    {ok, Sig1} = brine:sign_message(KeyPair, ?MESSAGE),
    ?assert(brine:verify_signature(KeyPair#brine_keypair.public_key, Sig1, ?MESSAGE)).
