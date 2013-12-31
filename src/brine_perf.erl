-module(brine_perf).

-export([keygen/0,
         signature/0,
         serialize/0,
         all/0]).

-define(ITER, 1000000).
-define(CHILDREN, 4).
-define(MSG_SIZE, 4096).

all() ->
    keygen(),
    signature(),
    serialize().

keygen() ->
    ChildIter = erlang:round(?ITER / ?CHILDREN),
    Start = os:timestamp(),
    start_children(fun keygen/2, ChildIter, ?CHILDREN),
    join_children(?CHILDREN),
    End = os:timestamp(),
    USecs = timer:now_diff(End, Start),
    Secs = erlang:round(USecs / 1000000),
    io:format("===== Key Generation =====~n"),
    io:format("Iterations: ~p~n", [ChildIter * ?CHILDREN]),
    io:format("Total runtime: ~ps~n", [Secs]),
    io:format("Keys per sec: ~p~n", [erlang:round((ChildIter * ?CHILDREN) / Secs)]).

signature() ->
    ChildIter = erlang:round(?ITER / ?CHILDREN),
    Start = os:timestamp(),
    start_children(fun signature/2, ChildIter, ?CHILDREN),
    join_children(?CHILDREN),
    End = os:timestamp(),
    USecs = timer:now_diff(End, Start),
    Secs = erlang:round(USecs / 1000000),
    io:format("===== Message Signing =====~n"),
    io:format("Iterations: ~p~n", [ChildIter * ?CHILDREN]),
    io:format("Message size: ~p bytes~n", [?MSG_SIZE]),
    io:format("Total runtime: ~ps~n", [Secs]),
    io:format("Signatures per sec: ~p~n", [erlang:round((ChildIter * ?CHILDREN) / Secs)]).

serialize() ->
    ChildIter = erlang:round(?ITER / ?CHILDREN),
    Start = os:timestamp(),
    start_children(fun serialize/2, ChildIter, ?CHILDREN),
    join_children(?CHILDREN),
    End = os:timestamp(),
    USecs = timer:now_diff(End, Start),
    Secs = erlang:round(USecs / 1000000),
    io:format("===== Key Pair Serialization  =====~n"),
    io:format("Iterations: ~p~n", [ChildIter * ?CHILDREN]),
    io:format("Total runtime: ~ps~n", [Secs]),
    io:format("Roundtrips per sec: ~p~n", [erlang:round((ChildIter * ?CHILDREN) / Secs)]),
    io:format("Note: 1 roundtrip converts a key pair to a binary blob and back to an Erlang record~n").

    
%% Internal functions
join_children(0) ->
    ok;
join_children(Child) ->
    receive
        done ->
            join_children(Child - 1)
    end.

start_children(_Fun, _Iterations, 0) ->
    ok;
start_children(Fun, Iterations, Child) ->
    Owner = self(),
    spawn_link(fun() -> Fun(Owner, Iterations) end),
    start_children(Fun, Iterations, Child - 1).

keygen(Owner, 0) ->
    Owner ! done,
    ok;
keygen(Owner, X) ->
    {ok, _} = brine:new_keypair(),
    keygen(Owner, X - 1).

signature(Owner, X) ->
    random:seed(erlang:now()),
    {ok, KeyPair} = brine:new_keypair(),
    Msg = list_to_binary([random:uniform(255) || _ <- lists:seq(1, ?MSG_SIZE)]),
    signature(Owner, Msg, KeyPair, X).

signature(Owner, _Msg, _KeyPair, 0) ->
    Owner ! done,
    ok;
signature(Owner, Msg, KeyPair, X) ->
    {ok, _} = brine:sign_message(KeyPair, Msg),
    signature(Owner, Msg, KeyPair, X - 1).

serialize(Owner, X) ->
    {ok, KeyPair} = brine:new_keypair(),
    serialize(Owner, KeyPair, X).

serialize(Owner, _KeyPair, 0) ->
    Owner ! done,
    ok;
serialize(Owner, KeyPair, X) ->
    {ok, Blob} = brine:keypair_to_binary(KeyPair),
    {ok, KeyPair} = brine:binary_to_keypair(Blob),
    serialize(Owner, KeyPair, X - 1).
