-module(brine_stress).

-export([keygen/0]).

-define(ITER, 1000000).
-define(CHILDREN, 4).

keygen() ->
    Start = os:timestamp(),
    ChildIter = erlang:round(?ITER / ?CHILDREN),
    start_children(fun keygen/2, ChildIter, ?CHILDREN),
    join_children(?CHILDREN),
    End = os:timestamp(),
    timer:now_diff(End, Start).

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
