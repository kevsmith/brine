%% -------------------------------------------------------------------
%%
%% Copyright (c) 2013 Kevin A. Smith    All Rights Reserved
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% -------------------------------------------------------------------

-module(brine).

-opaque handle()    :: <<>>.
-type public_key()  :: <<_:256>>.
-type private_key() :: <<_:512>>.
-type keypair_blob() :: <<_:848>>.
-type signature() :: <<_:512>>.

-export_type([handle/0,
              public_key/0,
              private_key/0,
              keypair_blob/0]).

-include_lib("brine/include/brine.hrl").

-export([new_keypair/0,
         sign_message/2,
         verify_signature/3,
         keypair_to_binary/1,
         binary_to_keypair/1]).

%% Needs to be a macro so the stacktrace for the badarg error
%% is correct.
-define(complete_nif_call(Ref, Ret), case Ret of
                                         ok ->
                                             receive
                                                 {Ref, badarg} ->
                                                     erlang:error(badarg);
                                                 {Ref, Result} ->
                                                     Result
                                             end;
                                         Error ->
                                             Error
                                     end).

-spec new_keypair() -> {ok, #brine_keypair{}} | {error, term()}.
new_keypair() ->
    Owner = self(),
    Ref = erlang:make_ref(),
    ?complete_nif_call(Ref, brine_nif:generate_keypair(Owner, Ref)).

-spec sign_message(#brine_keypair{}, binary()) -> {ok, signature()} | {error, term()}.
sign_message(#brine_keypair{handle=H}, Message) ->
    Owner = self(),
    Ref = erlang:make_ref(),
    ?complete_nif_call(Ref, brine_nif:sign_message(Owner, Ref, H, Message)).

-spec verify_signature(binary(), binary(), binary()) -> boolean() | {error, term()}.
verify_signature(PubKey, Signature, Message) ->
    Owner = self(),
    Ref = erlang:make_ref(),
    ?complete_nif_call(Ref, brine_nif:verify_signature(Owner, Ref, PubKey, Signature, Message)).

-spec keypair_to_binary(#brine_keypair{}) -> {ok, keypair_blob()} | {error, term()}.
keypair_to_binary(#brine_keypair{handle=H}) ->
    Owner = self(),
    Ref = erlang:make_ref(),
    ?complete_nif_call(Ref, brine_nif:to_binary(Owner, Ref, H)).

-spec binary_to_keypair(keypair_blob()) -> {ok, #brine_keypair{}} | {error, term()}.
binary_to_keypair(Blob = <<_:848>>) ->
    Owner = self(),
    Ref = erlang:make_ref(),
    ?complete_nif_call(Ref, brine_nif:to_keypair(Owner, Ref, Blob)).
