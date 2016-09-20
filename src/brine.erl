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
-type hex_signature() :: <<_:1024>>.

-export_type([handle/0,
              public_key/0,
              private_key/0,
              keypair_blob/0,
              signature/0,
              hex_signature/0]).

-include_lib("brine/include/brine.hrl").

-export([new_keypair/0,
         new_keypair/1,
         sign_message/2,
         sign_message_hex/2,
         verify_signature/3,
         keypair_to_binary/1,
         binary_to_keypair/1,
         keys_to_keypair/2]).

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

-spec new_keypair() -> map() | {error, term()}.
new_keypair() ->
    Owner = self(),
    Ref = erlang:make_ref(),
    case ?complete_nif_call(Ref, brine_nif:generate_keypair(Owner, Ref)) of
        {ok, #brine_keypair{handle=H, private_key=S, public_key=P}} ->
            #{handle => H, public => P, secret => S};
        E -> E
    end.

-spec new_keypair(binary()) -> map() | {error, term()}.
new_keypair(Seed) ->
    Owner = self(),
    Ref = erlang:make_ref(),
    case ?complete_nif_call(Ref, brine_nif:generate_keypair_from_seed(Owner, Ref, Seed)) of
	{ok, #brine_keypair{handle=H, private_key=S, public_key=P}} ->
	    #{handle => H, public => P, secret => S};
        E -> E
    end.

-spec sign_message(map(), binary()) -> signature() | {error, term()}.
sign_message(#{handle := H}, Message) ->
    Owner = self(),
    Ref = erlang:make_ref(),
    case ?complete_nif_call(Ref, brine_nif:sign_message(Owner, Ref, H, Message)) of
        {ok, Sig} -> Sig;
        E -> E
    end;
sign_message(#{public := P, secret := S}, Message) ->
    KeyPair = keys_to_keypair(P, S),
    sign_message(KeyPair, Message).

-spec sign_message_hex(map(), binary()) -> hex_signature() | {error, term()}.
sign_message_hex(#{handle := H}, Message) ->
    Owner = self(),
    Ref = erlang:make_ref(),
    case ?complete_nif_call(Ref, brine_nif:sign_message(Owner, Ref, H, Message)) of
        {ok, Sig} ->
            brine_format:binary_to_hex(Sig);
        E ->
            E
    end;
sign_message_hex(#{public := P, secret := S}, Message) ->
    KeyPair = keys_to_keypair(P, S),
    sign_message_hex(KeyPair, Message).

-spec verify_signature(binary(), binary(), binary()) -> boolean() | {error, term()}.
verify_signature(PubKey, Signature, Message) ->
    Owner = self(),
    Ref = erlang:make_ref(),
    ?complete_nif_call(Ref, brine_nif:verify_signature(Owner, Ref, PubKey, Signature, Message)).

-spec keypair_to_binary(map()) -> keypair_blob() | {error, term()}.
keypair_to_binary(#{handle := H}) ->
    Owner = self(),
    Ref = erlang:make_ref(),
    case ?complete_nif_call(Ref, brine_nif:to_binary(Owner, Ref, H)) of
        {ok, Bin} -> Bin;
        E -> E
    end;
keypair_to_binary(#{public := P, secret := S}) ->
    KeyPair = keys_to_keypair(P, S),
    keypair_to_binary(KeyPair).

-spec binary_to_keypair(keypair_blob()) -> map() | {error, term()}.
binary_to_keypair(Blob = <<_:848>>) ->
    Owner = self(),
    Ref = erlang:make_ref(),
    case ?complete_nif_call(Ref, brine_nif:to_keypair(Owner, Ref, Blob)) of
        {ok, #brine_keypair{handle=H, private_key=S, public_key=P}} ->
            #{handle => H, public => P, secret => S};
        E -> E
    end.

-spec keys_to_keypair(public_key(), private_key()) -> map() | {error, term()}.
keys_to_keypair(Public = <<_:256>>, Secret = <<_:512>>) ->
    case brine_nif:to_keypair_from_keys(Public, Secret) of
        {ok, #brine_keypair{handle=H, private_key=S, public_key=P}} ->
            #{handle => H, public => P, secret => S};
        E -> E
    end.
