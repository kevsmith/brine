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

-module(brine_nif).

-on_load(init/0).

-export([init/0,
         generate_keypair/2,
         sign_message/4,
         verify_signature/5,
         to_binary/3,
         to_keypair/3]).

-define(nif_error, erlang:nif_error(not_loaded)).

init() ->
    Workers = erlang:max(1, erlang:round(erlang:system_info(logical_processors_available) * 0.5)),
    case build_nif_path() of
        {ok, Path} ->
            erlang:load_nif(Path, Workers);
        Error ->
            Error
    end.

generate_keypair(_Caller, _Ref) ->
    ?nif_error.

sign_message(_Caller, _Ref, _KeyPair, _Message) ->
    ?nif_error.

verify_signature(_Caller, _Ref, _PubKey, _Signature, _Message) ->
    ?nif_error.

to_binary(_Caller, _Ref, _KeyPair) ->
    ?nif_error.

to_keypair(_Caller, _Ref, _Blob) ->
    ?nif_error.

%% Internal functions
build_nif_path() ->
    case code:priv_dir(brine) of
        Path when is_list(Path) ->
            {ok, filename:join([Path, "brine_nif"])};
        {error, bad_name} ->
            case code:which(?MODULE) of
                Filename when is_list(Filename) ->
                    {ok, filename:join([filename:dirname(Filename),
                                        "..","priv",
                                        "brine_nif"])};
                Reason when is_atom(Reason) ->
                    {error, Reason}
            end
    end.
