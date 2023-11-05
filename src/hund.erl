-module(hund).

-include_lib("public_key/include/public_key.hrl").
-include_lib("../include/hund.hrl").

-type contact() :: #saml_contact{}.
-type org() :: #saml_org{}.
-type idp_metadata() :: #saml_idp_metadata{}.
-type sp_metadata() :: #saml_sp_metadata{}.
-type subject() :: #saml_subject{}.
-type assertion() :: #saml_assertion{}.
-type authnreq() :: #saml_authnreq{}.
-type authn() :: #saml_authn{}.
-type logout_request() :: #saml_logout_request{}.
-type logout_response() :: #saml_logout_response{}.
-type saml_record() :: contact()
                     | org()
                     | idp_metadata()
                     | sp_metadata()
                     | subject()
                     | assertion()
                     | authn()
                     | authnreq()
                     | logout_request()
                     | logout_response().

-export_type(
  [
    contact/0,
    org/0,
    idp_metadata/0,
    sp_metadata/0,
    saml_record/0,
    authnreq/0,
    assertion/0,
    logout_request/0,
    logout_response/0
  ]
).

-type localized_string() :: string() | [{Locale :: atom(), LocalString :: string()}].
-type name_format() :: email | x509 | windows | krb | persistent | transient | unknown.
-type status_code() :: success
                     | request_error
                     | response_error
                     | bad_version
                     | authn_failed
                     | bad_attr
                     | denied
                     | bad_binding
                     | unknown.
-type version() :: string().
-type datetime() :: string() | binary().
-type condition() :: #saml_condition{}.
-type subject_method() :: bearer | holder_of_key | sender_vouches.
-type authn_class() :: password
                     | password_protected_transport
                     | internet_protocol
                     | internet_protocol_password
                     | mobile_one_factor_contract
                     | mobile_two_factor_contract
                     | previous_session
                     | unspecified.

-export_type(
  [
    localized_string/0,
    name_format/0,
    status_code/0,
    version/0,
    datetime/0,
    condition/0,
    subject_method/0,
    authn_class/0
  ]
).

-export([nameid_map/1, rev_nameid_map/1, status_code_map/1, datetime_to_saml/1]).
-export([threaduntil/2]).
-export([map_if/2, map_if/1]).
-export([rev_subject_method_map/1, rev_map_authn_class/1, rev_status_code_map/1, map_authn_class/1]).
-export([saml_to_datetime/1, date_to_saml/1]).
-export([start_ets/0, check_dupe_ets/2]).
-export(
  [
    convert_fingerprints/1,
    load_private_key/1,
    import_private_key/2,
    load_certificate/1,
    import_certificate/2,
    load_metadata/1,
    load_metadata/2,
    unique_id/0
  ]
).

-spec threaduntil(
  [fun((Acc :: term()) -> {error, term()} | {stop, term()} | term())],
  InitAcc :: term()
) ->
  {error, term()} | {ok, term()}.
threaduntil([], Acc) -> {ok, Acc};

threaduntil([F | Rest], Acc) ->
  case catch F(Acc) of
    {'EXIT', Reason} -> {error, Reason};
    {error, Reason} -> {error, Reason};
    {stop, LastAcc} -> {ok, LastAcc};
    NextAcc -> threaduntil(Rest, NextAcc)
  end.


-spec nameid_map(string()) -> name_format().
nameid_map("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress") -> email;
nameid_map("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName") -> x509;
nameid_map("urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName") -> windows;
nameid_map("urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos") -> krb;
nameid_map("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent") -> persistent;
nameid_map("urn:oasis:names:tc:SAML:2.0:nameid-format:transient") -> transient;
nameid_map(S) when is_list(S) -> unknown.

-spec rev_nameid_map(atom()) -> string().
rev_nameid_map(email) -> "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
rev_nameid_map(x509) -> "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
rev_nameid_map(windows) -> "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName";
rev_nameid_map(krb) -> "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos";
rev_nameid_map(persistent) -> "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos";
rev_nameid_map(transient) -> "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
rev_nameid_map(_) -> "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".

-spec status_code_map(string()) -> status_code() | atom().
status_code_map("urn:oasis:names:tc:SAML:2.0:status:Success") -> success;
status_code_map("urn:oasis:names:tc:SAML:2.0:status:VersionMismatch") -> bad_version;
status_code_map("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed") -> authn_failed;
status_code_map("urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue") -> bad_attr;
status_code_map("urn:oasis:names:tc:SAML:2.0:status:RequestDenied") -> denied;
status_code_map("urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding") -> bad_binding;
status_code_map(Urn = "urn:" ++ _) -> list_to_atom(lists:last(string:tokens(Urn, ":")));
status_code_map(S) when is_list(S) -> unknown.

-spec rev_status_code_map(status_code() | atom()) -> string().
rev_status_code_map(success) -> "urn:oasis:names:tc:SAML:2.0:status:Success";
rev_status_code_map(bad_version) -> "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";
rev_status_code_map(authn_failed) -> "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
rev_status_code_map(bad_attr) -> "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue";
rev_status_code_map(denied) -> "urn:oasis:names:tc:SAML:2.0:status:RequestDenied";
rev_status_code_map(bad_binding) -> "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding";

rev_status_code_map(Status) when is_atom(Status) ->
  "urn:oasis:names:tc:SAML:2.0:status:" ++ pascal_case(atom_to_list(Status)).

-spec rev_subject_method_map(subject_method()) -> string().
rev_subject_method_map(bearer) -> "urn:oasis:names:tc:SAML:2.0:cm:bearer";
rev_subject_method_map(holder_of_key) -> "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key";
rev_subject_method_map(sender_vouches) -> "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches".

-spec rev_map_authn_class(Context :: atom()) -> string().
rev_map_authn_class(password_protected_transport) ->
  "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

rev_map_authn_class(password) -> "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";
rev_map_authn_class(internet_protocol) -> "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol";

rev_map_authn_class(internet_protocol_password) ->
  "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword";

rev_map_authn_class(mobile_one_factor_contract) ->
  "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorContract";

rev_map_authn_class(mobile_two_factor_contract) ->
  "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract";

rev_map_authn_class(previous_session) -> "urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession";
rev_map_authn_class(_) -> "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified".

-spec map_authn_class(AuthnClass :: string()) -> authn_class().
map_authn_class("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport") ->
  password_protected_transport;

map_authn_class("urn:oasis:names:tc:SAML:2.0:ac:classes:Password") -> password;
map_authn_class("urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol") -> internet_protocol;

map_authn_class("urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword") ->
  internet_protocol_password;

map_authn_class("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileOneFactorContract") ->
  mobile_one_factor_contract;

map_authn_class("urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract") ->
  mobile_two_factor_contract;

map_authn_class("urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession") -> previous_session;
map_authn_class(_) -> unspecified.

%% @doc Converts a calendar:datetime() into SAML time string

-spec datetime_to_saml(calendar:datetime()) -> datetime().
datetime_to_saml(Time) when is_tuple(Time) ->
  {{Y, Mo, D}, {H, Mi, S}} = Time,
  lists:flatten(
    io_lib:format("~4.10.0B-~2.10.0B-~2.10.0BT~2.10.0B:~2.10.0B:~2.10.0BZ", [Y, Mo, D, H, Mi, S])
  );

datetime_to_saml(_Time) -> "".


-spec date_to_saml(calendar:date()) -> string() | binary().
date_to_saml(Date) ->
  {Year, Month, Day} = Date,
  list:flatten(io_lib:format("~4.10.0B-~2.10.0B-~2.10.0B", [Year, Month, Day])).

%% @doc Converts a SAML time string into a calendar:datetime()
%%
%% Inverse of datetime_to_saml/1

-spec saml_to_datetime(esaml:datetime()) -> calendar:datetime().
saml_to_datetime(Stamp) ->
  StampBin =
    if
      is_list(Stamp) -> list_to_binary(Stamp);
      true -> Stamp
    end,
  <<
    YBin:4/binary,
    "-",
    MoBin:2/binary,
    "-",
    DBin:2/binary,
    "T",
    HBin:2/binary,
    ":",
    MiBin:2/binary,
    ":",
    SBin:2/binary,
    Rest/binary
  >> = StampBin,
  %% check that time in UTC timezone because we don't handle another timezones properly
  $Z = binary:last(Rest),
  F = fun (B) -> list_to_integer(binary_to_list(B)) end,
  {{F(YBin), F(MoBin), F(DBin)}, {F(HBin), F(MiBin), F(SBin)}}.


-spec map_if(term()) -> [term()].
map_if("") -> [];
map_if(undefined) -> [];
map_if(K) -> [K].

-spec map_if(atom(), term()) -> [term()].
map_if(Key, List = [{K, _} | _]) when is_atom(K) ->
  case proplists:get_value(Key, List) of
    undefined -> [];
    V when is_list(V) -> V;
    Other -> [Other]
  end;

map_if(_, _) -> [].


-spec pascal_case(String :: string()) -> string().
pascal_case(String) -> pascal_case(String, "_").

-spec pascal_case(String :: string(), Sep :: string()) -> string().
pascal_case(String, Sep) ->
  Chunks = string:split(String, Sep),
  Chunks2 = lists:map(fun string:titlecase/1, Chunks),
  string:join(Chunks2, "").

%% @doc Converts various ascii hex/base64 fingerprint formats to binary

-spec convert_fingerprints([string() | binary()]) -> [binary()].
convert_fingerprints(FPs) ->
  FPSources = FPs ++ esaml:config(trusted_fingerprints, []),
  lists:map(
    fun
      (Print) ->
        if
          is_list(Print) ->
            case string:tokens(Print, ":") of
              [Type, Base64] ->
                Hash = base64:decode(Base64),
                case string:to_lower(Type) of
                  "sha" -> {sha, Hash};
                  "sha1" -> {sha, Hash};
                  "md5" -> {md5, Hash};
                  "sha256" -> {sha256, Hash};
                  "sha384" -> {sha384, Hash};
                  "sha512" -> {sha512, Hash}
                end;

              [_] -> error("unknown fingerprint format");
              HexParts -> list_to_binary([list_to_integer(P, 16) || P <- HexParts])
            end;

          is_binary(Print) -> Print;
          true -> error("unknown fingerprint format")
        end
    end,
    FPSources
  ).

%% @private

start_ets() ->
  case erlang:whereis(hund_ets_table_owner) of
    undefined -> create_tables();

    Pid ->
      Pid ! {self(), check_ready},
      receive {Pid, ready} -> {ok, Pid} end
  end.

%% @private

create_tables() ->
  Caller = self(),
  Pid =
    spawn_link(
      fun
        () ->
          register(hund_ets_table_owner, self()),
          ets:new(hund_assertion_seen, [set, public, named_table]),
          ets:new(hund_privkey_cache, [set, public, named_table]),
          ets:new(hund_certbin_cache, [set, public, named_table]),
          ets:new(hund_idp_meta_cache, [set, public, named_table]),
          Caller ! {self(), ready},
          ets_table_owner()
      end
    ),
  receive {Pid, ready} -> ok end,
  {ok, Pid}.

%% @private

ets_table_owner() ->
  receive
    stop -> ok;

    {Caller, check_ready} ->
      Caller ! {self(), ready},
      ets_table_owner();

    _ -> ets_table_owner()
  end.


% @doc Loads a private key from a file on disk (or ETS memory cache)
-spec load_private_key(Path :: string()) -> #'RSAPrivateKey'{}.
load_private_key(Path) ->
  case ets:lookup(hund_privkey_cache, Path) of
    [{_, Key}] -> Key;

    _ ->
      {ok, KeyFile} = file:read_file(Path),
      do_import_private_key(KeyFile, Path)
  end.


-spec import_private_key(EncodedKey :: string(), Identifier :: term()) -> #'RSAPrivateKey'{}.
import_private_key(EncodedKey, Identifier) ->
  case ets:lookup(hund_privkey_cache, Identifier) of
    [{_, Key}] -> Key;
    _ -> do_import_private_key(EncodedKey, Identifier)
  end.


do_import_private_key(EncodedKey, Identifier) ->
  [KeyEntry] = public_key:pem_decode(EncodedKey),
  Key =
    case public_key:pem_entry_decode(KeyEntry) of
      #'PrivateKeyInfo'{privateKey = KeyData} ->
        KeyDataBin =
          if
            is_list(KeyData) -> list_to_binary(KeyData);
            true -> KeyData
          end,
        public_key:der_decode('RSAPrivateKey', KeyDataBin);

      Other -> Other
    end,
  ets:insert(hund_privkey_cache, {Identifier, Key}),
  Key.


-spec load_certificate(Path :: string()) -> binary().
load_certificate(Path) ->
  [CertBin] = load_certificate_chain(Path),
  CertBin.


-spec import_certificate(EncodedCert :: string(), Identifier :: term()) -> binary().
import_certificate(EncodedCert, Identifier) ->
  [CertBin] = import_certificate_chain(EncodedCert, Identifier),
  CertBin.

%% @doc Loads certificate chain from a file on disk (or ETS memory cache)

-spec load_certificate_chain(Path :: string()) -> [binary()].
load_certificate_chain(Path) ->
  case ets:lookup(hund_certbin_cache, Path) of
    [{_, CertChain}] -> CertChain;

    _ ->
      {ok, EncodedCert} = file:read_file(Path),
      do_import_certificate_chain(EncodedCert, Path)
  end.

%% @doc Loads certificate chain from a file on disk (or ETS memory cache)

-spec import_certificate_chain(EncodedCerts :: string(), Identifier :: string()) -> [binary()].
import_certificate_chain(EncodedCerts, Identifier) ->
  case ets:lookup(hund_certbin_cache, Identifier) of
    [{_, CertChain}] -> CertChain;
    _ -> do_import_certificate_chain(EncodedCerts, Identifier)
  end.


do_import_certificate_chain(EncodedCerts, Identifier) ->
  CertChain =
    [CertBin || {'Certificate', CertBin, not_encrypted} <- public_key:pem_decode(EncodedCerts)],
  ets:insert(hund_certbin_cache, {Identifier, CertChain}),
  CertChain.

%% @doc Reads IDP metadata from a URL (or ETS memory cache) and validates the signature

-spec load_metadata(Url :: string(), Fingerprints :: [string() | binary()]) -> esaml:idp_metadata().
load_metadata(Url, FPs) ->
  Fingerprints = convert_fingerprints(FPs),
  case ets:lookup(hund_idp_meta_cache, Url) of
    [{Url, Meta}] -> Meta;

    _ ->
      {ok, {{_Ver, 200, _}, _Headers, Body}} =
        httpc:request(get, {Url, []}, [{autoredirect, true}, {timeout, 3000}], []),
      {Xml, _} = xmerl_scan:string(Body, [{namespace_conformant, true}]),
      case xmerl_dsig:verify(Xml, Fingerprints) of
        ok -> ok;
        Err -> error(Err)
      end,
      {ok, Meta = #saml_sp_metadata{}} = hund_xml:decode_sp_metadata(Xml),
      ets:insert(hund_idp_meta_cache, {Url, Meta}),
      Meta
  end.

%% @doc Reads IDP metadata from a URL (or ETS memory cache)

-spec load_metadata(Url :: string()) -> esaml:idp_metadata().
load_metadata(Url) ->
  case ets:lookup(hund_idp_meta_cache, Url) of
    [{Url, Meta}] -> Meta;

    _ ->
      Timeout = application:get_env(esaml, load_metadata_timeout, 15000),
      {ok, {{_Ver, 200, _}, _Headers, Body}} =
        httpc:request(get, {Url, []}, [{autoredirect, true}, {timeout, Timeout}], []),
      {Xml, _} = xmerl_scan:string(Body, [{namespace_conformant, true}]),
      {ok, Meta = #saml_sp_metadata{}} = hund:decode_sp_metadata(Xml),
      ets:insert(hund_idp_meta_cache, {Url, Meta}),
      Meta
  end.

%% @doc Checks for a duplicate assertion using ETS tables in memory on all available nodes.
%%
%% This is a helper to be used as a DuplicateFun with hund_sp:validate_assertion/3.
%% If you aren't using standard erlang distribution for your app, you probably don't
%% want to use this.

-spec check_dupe_ets(esaml:assertion(), Digest :: binary()) -> ok | {error, duplicate_assertion}.
check_dupe_ets(A, Digest) ->
  Now = erlang:localtime_to_universaltime(erlang:localtime()),
  NowSecs = calendar:datetime_to_gregorian_seconds(Now),
  DeathSecs = esaml:stale_time(A),
  {ResL, _BadNodes} =
    rpc:multicall(
      erlang,
      apply,
      [
        fun
          () ->
            case catch ets:lookup(hund_assertion_seen, Digest) of
              [{Digest, seen} | _] -> seen;
              _ -> ok
            end
        end,
        []
      ]
    ),
  case lists:member(seen, ResL) of
    true -> {error, duplicate_assertion};

    _ ->
      Until = DeathSecs - NowSecs + 1,
      rpc:multicall(
        erlang,
        apply,
        [
          fun
            () ->
              case ets:info(hund_assertion_seen) of
                undefined ->
                  Me = self(),
                  Pid =
                    spawn(
                      fun
                        () ->
                          register(hund_ets_table_owner, self()),
                          ets:new(hund_assertion_seen, [set, public, named_table]),
                          ets:new(hund_privkey_cache, [set, public, named_table]),
                          ets:new(hund_certbin_cache, [set, public, named_table]),
                          ets:insert(hund_assertion_seen, {Digest, seen}),
                          Me ! {self(), ping},
                          ets_table_owner()
                      end
                    ),
                  receive {Pid, ping} -> ok end;

                _ -> ets:insert(hund_assertion_seen, {Digest, seen})
              end,
              {ok, _} =
                timer:apply_after(
                  Until * 1000,
                  erlang,
                  apply,
                  [fun () -> ets:delete(hund_assertion_seen, Digest) end, []]
                )
          end,
          []
        ]
      ),
      ok
  end.


% TODO: switch to uuid_erl hex pkg
unique_id() ->
  "id"
  ++
  integer_to_list(erlang:system_time())
  ++
  integer_to_list(erlang:unique_integer([positive])).
