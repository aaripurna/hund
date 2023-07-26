-module(hund).

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

-export(
  [
    threaduntil/2,
    nameid_map/1,
    rev_nameid_map/1,
    status_code_map/1,
    datetime_to_saml/1,
    saml_to_datetime/1,
    date_to_saml/1,
    rev_subject_method_map/1,
    map_if/2,
    map_if/1,
    rev_map_authn_class/1,
    rev_status_code_map/1,
    map_authn_class/1
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
datetime_to_saml(Time) ->
  {{Y, Mo, D}, {H, Mi, S}} = Time,
  lists:flatten(
    io_lib:format("~4.10.0B-~2.10.0B-~2.10.0BT~2.10.0B:~2.10.0B:~2.10.0BZ", [Y, Mo, D, H, Mi, S])
  ).


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


-spec map_if(term()) -> list(term()).
map_if("") -> [];
map_if(undefined) -> [];
map_if(K) -> [K].

-spec map_if(atom(), term()) -> list(term()).
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
