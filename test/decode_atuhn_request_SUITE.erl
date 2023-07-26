-module(decode_atuhn_request_SUITE).

-include_lib("eunit/include/eunit.hrl").

-include("hund.hrl").

without_entity_id_test() ->
  Doc =
    "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"></samlp:AuthnRequest>",
  ?assertEqual({error, bad_issuer}, hund_xml:decode_authn_request(Doc)).


without_consumer_location_test() ->
  Doc =
    "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
    "<saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer>"
    "</samlp:AuthnRequest>",
  ?assertEqual({error, missing_consumer_location}, hund_xml:decode_authn_request(Doc)).


without_authn_context_class_test() ->
  Doc =
    "<samlp:AuthnRequest "
    "AssertionConsumerServiceURL=\"http://sp.example.com/demo1/index.php?acs\" "
    "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
    "<saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer>"
    "</samlp:AuthnRequest>",
  {ok, Decoded} = hund_xml:decode_authn_request(Doc),
  ?assertEqual(password, Decoded#saml_authnreq.authn_class).


decode_atuhn_request_test() ->
  Doc =
    "<samlp:AuthnRequest "
    "AssertionConsumerServiceURL=\"http://sp.example.com/demo1/index.php?acs\" "
    "ID=\"ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24\" Version=\"2.0\" ProviderName=\"SP test\" "
    "IssueInstant=\"2014-07-16T23:52:45Z\" Destination=\"http://idp.example.com/SSOService.php\" "
    "ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" "
    "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
    "<samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\" AllowCreate=\"true\" />"
    "<saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer>"
    "<samlp:RequestedAuthnContext Comparison=\"exact\">"
    "<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>"
    "</samlp:RequestedAuthnContext>"
    "</samlp:AuthnRequest>",
  {
    ok,
    #saml_authnreq{
      issuer = Issuer,
      consumer_location = ConsumerLocation,
      authn_class = AuthnClass,
      name_format = NameFormat,
      destination = Destination,
      version = Version,
      issue_instant = IssueInstant
    }
  } = hund_xml:decode_authn_request(Doc),
  ?assertEqual("2.0", Version),
  ?assertEqual({{2014, 7, 16}, {23, 52, 45}}, IssueInstant),
  ?assertEqual("http://idp.example.com/SSOService.php", Destination),
  ?assertEqual(email, NameFormat),
  ?assertEqual(password_protected_transport, AuthnClass),
  ?assertEqual("http://sp.example.com/demo1/index.php?acs", ConsumerLocation),
  ?assertEqual("http://sp.example.com/demo1/metadata.php", Issuer).
