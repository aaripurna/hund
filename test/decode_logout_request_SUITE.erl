-module(decode_logout_request_SUITE).

-include("hund.hrl").

-include_lib("eunit/include/eunit.hrl").

without_issuer_test() ->
  Doc =
    "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
    "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" >"
    "</samlp:LogoutRequest>",
  ?assertEqual({error, bad_issuer}, hund_xml:decode_logout_request(Doc)).


decode_logout_request_test() ->
  Doc =
    "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
    "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" "
    "ID=\"ONELOGIN_21df91a89767879fc0f7df6a1490c6000c81644d\" Version=\"2.0\" "
    "IssueInstant=\"2014-07-18T01:13:06Z\" Destination=\"http://idp.example.com/SingleLogoutService.php\">"
    "<saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer>"
    "<saml:NameID SPNameQualifier=\"http://sp.example.com/demo1/metadata.php\" "
    "Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">"
    "ONELOGIN_f92cc1834efc0f73e9c09f482fce80037a6251e7</saml:NameID>"
    "</samlp:LogoutRequest>",
  {
    ok,
    #saml_logout_request{
      issuer = Issuer,
      issue_instant = IssueInstant,
      sp_name_qualifier = SpNameQualifier,
      name_format = NameFormat,
      name = Name
    }
  } = hund_xml:decode_logout_request(Doc),
  ?assertEqual(transient, NameFormat),
  ?assertEqual("ONELOGIN_f92cc1834efc0f73e9c09f482fce80037a6251e7", Name),
  ?assertEqual("http://sp.example.com/demo1/metadata.php", SpNameQualifier),
  ?assertEqual({{2014, 7, 18}, {1, 13, 6}}, IssueInstant),
  ?assertEqual("http://sp.example.com/demo1/metadata.php", Issuer).
