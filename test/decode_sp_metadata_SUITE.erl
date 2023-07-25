-module(decode_sp_metadata_SUITE).

-include_lib("eunit/include/eunit.hrl").

-include("hund.hrl").

metadata_without_entity_id_test() ->
  Doc =
    "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"></md:EntityDescriptor>",
  ?assertEqual({error, bad_entity}, hund_xml:decode_sp_metadata(Doc)).


metadata_wothout_consumer_test() ->
  Doc =
    "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"urn:bibi.com:sp_is\"><md:SPSSODescriptor><md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" index=\"1\" /></md:SPSSODescriptor></md:EntityDescriptor>",
  ?assertEqual({error, missing_consumer_location}, hund_xml:decode_sp_metadata(Doc)).


decode_metadata_test() ->
  Base64 =
    "MIIDuzCCAqOgAwIBAgIUf/mmRI53FmyUE06pvSAgJkqUUO8wDQYJKoZIhvcNAQELBQAwbTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xEDAOBgNVBAoMB0phbmt5Q28xHzAdBgNVBAMMFlRlc3QgSWRlbnRpdHkgUHJvdmlkZXIwHhcNMjMwNzE5MDIwMzM3WhcNNDMwNzE0MDIwMzM3WjBtMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEQMA4GA1UECgwHSmFua3lDbzEfMB0GA1UEAwwWVGVzdCBJZGVudGl0eSBQcm92aWRlcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKhPXAaSLCDij8r0ExfTIMyquG/neaO1CrI5pml7XAVQ5r+MHHfz2IVm6bvkiM4gMzZHEDu2tNRGn6xuKa7KMkcsvzIb+i+1IO7M7ccoM8wvwVVAIE5dN4dVVrfBwGjU8xlAl+/Ci+qrZzrlS+gMw4xO6nTJ24i92Mbgh/JZbpqZFsYyDBWbO7dYPNQc5+n1TUcPyAECaHD9ryDnGh6Omun9MiPHNbfD9bXK304IFesrOCSYg6gaVc6qeK9eb0TLTCF2A0NQRi9tv/ViXcBoORMSugtw+2tCE0BGlKs8siwxnHweaKu6mqwOtsnybXhBX2sOWggmmSPcKvSpwN5bSZcCAwEAAaNTMFEwHQYDVR0OBBYEFAxhaXaalBryAcy54N5+0905svx9MB8GA1UdIwQYMBaAFAxhaXaalBryAcy54N5+0905svx9MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAGlgqFrav4FfcICAPmYOQ6x3X0qDnnpJWJZ0782+1rcoSD05kX2aQCJCrxHdOhEJKoROrKeviqvx4gZiKaA497dZJIB+EuhvJ8DOkVwqvre8YhJuVOjkKTgu8ej6RJw30v3kl+MdyFDT71O+d08Zkidu8ewspUx9aKzGJbY/aRLNBMNtfpPB4ZTnk81D0eCAWNiQRT+3fVk/S1kDPFnzLx8MGb/7QLj4WRRNPUBizulMLOznsJlloMaDpopqq9l0XXB+PPeByIIq6kKv/HSXvFQEftdna7ssCCtbKBYZbPRyb/6ZWHX4OcXHS1AyhpJqMNTK7ehsEzHEFILBOJdUdTk=",
  Doc =
    "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"urn:bibi.com:sp_is\">"
    "<md:SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"false\">"
    "<md:KeyDescriptor use=\"signing\">"
    "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
    "<ds:X509Data>"
    "<ds:X509Certificate>"
    ++
    Base64
    ++
    "</ds:X509Certificate>"
    "</ds:X509Data>"
    "</ds:KeyInfo>"
    "</md:KeyDescriptor>"
    "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:3000/sso/signout\" />"
    "<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" index=\"1\" Location=\"https://localhost:3000/sso/signin\"/>"
    "</md:SPSSODescriptor>"
    "<md:Organization>"
    "<md:OrganizationName xml:lang=\"en-US\">Walrus</md:OrganizationName>"
    "<md:OrganizationDisplayName xml:lang=\"en-US\">Walrus Food Chain</md:OrganizationDisplayName>"
    "<md:OrganizationURL xml:lang=\"en-US\">https://walruscahin.com</md:OrganizationURL>"
    "</md:Organization>"
    "<md:ContactPerson contactType=\"technical\">"
    "<md:GivenName>Dev Walrus</md:GivenName>"
    "<md:EmailAddress>dev@walruschain.com</md:EmailAddress>"
    "</md:ContactPerson>"
    "</md:EntityDescriptor>",
  {
    ok,
    #saml_sp_metadata{
      entity_id = EntityId,
      consumer_location = ConsumerLocation,
      signed_request = SignedRequest,
      logout_location = LogoutLocation,
      signed_assertion = SignedAssertion,
      certificate = Certificate,
      org = Org,
      tech = Tech
    }
  } = hund_xml:decode_sp_metadata(Doc),
  ?assertEqual(
    #saml_org{display_name = "Walrus Food Chain", name = "Walrus", url = "https://walruscahin.com"},
    Org
  ),
  ?assertEqual(#saml_contact{email = "dev@walruschain.com", name = "Dev Walrus"}, Tech),
  ?assertEqual(false, SignedRequest),
  ?assertEqual(false, SignedAssertion),
  ?assertEqual(base64:decode_to_string(Base64), Certificate),
  ?assertEqual("http://localhost:3000/sso/signout", LogoutLocation),
  ?assertEqual("https://localhost:3000/sso/signin", ConsumerLocation),
  ?assertEqual("urn:bibi.com:sp_is", EntityId).
