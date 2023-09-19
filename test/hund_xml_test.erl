-module(hund_xml_test).

-include_lib("../include/hund.hrl").
-include_lib("../include/hund_xpath_macro.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("xmerl/include/xmerl.hrl").

collect_xpath([], _Xml, _Ns, Acc) -> Acc;

collect_xpath([{Key, Xpath} | Rest], Xml, Ns, Acc) ->
  Data =
    case xmerl_xpath:string(Xpath, Xml, [{namespace, Ns}]) of
      [#xmlText{value = Value}] -> [{Key, Value}];
      [#xmlAttribute{value = Value}] -> [{Key, Value}];
      Texts = [#xmlText{} | _Rest] -> [{Key, [Text#xmlText.value || Text <- Texts]}];
      Attrs = [#xmlAttribute{} | _Rest] -> [{Key, [Attr#xmlAttribute.value || Attr <- Attrs]}];
      _ -> []
    end,
  collect_xpath(Rest, Xml, Ns, Acc ++ Data).


build_nsinfo_test() ->
  Ns = #xmlNamespace{nodes = [{"foo", "urn:bar"}]},
  E1 = hund_xml:build_nsinfo(Ns, #xmlElement{name = foo, content = [#xmlText{value = bar}]}),
  ?assertEqual(E1#xmlElement.namespace, Ns),
  E2 =
    hund_xml:build_nsinfo(
      Ns,
      #xmlElement{
        name = 'foo:bar',
        content = [#xmlElement{name = 'foo:bie'}],
        attributes = [#xmlAttribute{name = 'foo:faa', value = bar}]
      }
    ),
  ?assertEqual(E2#xmlElement.namespace, Ns),
  ?assertEqual(E2#xmlElement.nsinfo, {"foo", "bar"}),
  [E3 | _] = E2#xmlElement.content,
  ?assertEqual(E3#xmlElement.namespace, Ns),
  [Attr | _] = E2#xmlElement.attributes,
  ?assertEqual(Attr#xmlAttribute.namespace, Ns).


generate_idp_metadata_test() ->
  {[_, Pub], _Pivate} = crypto:generate_key(rsa, {2048, 3}),
  Xml =
    hund_xml:to_xml(
      #saml_idp_metadata{
        entity_id = "urn:sp-security:test",
        signed_request = false,
        certificate = Pub,
        login_location = "https://sp-security.com/accounts/login",
        logout_location = "https://sp-security.com/accounts/logout",
        name_format = email
      }
    ),
  Ns = [{md, "urn:oasis:names:tc:SAML:2.0:metadata"}, {ds, "http://www.w3.org/2000/09/xmldsig#"}],
  {ok, Decoded} =
    hund:threaduntil(
      [
        ?xpath_attr("/md:EntityDescriptor/@entityID", saml_idp_metadata, entity_id),
        ?xpath_attr(
          "/md:EntityDescriptor/md:IDPSSODescriptor/@WantAuthnRequestsSigned",
          saml_idp_metadata,
          signed_request
        ),
        ?xpath_text(
          "/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor[@use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate/text()",
          saml_idp_metadata,
          certificate
        ),
        ?xpath_attr(
          "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']/@Location",
          saml_idp_metadata,
          login_location
        ),
        ?xpath_attr(
          "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']/@Location",
          saml_idp_metadata,
          logout_location
        ),
        ?xpath_text(
          "/md:EntityDescriptor/md:IDPSSODescriptor/md:NameIDFormat/text()",
          saml_idp_metadata,
          name_format
        )
      ],
      #saml_idp_metadata{}
    ),
  ?assertEqual(Decoded#saml_idp_metadata.entity_id, "urn:sp-security:test"),
  ?assertEqual(Decoded#saml_idp_metadata.certificate, base64:encode_to_string(Pub)),
  ?assertEqual(Decoded#saml_idp_metadata.login_location, "https://sp-security.com/accounts/login"),
  ?assertEqual(Decoded#saml_idp_metadata.logout_location, "https://sp-security.com/accounts/logout"),
  ?assertEqual(
    Decoded#saml_idp_metadata.name_format,
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  ),
  ?assertEqual(Decoded#saml_idp_metadata.signed_request, "false").


build_saml_assertion_test() ->
  Xml =
    hund_xml:to_xml(
      #saml_assertion{
        issuer = "urn:sp-test:com",
        status = bad_version,
        recipient = "urn:idp-test:com"
      }
    ),
  xmerl:export([Xml], xmerl_xml),
  Ns =
    [
      {samlp, "urn:oasis:names:tc:SAML:2.0:protocol"},
      {saml, "urn:oasis:names:tc:SAML:2.0:assertion"},
      {xsi, "http://www.w3.org/2001/XMLSchema-instance"},
      {xs, "http://www.w3.org/2001/XMLSchema"}
    ],
  {ok, Decoded} =
    hund:threaduntil(
      [
        ?xpath_text("/samlp:Response/saml:Issuer/text()", saml_assertion, issuer),
        ?xpath_attr("/samlp:Response/samlp:Status/samlp:StatusCode/@Value", saml_assertion, status),
        ?xpath_attr(
          "/samlp:Response/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Recipient",
          saml_assertion,
          recipient
        )
      ],
      #saml_assertion{}
    ),
  ?assertEqual(Decoded#saml_assertion.status, "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"),
  ?assertEqual(Decoded#saml_assertion.recipient, "urn:idp-test:com"),
  ?assertEqual(Decoded#saml_assertion.issuer, "urn:sp-test:com").


build_saml_assertion_subject_test() ->
  Root =
    hund_xml:to_xml(
      #saml_assertion{
        subject =
          #saml_subject{
            name = "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7",
            sp_name_qualifier = "http://sp.example.com/demo1/metadata.php",
            name_format = transient,
            not_on_or_after = {{2023, 7, 23}, {18, 30, 3}},
            confirmation_method = bearer,
            in_response_to = "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"
          }
      }
    ),
  Ns =
    [
      {samlp, "urn:oasis:names:tc:SAML:2.0:protocol"},
      {saml, "urn:oasis:names:tc:SAML:2.0:assertion"},
      {xsi, "http://www.w3.org/2001/XMLSchema-instance"},
      {xs, "http://www.w3.org/2001/XMLSchema"}
    ],
  [Xml] =
    xmerl_xpath:string("/samlp:Response/saml:Assertion/saml:Subject", Root, [{namespace, Ns}]),
  Decoded =
    collect_xpath(
      [
        {name, "/saml:Subject/saml:NameID/text()"},
        {sp_name_qualifier, "/saml:Subject/saml:NameID/@SPNameQualifier"},
        {name_format, "/saml:Subject/saml:NameID/@Format"},
        {
          not_on_or_after,
          "/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter"
        },
        {confirmation_method, "/saml:Subject/saml:SubjectConfirmation/@Method"},
        {
          in_response_to,
          "/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@InResponseTo"
        }
      ],
      Xml,
      Ns,
      []
    ),
  ?assertEqual(
    Decoded,
    [
      {name, "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7"},
      {sp_name_qualifier, "http://sp.example.com/demo1/metadata.php"},
      {name_format, "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"},
      {not_on_or_after, "2023-07-23T18:30:03Z"},
      {confirmation_method, "urn:oasis:names:tc:SAML:2.0:cm:bearer"},
      {in_response_to, "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"}
    ]
  ).


build_saml_assertion_context_test() ->
  Root =
    hund_xml:to_xml(
      #saml_assertion{
        authn =
          #saml_authn{
            authn_instant = {{2023, 4, 20}, {20, 20, 20}},
            session_not_on_or_after = {{2023, 12, 20}, {20, 20, 20}},
            session_index = "_be9967abd904ddcae3c0eb4189adbe3f71e327cf93",
            authn_class = internet_protocol
          }
      }
    ),
  Ns =
    [
      {samlp, "urn:oasis:names:tc:SAML:2.0:protocol"},
      {saml, "urn:oasis:names:tc:SAML:2.0:assertion"},
      {xsi, "http://www.w3.org/2001/XMLSchema-instance"},
      {xs, "http://www.w3.org/2001/XMLSchema"}
    ],
  [Xml] =
    xmerl_xpath:string(
      "/samlp:Response/saml:Assertion/saml:AuthnStatement",
      Root,
      [{namespace, Ns}]
    ),
  Decoded =
    collect_xpath(
      [
        {authn_instant, "/saml:AuthnStatement/@AuthnInstant"},
        {session_not_on_or_after, "/saml:AuthnStatement/@SessionNotOnOrAfter"},
        {session_index, "/saml:AuthnStatement/@SessionIndex"},
        {authn_class, "/saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef/text()"}
      ],
      Xml,
      Ns,
      []
    ),
  ?assertEqual(
    Decoded,
    [
      {authn_instant, "2023-04-20T20:20:20Z"},
      {session_not_on_or_after, "2023-12-20T20:20:20Z"},
      {session_index, "_be9967abd904ddcae3c0eb4189adbe3f71e327cf93"},
      {authn_class, "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol"}
    ]
  ).


build_saml_assertion_conditions_test() ->
  Root =
    hund_xml:to_xml(
      #saml_assertion{
        conditions =
          #saml_condition{
            audience = "http://sp.example.com/demo1/metadata.php",
            not_before = {{2022, 4, 3}, {18, 30, 0}},
            not_on_or_after = {{2024, 4, 3}, {18, 30, 0}}
          }
      }
    ),
  Ns =
    [
      {samlp, "urn:oasis:names:tc:SAML:2.0:protocol"},
      {saml, "urn:oasis:names:tc:SAML:2.0:assertion"},
      {xsi, "http://www.w3.org/2001/XMLSchema-instance"},
      {xs, "http://www.w3.org/2001/XMLSchema"}
    ],
  [Xml] =
    xmerl_xpath:string("/samlp:Response/saml:Assertion/saml:Conditions", Root, [{namespace, Ns}]),
  Decoded =
    collect_xpath(
      [
        {audience, "/saml:Conditions/saml:AudienceRestriction/saml:Audience/text()"},
        {not_before, "/saml:Conditions/@NotBefore"},
        {not_on_or_after, "/saml:Conditions/@NotOnOrAfter"}
      ],
      Xml,
      Ns,
      []
    ),
  ?assertEqual(
    Decoded,
    [
      {audience, "http://sp.example.com/demo1/metadata.php"},
      {not_before, "2022-04-03T18:30:00Z"},
      {not_on_or_after, "2024-04-03T18:30:00Z"}
    ]
  ).


build_saml_assertion_attributes_test() ->
  Root =
    hund_xml:to_xml(
      #saml_assertion{
        attributes =
          [
            {name, "Alice"},
            {email, "alice@example.com"},
            {id, 20302},
            {created_at, {{2022, 4, 3}, {18, 30, 0}}}
          ]
      }
    ),
  Ns =
    [
      {samlp, "urn:oasis:names:tc:SAML:2.0:protocol"},
      {saml, "urn:oasis:names:tc:SAML:2.0:assertion"},
      {xsi, "http://www.w3.org/2001/XMLSchema-instance"},
      {xs, "http://www.w3.org/2001/XMLSchema"}
    ],
  [Xml] =
    xmerl_xpath:string(
      "/samlp:Response/saml:Assertion/saml:AttributeStatement",
      Root,
      [{namespace, Ns}]
    ),
  Decoded =
    collect_xpath(
      [
        {attribute_names, "/saml:AttributeStatement/saml:Attribute/@Name"},
        {attribute_types, "/saml:AttributeStatement/saml:Attribute/saml:AttributeValue/@xsi:type"},
        {attributes_values, "/saml:AttributeStatement/saml:Attribute/saml:AttributeValue/text()"}
      ],
      Xml,
      Ns,
      []
    ),
  ?assertEqual(
    Decoded,
    [
      {attribute_names, [name, email, id, created_at]},
      {attribute_types, ['xs:string', 'xs:string', 'xs:integer', 'xs:dateTime']},
      {attributes_values, ["Alice", "alice@example.com", 20302, "2022-04-03T18:30:00Z"]}
    ]
  ).


build_saml_logout_response_test() ->
  Xml =
    hund_xml:to_xml(
      #saml_logout_response{
        destination = "http://sp.example.com/demo1/index.php?acs",
        in_response_to = "ONELOGIN_21df91a89767879fc0f7df6a1490c6000c81644d",
        issue_instant = {{2023, 7, 4}, {20, 30, 0}},
        status = success,
        issuer = "http://idp.example.com/metadata.php"
      }
    ),
  Ns =
    [
      {samlp, "urn:oasis:names:tc:SAML:2.0:protocol"},
      {saml, "urn:oasis:names:tc:SAML:2.0:assertion"}
    ],
  Decoded =
    collect_xpath(
      [
        {destination, "/samlp:LogoutResponse/@Destination"},
        {in_response_to, "/samlp:LogoutResponse/@InResponseTo"},
        {issue_instant, "/samlp:LogoutResponse/@IssueInstant"},
        {status, "/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/@Value"},
        {issuer, "/samlp:LogoutResponse/saml:Issuer/text()"}
      ],
      Xml,
      Ns,
      []
    ),
  ?assertEqual(
    [
      {destination, "http://sp.example.com/demo1/index.php?acs"},
      {in_response_to, "ONELOGIN_21df91a89767879fc0f7df6a1490c6000c81644d"},
      {issue_instant, "2023-07-04T20:30:00Z"},
      {status, "urn:oasis:names:tc:SAML:2.0:status:Success"},
      {issuer, "http://idp.example.com/metadata.php"}
    ],
    Decoded
  ).
