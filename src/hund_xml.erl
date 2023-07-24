-module(hund_xml).

-include("../include/hund.hrl").

-include_lib("xmerl/include/xmerl.hrl").

-export([to_xml/1, build_nsinfo/2]).

-spec to_xml(Data :: hund:saml_record()) -> #xmlElement{}.
to_xml(
  #saml_idp_metadata{
    entity_id = EntityId,
    certificate = Certificate,
    login_location = LoginLocation,
    logout_location = LogoutLocation,
    org = #saml_org{name = OrgName, display_name = OrgDisplayName, url = OrgUrl},
    tech = #saml_contact{name = TechName, email = TechEmail},
    signed_request = SignedRequest,
    name_format = NameFormat
  }
) ->
  Ns =
    #xmlNamespace{
      nodes =
        [{md, "urn:oasis:names:tc:SAML:2.0:metadata"}, {ds, "http://www.w3.org/2000/09/xmldsig#"}]
    },
  KeyDescriptor =
    case is_binary(Certificate) of
      false -> [];

      true ->
        [
          #xmlElement{
            name = 'md:KeyDescriptor',
            attributes = [#xmlAttribute{name = use, value = "signing"}],
            content =
              [
                #xmlElement{
                  name = 'ds:KeyInfo',
                  content =
                    [
                      #xmlElement{
                        name = 'ds:X509Data',
                        content =
                          [
                            #xmlElement{
                              name = 'ds:X509Certificate',
                              content = [#xmlText{value = base64:encode_to_string(Certificate)}]
                            }
                          ]
                      }
                    ]
                }
              ]
          },
          #xmlElement{
            name = 'md:KeyDescriptor',
            attributes = [#xmlAttribute{name = use, value = "encryption"}],
            content =
              [
                #xmlElement{
                  name = 'ds:KeyInfo',
                  content =
                    [
                      #xmlElement{
                        name = 'ds:X509Data',
                        content =
                          [
                            #xmlElement{
                              name = 'ds:X509Certificate',
                              content = [#xmlText{value = base64:encode_to_string(Certificate)}]
                            }
                          ]
                      }
                    ]
                }
              ]
          }
        ]
    end,
  SSoElement =
    case LoginLocation of
      undefined -> [];

      _ ->
        [
          #xmlElement{
            name = 'md:SingleSignOnService',
            attributes =
              [
                #xmlAttribute{
                  name = 'Binding',
                  value = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                },
                #xmlAttribute{name = 'Location', value = LoginLocation},
                #xmlAttribute{name = index, value = "0"},
                #xmlAttribute{name = isDefault, value = "true"}
              ]
          },
          #xmlElement{
            name = 'md:SingleSignOnService',
            attributes =
              [
                #xmlAttribute{
                  name = 'Binding',
                  value = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                #xmlAttribute{name = 'Location', value = LoginLocation},
                #xmlAttribute{name = index, value = "1"}
              ]
          }
        ]
    end,
  SLoElement =
    case LogoutLocation of
      undefined -> [];

      _ ->
        [
          #xmlElement{
            name = 'md:SingleLogoutService',
            attributes =
              [
                #xmlAttribute{
                  name = 'Binding',
                  value = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                },
                #xmlAttribute{name = 'Location', value = LogoutLocation},
                #xmlAttribute{name = index, value = "0"},
                #xmlAttribute{name = isDefault, value = "true"}
              ]
          },
          #xmlElement{
            name = 'md:SingleLogoutService',
            attributes =
              [
                #xmlAttribute{
                  name = 'Binding',
                  value = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                #xmlAttribute{name = 'Location', value = LogoutLocation},
                #xmlAttribute{name = index, value = "1"}
              ]
          }
        ]
    end,
  OrgLocation =
    [
      #xmlElement{
        name = 'md:Organization',
        content =
          lang_elems(#xmlElement{name = 'md:OrganizationName'}, OrgName)
          ++
          lang_elems(#xmlElement{name = 'md:OrganizationDisplayName'}, OrgDisplayName)
          ++
          lang_elems(#xmlElement{name = 'md:OrganizationURL'}, OrgUrl)
      }
    ],
  TechElement =
    [
      #xmlElement{
        name = 'md:ContactPerson',
        content =
          [
            #xmlElement{name = 'md:GivenName', content = [#xmlText{value = TechName}]},
            #xmlElement{name = 'md:EmailAddress', content = [#xmlText{value = TechEmail}]}
          ],
        attributes = [#xmlAttribute{name = contactType, value = "technical"}]
      }
    ],
  NameIdElement =
    [
      #xmlElement{
        name = 'md:NameIDFormat',
        content = [#xmlText{value = hund:rev_nameid_map(NameFormat)}]
      }
    ],
  IDPSSODescriptor =
    [
      #xmlElement{
        name = 'md:IDPSSODescriptor',
        content = KeyDescriptor ++ SSoElement ++ SLoElement ++ NameIdElement,
        attributes =
          [#xmlAttribute{name = 'WantAuthnRequestsSigned', value = atom_to_list(SignedRequest)}]
      }
    ],
  build_nsinfo(
    Ns,
    #xmlElement{
      name = 'md:EntityDescriptor',
      content = IDPSSODescriptor ++ OrgLocation ++ TechElement,
      attributes =
        [
          #xmlAttribute{name = entityID, value = EntityId},
          #xmlAttribute{name = 'xmlns:md', value = proplists:get_value(md, Ns#xmlNamespace.nodes)},
          #xmlAttribute{name = 'xmlns:ds', value = proplists:get_value(ds, Ns#xmlNamespace.nodes)}
        ]
    }
  );

to_xml(
  #saml_assertion{
    issuer = Issuer,
    status = Status,
    recipient = Recipient,
    conditions =
      #saml_condition{
        not_before = ConditionNotBefore,
        not_on_or_after = ConditionNotOnOrAfter,
        audience = Audience
      },
    attributes = Attributes,
    authn =
      #saml_authn{
        authn_instant = AuthnInstant,
        session_not_on_or_after = SessionNotOnOrAfter,
        session_index = SessionIndex,
        authn_class = AuthnClass
      },
    subject =
      #saml_subject{
        in_response_to = InResponseTo,
        confirmation_method = ConfirmationMethod,
        name = Name,
        name_format = NameFormat,
        not_on_or_after = Notonorafter,
        sp_name_qualifier = SpNameQualifier
      }
  }
) ->
  Ns =
    #xmlNamespace{
      nodes =
        [
          {samlp, "urn:oasis:names:tc:SAML:2.0:protocol"},
          {saml, "urn:oasis:names:tc:SAML:2.0:assertion"},
          {xsi, "http://www.w3.org/2001/XMLSchema-instance"},
          {xs, "http://www.w3.org/2001/XMLSchema"}
        ]
    },
  IssuerElement = [#xmlElement{name = 'saml:Issuer', content = [#xmlText{value = Issuer}]}],
  StatusElement =
    [
      #xmlElement{
        name = 'samlp:Status',
        content =
          [
            #xmlElement{
              name = 'samlp:StatusCode',
              attributes = [#xmlAttribute{name = 'Value', value = hund:rev_status_code_map(Status)}]
            }
          ]
      }
    ],
  AssertionSubjectElement =
    [
      #xmlElement{
        name = 'saml:Subject',
        content =
          [
            #xmlElement{
              name = 'saml:NameID',
              content = [#xmlText{value = Name}],
              attributes =
                [
                  #xmlAttribute{name = 'SPNameQualifier', value = SpNameQualifier},
                  #xmlAttribute{name = 'Format', value = hund:rev_nameid_map(NameFormat)}
                ]
            },
            #xmlElement{
              name = 'saml:SubjectConfirmation',
              attributes =
                [
                  #xmlAttribute{
                    name = 'Method',
                    value = hund:rev_subject_method_map(ConfirmationMethod)
                  }
                ],
              content =
                [
                  #xmlElement{
                    name = 'saml:SubjectConfirmationData',
                    attributes =
                      [
                        #xmlAttribute{
                          name = 'NotOnOrAfter',
                          value = hund:datetime_to_saml(Notonorafter)
                        },
                        #xmlAttribute{name = 'Recipient', value = Recipient},
                        #xmlAttribute{name = 'InResponseTo', value = InResponseTo}
                      ]
                  }
                ]
            }
          ]
      }
    ],
  ConditionElement =
    [
      #xmlElement{
        name = 'saml:Conditions',
        attributes =
          [
            #xmlAttribute{name = 'NotBefore', value = hund:datetime_to_saml(ConditionNotBefore)},
            #xmlAttribute{
              name = 'NotOnOrAfter',
              value = hund:datetime_to_saml(ConditionNotOnOrAfter)
            }
          ],
        content =
          [
            #xmlElement{
              name = 'saml:AudienceRestriction',
              content =
                [#xmlElement{name = 'saml:Audience', content = [#xmlText{value = Audience}]}]
            }
          ]
      }
    ],
  AuthnStatement =
    [
      #xmlElement{
        name = 'saml:AuthnStatement',
        attributes =
          [
            #xmlAttribute{name = 'AuthnInstant', value = hund:datetime_to_saml(AuthnInstant)},
            #xmlAttribute{name = 'SessionIndex', value = SessionIndex},
            #xmlAttribute{
              name = 'SessionNotOnOrAfter',
              value = hund:datetime_to_saml(SessionNotOnOrAfter)
            }
          ],
        content =
          [
            #xmlElement{
              name = 'saml:AuthnContext',
              content =
                [
                  #xmlElement{
                    name = 'saml:AuthnContextClassRef',
                    content = [#xmlText{value = hund:rev_map_authn_class(AuthnClass)}]
                  }
                ]
            }
          ]
      }
    ],
  AttributeStatement =
    [
      #xmlElement{
        name = 'saml:AttributeStatement',
        content =
          [
            #xmlElement{
              name = 'saml:Attribute',
              attributes =
                [
                  #xmlAttribute{name = 'Name', value = Key},
                  #xmlAttribute{
                    name = 'NameFormat',
                    value = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
                  }
                ],
              content =
                [
                  #xmlElement{
                    name = 'saml:AttributeValue',
                    attributes = [#xmlAttribute{name = 'xsi:type', value = xml_type_schema(Value)}],
                    content = [#xmlText{value = stringify(Value)}]
                  }
                ]
            }
            || {Key, Value} <- Attributes
          ]
      }
    ],
  Assertion =
    [
      #xmlElement{
        name = 'saml:Assertion',
        content =
          IssuerElement
          ++
          AssertionSubjectElement
          ++
          ConditionElement
          ++
          AuthnStatement
          ++
          AttributeStatement,
        attributes =
          [
            #xmlAttribute{name = 'Version', value = '2.0'},
            #xmlAttribute{
              name = 'IssueInstant',
              value = hund:datetime_to_saml(calendar:universal_time())
            }
          ]
      }
    ],
  % IssuerElement ++ StatusElement ++ Assertion
  build_nsinfo(
    Ns,
    #xmlElement{
      name = 'samlp:Response',
      content = IssuerElement ++ StatusElement ++ Assertion,
      attributes =
        [
          #xmlAttribute{name = 'xmlns:samlp', value = "urn:oasis:names:tc:SAML:2.0:protocol"},
          #xmlAttribute{name = 'xmlns:saml', value = "urn:oasis:names:tc:SAML:2.0:assertion"},
          #xmlAttribute{name = 'xmlns:xsi', value = "http://www.w3.org/2001/XMLSchema-instance"},
          #xmlAttribute{name = 'xmlns:xs', value = "http://www.w3.org/2001/XMLSchema"}
        ]
    }
  ).


-spec build_nsinfo(#xmlNamespace{}, #xmlElement{}) -> #xmlElement{}.
build_nsinfo(Ns, Attr = #xmlAttribute{name = Name}) ->
  case string:tokens(atom_to_list(Name), ":") of
    [NsPrefix, Rest] -> Attr#xmlAttribute{namespace = Ns, nsinfo = {NsPrefix, Rest}};
    _ -> Attr#xmlAttribute{namespace = Ns}
  end;

build_nsinfo(Ns, Elem = #xmlElement{name = Name, content = Children, attributes = Attrs}) ->
  Elem2 =
    case string:tokens(atom_to_list(Name), ":") of
      [NsPrefix, Rest] -> Elem#xmlElement{namespace = Ns, nsinfo = {NsPrefix, Rest}};
      _ -> Elem#xmlElement{namespace = Ns}
    end,
  Elem2#xmlElement{
    attributes = [build_nsinfo(Ns, Attr) || Attr <- Attrs],
    content = [build_nsinfo(Ns, Child) || Child <- Children]
  };

build_nsinfo(_Ns, Other) -> Other.


-spec lang_elems(#xmlElement{}, hund:localized_string()) -> [#xmlElement{}].
lang_elems(BaseTag, Vals = [{Lang, _} | _]) when is_atom(Lang) ->
  [
    BaseTag#xmlElement{
      attributes =
        BaseTag#xmlElement.attributes
        ++
        [#xmlAttribute{name = 'xml:lang', value = atom_to_list(L)}],
      content = BaseTag#xmlElement.content ++ [#xmlText{value = V}]
    }
    || {L, V} <- Vals
  ];

lang_elems(BaseTag, Val) ->
  [
    BaseTag#xmlElement{
      attributes =
        BaseTag#xmlElement.attributes ++ [#xmlAttribute{name = 'xml:lang', value = "en"}],
      content = BaseTag#xmlElement.content ++ [#xmlText{value = Val}]
    }
  ].

-spec xml_type_schema(Scalar :: term()) -> atom().
xml_type_schema(Scalar) when is_integer(Scalar) -> 'xs:integer';
xml_type_schema(Scalar) when is_boolean(Scalar) -> 'xs:boolean';
xml_type_schema(Scalar) when is_float(Scalar) -> 'xs:float';

xml_type_schema({{Year, Month, Day}})
when is_integer(Year) andalso is_integer(Month) andalso is_integer(Day) ->
  'xs:date';

xml_type_schema({{Year, Month, Day}, {Hour, Minute, Second}})
when is_integer(Year)
     andalso is_integer(Month) and is_integer(Day)
     andalso is_integer(Hour)
     andalso is_integer(Minute)
     andalso is_integer(Second) ->
  'xs:dateTime';

xml_type_schema(_) -> 'xs:string'.

-spec stringify(Scalar :: term()) -> string() | number().
stringify(Date = {Year, Month, Day})
when is_integer(Year) andalso is_integer(Month) andalso is_integer(Day) ->
  hund:date_to_saml(Date);

stringify(DateTime = {{Year, Month, Day}, {Hour, Minute, Second}})
when is_integer(Year)
     andalso is_integer(Month) and is_integer(Day)
     andalso is_integer(Hour)
     andalso is_integer(Minute)
     andalso is_integer(Second) ->
  hund:datetime_to_saml(DateTime);

stringify(Scalar) -> Scalar.
