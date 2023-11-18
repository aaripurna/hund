-record(
  saml_org,
  {
    name = "" :: hund:localized_string(),
    display_name = "" :: hund:localized_string(),
    url = "" :: hund:localized_string()
  }
).
-record(saml_contact, {name = "" :: string(), email = "" :: string()}).
-record(
  saml_idp_metadata,
  {
    entity_id = "" :: string(),
    org = #saml_org{} :: hund:org(),
    tech = #saml_contact{} :: hund:contact(),
    signed_request = true :: boolean(),
    certificate :: binary() | undefined,
    login_location = "" :: string(),
    logout_location :: string() | undefined,
    name_format = unknown :: hund:name_format()
  }
).
-record(
  saml_sp_metadata,
  {
    entity_id = "" :: string(),
    org = #saml_org{} :: hund:org(),
    tech = #saml_contact{} :: hund:contact(),
    signed_request = true :: boolean(),
    signed_assertion = true :: boolean(),
    certificate :: binary() | undefined,
    consumer_location = "" :: string(),
    logout_location :: string() | undefined
  }
).
-record(
  saml_authnreq,
  {
    version = "2.0" :: hund:version(),
    issue_instant = "" :: hund:datetime(),
    destination = "" :: string(),
    issuer = "" :: string(),
    name_format = undefined :: undefined | string(),
    consumer_location = "" :: string(),
    authn_class = password :: hund:authn_class()
  }
).
-record(
  saml_subject,
  {
    name = "" :: string(),
    name_qualifier = undefined :: undefined | string(),
    sp_name_qualifier = undefined :: undefined | string(),
    name_format = undefined :: undefined | string(),
    confirmation_method = bearer :: atom(),
    not_on_or_after = calendar:universal_time() :: calendar:datetime(),
    in_response_to = "" :: string()
  }
).
-record(
  saml_authn,
  {
    authn_instant = calendar:universal_time() :: calendar:datetime(),
    session_not_on_or_after = calendar:universal_time() :: calendar:datetime(),
    session_index :: string(),
    authn_class = password :: hund:authn_class()
  }
).
-record(
  saml_condition,
  {
    not_before = calendar:universal_time() :: calendar:datetime(),
    not_on_or_after = calendar:universal_time() :: calendar:datetime(),
    audience :: string()
  }
).
-record(
  saml_assertion,
  {
    recipient = "" :: string(),
    status = success :: hund:status_code(),
    issuer = "" :: string(),
    subject = #saml_subject{} :: hund:subject(),
    conditions = #saml_condition{} :: hund:condition(),
    attributes = [] :: proplists:proplist(),
    authn = #saml_authn{} :: hund:authn()
  }
).
-record(
  saml_logout_response,
  {
    in_response_to = "" :: string(),
    destination = "" :: string(),
    issue_instant = calendar:universal_time() :: calendar:datetime(),
    status = success :: hund:status_code(),
    issuer = "" :: string()
  }
).
-record(
  saml_logout_request,
  {
    issue_instant :: calendar:datetime(),
    issuer = "" :: string(),
    sp_name_qualifier = "" :: string(),
    name_format = "" :: hund:name_format(),
    name = "" :: string(),
    session_index = "" :: string(),
    destination = "" :: string()
  }
).
