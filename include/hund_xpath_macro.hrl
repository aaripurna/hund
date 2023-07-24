-define(
  xpath_generic(XPath, Record, Field, TransformFun, TargetType, NotFoundRet),
  fun
    (Resp) ->
      case xmerl_xpath:string(XPath, Xml, [{namespace, Ns}]) of
        [# TargetType {value = V}] -> Resp # Record {Field = TransformFun(V)};
        _ -> NotFoundRet
      end
  end
).
-define(
  xpath_generic(XPath, Record, Field, TargetType, NotFoundRet),
  fun
    (Resp) ->
      case xmerl_xpath:string(XPath, Xml, [{namespace, Ns}]) of
        [# TargetType {value = V}] -> Resp # Record {Field = V};
        _ -> NotFoundRet
      end
  end
).
-define(xpath_attr(XPath, Record, Field), ?xpath_generic(XPath, Record, Field, xmlAttribute, Resp)).
-define(
  xpath_attr(XPath, Record, Field, TransformFun),
  ?xpath_generic(XPath, Record, Field, TransformFun, xmlAttribute, Resp)
).
-define(
  xpath_attr_required(XPath, Record, Field, Error),
  ?xpath_generic(XPath, Record, Field, xmlAttribute, {error, Error})
).
-define(
  xpath_attr_required(XPath, Record, Field, TransformFun, Error),
  ?xpath_generic(XPath, Record, Field, TransformFun, xmlAttribute, {error, Error})
).
-define(xpath_text(XPath, Record, Field), ?xpath_generic(XPath, Record, Field, xmlText, Resp)).
-define(
  xpath_text(XPath, Record, Field, TransformFun),
  ?xpath_generic(XPath, Record, Field, TransformFun, xmlText, Resp)
).
-define(
  xpath_text_required(XPath, Record, Field, Error),
  ?xpath_generic(XPath, Record, Field, xmlText, {error, Error})
).
-define(
  xpath_text_required(XPath, Record, Field, TransformFun, Error),
  ?xpath_generic(XPath, Record, Field, TransformFun, xmlText, {error, Error})
).
-define(
  xpath_text_append(Xpath, Record, Field, Sep),
  fun
    (Resp) ->
      case xmerl_xpath:string(XPath, Xml, [{namespace, Ns}]) of
        [#xmlText{value = V}] when length(V) > 1 ->
          # Record {Field = CurrField} = Resp,
          Resp # Record {Field = CurrField ++ Sep ++ V};

        _ -> Resp
      end
  end
).
-define(
  xpath_recurse(Xpath, Record, Field, F),
  fun
    (Resp) ->
      case xmerl_xpath:string(Xpath, Xml, [{namespace, Ns}]) of
        [E = #xmlElement{}] ->
          case F(E) of
            {error, V} -> {error, V};
            {ok, V} -> Resp # Record {Filed = V}
          end;

        _ -> Resp
      end
  end
).
