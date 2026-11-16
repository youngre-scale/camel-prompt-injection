"""Regression tests for data dependencies, with no external tool or model calls."""

import ast

import pytest

from camel.capabilities import Capabilities, get_all_readers, get_all_sources, is_trusted, readers, sources
from camel.interpreter import interpreter, result, value
from camel.interpreter import namespace as ns
from camel.security_policy import NoSecurityPolicyEngine

UNTRUSTED_SOURCE = sources.Tool("external_data", frozenset())
PRIVATE = Capabilities(frozenset({UNTRUSTED_SOURCE}), frozenset({"authorized@example.com"}))
MODES = list(interpreter.MetadataEvalMode)


def evaluate(code, variables, mode):
    return interpreter.camel_eval(
        ast.parse(code),
        ns.Namespace.with_builtins(variables),
        [],
        (),
        interpreter.EvalArgs(NoSecurityPolicyEngine(), mode),
    )


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "expression",
    [
        "[x]",
        "(x,)",
        "{x}",
        "{x: 'value'}",
        "{'key': x}",
        "[[x], [x]]",
        "{'key': ([x],)}",
        "list((x,))",
        "tuple([x])",
        "set([x])",
        "str(x)",
        "repr(x)",
        "'{}'.format(x)",
        "'{item}'.format(item=x)",
        "''.join([x])",
        "''.join((x,))",
        "''.join({'key': x}.values())",
    ],
)
@pytest.mark.parametrize("private", [True, False])
def test_container_and_conversion_labels(expression, mode, private):
    caps = PRIVATE if private else Capabilities.camel()
    x = value.CaMeLStr.from_raw("data", caps, ())
    evaluated, namespace, _, _ = evaluate(f"out = {expression}", {"x": x}, mode)
    assert isinstance(evaluated, result.Ok)
    out = namespace.variables["out"]
    assert get_all_readers(out)[0] == caps.readers_set
    # Builtin results keep the existing Tool source, even for public inputs.
    literal_container = expression in {
        "[x]",
        "(x,)",
        "{x}",
        "{x: 'value'}",
        "{'key': x}",
        "[[x], [x]]",
        "{'key': ([x],)}",
    }
    assert is_trusted(out) is (not private and literal_container)
    if private:
        assert UNTRUSTED_SOURCE in get_all_sources(out)[0]
    assert x.metadata == caps


@pytest.mark.parametrize("mapping", [False, True])
def test_shared_references_and_container_cycles(mapping):
    secret = value.CaMeLStr.from_raw("secret", PRIVATE, ())
    shared = value.CaMeLList([secret], Capabilities.camel(), ())
    if mapping:
        root = value.CaMeLDict({}, Capabilities.camel(), ())
        for name, child in (("first", shared), ("second", shared), ("cycle", root)):
            root._python_value[value.CaMeLStr.from_raw(name, Capabilities.camel(), ())] = child
    else:
        root = value.CaMeLList[value.CaMeLValue]([shared, shared], Capabilities.camel(), ())
        root._python_value.append(root)
    assert get_all_readers(root)[0] == PRIVATE.readers_set
    assert UNTRUSTED_SOURCE in get_all_sources(root)[0]
    assert not is_trusted(root)


def test_deep_container_dependencies():
    root = value.CaMeLStr.from_raw("secret", PRIVATE, ())
    for _ in range(1500):
        root = value.CaMeLList([root], Capabilities.camel(), ())
    assert get_all_readers(root)[0] == PRIVATE.readers_set
    assert UNTRUSTED_SOURCE in get_all_sources(root)[0]


def test_dependency_queries_observe_mutation_and_copies():
    public = value.CaMeLStr.from_raw("public", Capabilities.camel(), ())
    secret = value.CaMeLStr.from_raw("secret", PRIVATE, ())
    root = value.CaMeLList([public], Capabilities.camel(), ())
    assert is_trusted(root)
    assert isinstance(get_all_readers(root)[0], readers.Public)
    root._python_value.append(secret)
    assert not is_trusted(root)
    assert get_all_readers(root)[0] == PRIVATE.readers_set
    root._python_value.pop()
    assert is_trusted(root)
    assert isinstance(get_all_readers(root)[0], readers.Public)
    for changed in (
        root.new_with_metadata(PRIVATE),
        root.new_with_dependencies((secret,)),
        root.new_with_python_value([secret]),
    ):
        assert not is_trusted(changed)
        assert get_all_readers(changed)[0] == PRIVATE.readers_set
    assert is_trusted(root)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "code, raw",
    [
        ("for item in items:\n    out = item", "data"),
        ("out = [item for item in items][0]", "data"),
        ("out = {item for item in items}", {"data"}),
        ("out = {item: item for item in items}['data']", "data"),
        ("for left, right in pairs:\n    out = right", "data"),
        ("out = [right for left, right in pairs][0]", "data"),
        ("out = [inner for row in nested for inner in row][0]", "data"),
        ("for item in mapping:\n    out = item", "data"),
        ("for item in text:\n    out = item", "a"),
        ("out = [item for item in text][0]", "d"),
        ("out = [item for item in text.split()][0]", "data"),
    ],
)
def test_iteration_retains_container_labels(code, raw, mode):
    namespace = ns.Namespace.with_builtins()
    variables = {
        "items": value.value_from_raw(["data"], PRIVATE, namespace, ()),
        "pairs": value.value_from_raw([("left", "data")], PRIVATE, namespace, ()),
        "nested": value.value_from_raw([["data"]], PRIVATE, namespace, ()),
        "mapping": value.value_from_raw({"data": "value"}, PRIVATE, namespace, ()),
        "text": value.CaMeLStr.from_raw("data", PRIVATE, ()),
    }
    evaluated, namespace, _, _ = evaluate(code, variables, mode)
    assert isinstance(evaluated, result.Ok)
    out = namespace.variables["out"]
    assert out.raw == raw
    assert not is_trusted(out)
    assert get_all_readers(out)[0] == PRIVATE.readers_set


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "declaration, call",
    [
        ("@dataclass\nclass Record:\n    field: str", "Record(x)"),
        ("@dataclass\nclass Record:\n    field: str", "Record(field=x)"),
        ("class Record(BaseModel):\n    field: str", "Record(field=x)"),
    ],
)
@pytest.mark.parametrize("private", [True, False])
def test_constructor_and_raw_field_labels(declaration, call, mode, private):
    caps = PRIVATE if private else Capabilities.camel()
    x = value.CaMeLStr.from_raw("data", caps, ())
    evaluated, namespace, _, _ = evaluate(
        f"{declaration}\nrecord = {call}\nout = record.field",
        {"x": x},
        mode,
    )
    assert isinstance(evaluated, result.Ok)
    assert namespace.variables["out"].raw == "data"
    for name in ("record", "out"):
        assert get_all_readers(namespace.variables[name])[0] == caps.readers_set
        assert is_trusted(namespace.variables[name]) is (not private)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "expression, raw",
    [
        ('f"{empty}suffix"', "suffix"),
        ('f"{empty}"', ""),
        ('f"{empty!r}"', "''"),
        ('f"{empty!s}"', ""),
        ('f"{text}{empty}"', "data"),
    ],
)
def test_f_string_retains_every_evaluated_component(expression, raw, mode):
    evaluated, namespace, _, _ = evaluate(
        "out = " + expression,
        {
            "empty": value.CaMeLStr.from_raw("", PRIVATE, ()),
            "text": value.CaMeLStr.from_raw("data", Capabilities.camel(), ()),
        },
        mode,
    )
    assert isinstance(evaluated, result.Ok)
    assert namespace.variables["out"].raw == raw
    assert not is_trusted(namespace.variables["out"])
    assert get_all_readers(namespace.variables["out"])[0] == PRIVATE.readers_set


@pytest.mark.parametrize("mode", MODES)
def test_modes_preserve_control_flow_difference(mode):
    flag = value.CaMeLTrue(PRIVATE, ())
    evaluated, namespace, _, _ = evaluate("if flag:\n    out = 'literal'", {"flag": flag}, mode)
    assert isinstance(evaluated, result.Ok)
    out = namespace.variables["out"]
    assert out.raw == "literal"
    assert is_trusted(out) is (mode == interpreter.MetadataEvalMode.NORMAL)


@pytest.mark.parametrize("mode", MODES)
def test_unsupported_constant_is_recoverable(mode):
    evaluated, namespace, calls, _ = evaluate("out = ...", {}, mode)
    assert isinstance(evaluated, result.Error)
    assert isinstance(evaluated.error.exception, NotImplementedError)
    assert str(evaluated.error.exception) == "unsupported constant type ellipsis"
    assert "out" not in namespace.variables
    assert not calls


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize(
    "declaration, call, raw",
    [
        ("@dataclass\nclass Record:\n    field: str", "Record(*items)", "data"),
        ("class Record(BaseModel):\n    field: str", "Record(**fields)", "data"),
    ],
)
def test_constructor_argument_unpacking_retains_parent_labels(declaration, call, raw, mode):
    public = value.CaMeLStr.from_raw(raw, Capabilities.camel(), ())
    evaluated, namespace, _, _ = evaluate(
        f"{declaration}\nrecord = {call}\nout = record.field",
        {
            "items": value.CaMeLList([public], PRIVATE, ()),
            "fields": value.CaMeLDict(
                {value.CaMeLStr.from_raw("field", Capabilities.camel(), ()): public}, PRIVATE, ()
            ),
        },
        mode,
    )
    assert isinstance(evaluated, result.Ok)
    assert namespace.variables["out"].raw == raw
    assert get_all_readers(namespace.variables["out"])[0] == PRIVATE.readers_set
    assert not is_trusted(namespace.variables["out"])
