"""Policy verdicts and simulated state changes; no model calls or scoring."""

import ast
import datetime
from typing import TypeVar, cast

import pydantic
import pytest
from agentdojo.default_suites.v1.tools.banking_client import Transaction
from agentdojo.default_suites.v1.tools.types import CalendarEvent, Email, EmailStatus
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite

from camel import quarantined_llm
from camel.capabilities import Capabilities, get_all_readers, is_trusted, readers, sources
from camel.interpreter import interpreter, result, value
from camel.interpreter import namespace as ns
from camel.pipeline_elements.agentdojo_function import make_agentdojo_namespace
from camel.pipeline_elements.security_policies import (
    BankingSecurityPolicyEngine,
    TravelSecurityPolicyEngine,
    WorkspaceSecurityPolicyEngine,
)
from camel.security_policy import Allowed, Denied, SecurityPolicyDeniedError

OWNER = "owner@example.com"
GUEST = "guest@example.com"
EXTERNAL = "external@example.com"
PAYEE = "ACCT-EXISTING"
NEW_PAYEE = "ACCT-SELECTED"
TRUSTED = Capabilities.default()
UNTRUSTED = Capabilities(frozenset({sources.Tool("external_data", frozenset())}), readers.Public())
PRIVATE = Capabilities(UNTRUSTED.sources_set, frozenset())
MODES = list(interpreter.MetadataEvalMode)
ENGINES = {
    "banking": BankingSecurityPolicyEngine,
    "workspace": WorkspaceSecurityPolicyEngine,
    "travel": TravelSecurityPolicyEngine,
}
_T = TypeVar("_T", bound=str | int | float | pydantic.BaseModel)


def wrapped(raw, caps=TRUSTED):
    return value.value_from_raw(raw, caps, ns.Namespace.with_builtins(), ())


def setup(suite_name):
    suite = get_suite("v1.2", suite_name)
    env = suite.load_and_inject_default_environment({})
    if suite_name == "banking":
        env.bank_account.balance = 123.0
        env.bank_account.transactions = []
        env.bank_account.scheduled_transactions = [
            Transaction(
                id=1,
                sender="me",
                recipient=PAYEE,
                amount=100.0,
                subject="Rent",
                date="2024-06-01",
                recurring=True,
            )
        ]
    else:
        env.inbox.account_email = OWNER
        env.inbox.emails = {
            "1": Email(
                id_="1",
                sender=GUEST,
                recipients=[OWNER],
                subject="Project sync",
                body="Private notes",
                status=EmailStatus.received,
            )
        }
        env.calendar.account_email = OWNER
        env.calendar.events = {
            "1": CalendarEvent(
                id_="1",
                title="Project sync",
                description="Private notes",
                location=None,
                start_time=datetime.datetime(2024, 6, 1, 10),
                end_time=datetime.datetime(2024, 6, 1, 11),
                participants=[OWNER, GUEST],
            )
        }
    runtime = FunctionsRuntime(suite.tools)
    return env, runtime, ENGINES[suite_name](env)


def execute(code, env, runtime, engine, mode, variables=None):
    namespace = ns.Namespace.with_builtins()
    namespace = namespace.add_variables(make_agentdojo_namespace(namespace, runtime, env))
    namespace = namespace.add_variables(variables or {})
    return interpreter.camel_eval(
        ast.parse(code),
        namespace,
        [],
        (),
        interpreter.EvalArgs(engine, mode),
    )


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("conversion", ["str", "repr", "format", "join"])
def test_bare_private_tool_returns_remain_private(conversion, mode):
    env, runtime, engine = setup("banking")
    expression = {
        "str": "str(get_balance())",
        "repr": "repr(get_balance())",
        "format": "'{}'.format(get_balance())",
        "join": "''.join([read_file('private.txt')])",
    }[conversion]
    env.filesystem.files["private.txt"] = "private data"
    evaluated, namespace, _, _ = execute("out = " + expression, env, runtime, engine, mode)
    assert isinstance(evaluated, result.Ok)
    assert get_all_readers(namespace.variables["out"])[0] == frozenset()


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("suite_name", ["travel", "workspace"])
@pytest.mark.parametrize("trusted", [False, True])
def test_recipient_container_does_not_bypass_body_check(suite_name, trusted, mode):
    env, runtime, engine = setup(suite_name)
    code = "send_email([address], 'Notes', secret)"
    variables = {"address": wrapped(EXTERNAL, TRUSTED if trusted else UNTRUSTED), "secret": wrapped("private", PRIVATE)}
    if trusted:
        evaluated, _, _, _ = execute(code, env, runtime, engine, mode, variables)
        assert isinstance(evaluated, result.Ok)
        assert len(env.inbox.sent) == 1
        email = env.inbox.sent[0]
        assert email.recipients == [EXTERNAL]
        assert email.body == "private"
    else:
        with pytest.raises(SecurityPolicyDeniedError):
            execute(code, env, runtime, engine, mode, variables)
        assert not env.inbox.sent


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("query", ["page", "str(page)", "'Extract: {}'.format(page)", "'Extract: ' + page"])
def test_extracted_recipient_and_private_tool_data(query, mode):
    env, runtime, engine = setup("travel")

    def query_ai_assistant(query: str, output_schema: type[_T]) -> _T:
        return cast(_T, EXTERNAL)

    query_ai_assistant.__doc__ = quarantined_llm.query_quarantined_llm.__doc__
    runtime.register_function(query_ai_assistant)
    code = f"address = query_ai_assistant({query}, str)\nsend_email([address], 'Notes', str(get_user_information()))"
    with pytest.raises(SecurityPolicyDeniedError):
        execute(code, env, runtime, engine, mode, {"page": wrapped("Contact: " + EXTERNAL, UNTRUSTED)})
    assert not env.inbox.sent


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("path", ["iteration", "constructor", "iteration_and_constructor"])
@pytest.mark.parametrize("trusted", [False, True])
def test_scheduled_payment_selection_and_reconstruction(path, trusted, mode):
    env, runtime, engine = setup("banking")

    def query_ai_assistant(query: str, output_schema: type[_T]) -> _T:
        schema = cast(type[pydantic.BaseModel], output_schema)
        return cast(_T, schema(items=[{"account": NEW_PAYEE}]))

    query_ai_assistant.__doc__ = quarantined_llm.query_quarantined_llm.__doc__
    runtime.register_function(query_ai_assistant)
    code = "class Payee(BaseModel):\n    account: str\nclass Payees(BaseModel):\n    items: list[Payee]\n"
    if trusted:
        code += "parsed = Payees(items=[Payee(account='ACCT-SELECTED')])\n"
    else:
        code += "parsed = query_ai_assistant('Extract: ' + page, Payees)\n"
    if path == "iteration":
        code += "for item in parsed.items:\n    account = item.account\n"
    elif path == "constructor":
        code += "rebuilt = Payee(account=parsed.items[0].account)\naccount = rebuilt.account\n"
    else:
        code += "for item in parsed.items:\n    chosen = item\nrebuilt = Payee(account=chosen.account)\naccount = rebuilt.account\n"
    code += "update_scheduled_transaction(id=1, recipient=account, amount=120.0, subject='Rent', date='2024-07-01')"
    variables = {"page": wrapped("Payee: " + NEW_PAYEE, TRUSTED if trusted else UNTRUSTED)}
    before = env.bank_account.scheduled_transactions[0].model_copy(deep=True)
    if trusted:
        evaluated, namespace, _, _ = execute(code, env, runtime, engine, mode, variables)
        assert isinstance(evaluated, result.Ok)
        assert is_trusted(namespace.variables["account"])
        transaction = env.bank_account.scheduled_transactions[0]
        assert transaction.recipient == NEW_PAYEE
        assert transaction.amount == 120.0
        assert transaction.date == "2024-07-01"
    else:
        with pytest.raises(SecurityPolicyDeniedError):
            execute(code, env, runtime, engine, mode, variables)
        assert env.bank_account.scheduled_transactions[0] == before
    assert not env.bank_account.transactions


@pytest.mark.parametrize("trusted", [False, True])
def test_delete_email_verdict_and_state(trusted):
    env, runtime, engine = setup("workspace")
    email_id = wrapped("1", TRUSTED if trusted else UNTRUSTED)
    verdict = engine.delete_email_policy("delete_email", {"email_id": email_id})
    assert isinstance(verdict, Allowed if trusted else Denied)
    if trusted:
        evaluated, _, _, _ = execute("delete_email(email_id)", env, runtime, engine, MODES[0], {"email_id": email_id})
        assert isinstance(evaluated, result.Ok)
        assert "1" not in env.inbox.emails
    else:
        with pytest.raises(SecurityPolicyDeniedError):
            execute("delete_email(email_id)", env, runtime, engine, MODES[0], {"email_id": email_id})
        assert "1" in env.inbox.emails


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("event_trusted", [False, True])
@pytest.mark.parametrize("participants_trusted", [False, True])
def test_participant_policy_checks_participants(event_trusted, participants_trusted, mode):
    env, runtime, engine = setup("workspace")
    kwargs = {
        "event_id": wrapped("1", TRUSTED if event_trusted else UNTRUSTED),
        "participants": value.CaMeLList(
            [wrapped(EXTERNAL, TRUSTED if participants_trusted else UNTRUSTED)], TRUSTED, ()
        ),
    }
    verdict = engine.add_calendar_event_participants_policy("add_calendar_event_participants", kwargs)
    assert isinstance(verdict, Allowed if participants_trusted else Denied)
    code = (
        ("event = search_calendar_events('Project sync')[0]\nadd_calendar_event_participants(event.id_, participants)")
        if not event_trusted
        else "add_calendar_event_participants(event_id, participants)"
    )
    before = env.calendar.events["1"].model_copy(deep=True)
    if participants_trusted:
        evaluated, _, _, _ = execute(code, env, runtime, engine, mode, kwargs)
        assert isinstance(evaluated, result.Ok)
        assert env.calendar.events["1"].participants == [OWNER, GUEST, EXTERNAL]
    else:
        assert isinstance(verdict, Denied)
        assert verdict.reason == "Participants do not come directly from the user"
        with pytest.raises(SecurityPolicyDeniedError):
            execute(code, env, runtime, engine, mode, kwargs)
        assert env.calendar.events["1"] == before
        with pytest.raises(SecurityPolicyDeniedError):
            execute(
                "event = search_calendar_events('Project sync')[0]\nsend_email(participants, 'Notes', event.description)",
                env,
                runtime,
                engine,
                mode,
                kwargs,
            )
        assert not env.inbox.sent


@pytest.mark.parametrize(
    "tool, kwargs",
    [
        (
            "reserve_car_rental",
            {"company": "Example Cars", "start_time": "2024-06-01 09:00", "end_time": "2024-06-02 09:00"},
        ),
        ("reserve_restaurant", {"restaurant": "Example Bistro", "start_time": "2024-06-01 19:00"}),
    ],
)
def test_reservation_fields_verdict_and_state(tool, kwargs):
    env, runtime, engine = setup("travel")
    policy = dict(engine.policies)[tool]
    wrapped_kwargs = {key: wrapped(raw) for key, raw in kwargs.items()}
    assert isinstance(policy(tool, wrapped_kwargs), Allowed)
    for field in kwargs:
        bad = wrapped_kwargs | {field: wrapped(kwargs[field], UNTRUSTED)}
        assert isinstance(policy(tool, bad), Denied)
        before = env.reservation.model_copy(deep=True)
        with pytest.raises(SecurityPolicyDeniedError):
            execute(
                f"{tool}(**arguments)",
                env,
                runtime,
                engine,
                MODES[0],
                {
                    "arguments": value.CaMeLDict(
                        {wrapped(key): val for key, val in bad.items()},
                        TRUSTED,
                        (),
                    )
                },
            )
        assert env.reservation == before
    evaluated, _, _, _ = execute(
        f"{tool}(**arguments)",
        env,
        runtime,
        engine,
        MODES[0],
        {
            "arguments": value.CaMeLDict({wrapped(key): val for key, val in wrapped_kwargs.items()}, TRUSTED, ()),
        },
    )
    assert isinstance(evaluated, result.Ok)
    assert env.reservation.title == kwargs.get("company", kwargs.get("restaurant"))
    assert env.reservation.start_time == datetime.datetime.fromisoformat(kwargs["start_time"])


@pytest.mark.parametrize("suite_name", ["workspace", "travel"])
@pytest.mark.parametrize("optional", ["", ", participants=None", ", participants=[]", ", participants=[owner]"])
def test_calendar_creation_defaults(suite_name, optional):
    env, runtime, engine = setup(suite_name)
    evaluated, _, _, _ = execute(
        "create_calendar_event(title='Lunch', start_time='2024-06-02 12:00', end_time='2024-06-02 13:00'"
        + optional
        + ")",
        env,
        runtime,
        engine,
        MODES[0],
        {"owner": wrapped(OWNER)},
    )
    assert isinstance(evaluated, result.Ok)
    event = env.calendar.events["2"]
    assert event.participants == [OWNER]
    assert event.description == ""
    assert event.location is None
    email = env.inbox.sent[0]
    assert email.recipients == [OWNER, OWNER] if "participants=[owner]" in optional else email.recipients == [OWNER]


@pytest.mark.parametrize("suite_name", ["workspace", "travel"])
@pytest.mark.parametrize("field", ["title", "description", "location", "start_time", "end_time"])
@pytest.mark.parametrize("readable", [False, True])
def test_calendar_creation_reader_checks(suite_name, field, readable):
    env, runtime, engine = setup(suite_name)
    kwargs = {
        "title": wrapped("Meeting"),
        "start_time": wrapped("2024-06-02 12:00"),
        "end_time": wrapped("2024-06-02 13:00"),
        "description": wrapped("Notes"),
        "location": wrapped("Room"),
        "participants": wrapped([EXTERNAL], UNTRUSTED),
    }
    caps = Capabilities(UNTRUSTED.sources_set, frozenset({EXTERNAL, OWNER}) if readable else frozenset())
    kwargs[field] = wrapped(kwargs[field].raw, caps)
    verdict = engine.create_calendar_event_policy("create_calendar_event", kwargs)
    assert isinstance(verdict, Allowed if readable else Denied)
    arguments = value.CaMeLDict({wrapped(key): val for key, val in kwargs.items()}, TRUSTED, ())
    if readable:
        evaluated, _, _, _ = execute(
            "create_calendar_event(**arguments)", env, runtime, engine, MODES[0], {"arguments": arguments}
        )
        assert isinstance(evaluated, result.Ok)
        assert set(env.calendar.events["2"].participants) == {OWNER, EXTERNAL}
        assert len(env.inbox.sent) == 1
    else:
        with pytest.raises(SecurityPolicyDeniedError):
            execute("create_calendar_event(**arguments)", env, runtime, engine, MODES[0], {"arguments": arguments})
        assert set(env.calendar.events) == {"1"}
        assert not env.inbox.sent


@pytest.mark.parametrize("suite_name", ["workspace", "travel"])
def test_calendar_optional_fields_with_untrusted_participants(suite_name):
    env, runtime, engine = setup(suite_name)
    evaluated, _, _, _ = execute(
        "create_calendar_event('Meeting', '2024-06-02 12:00', '2024-06-02 13:00', participants=participants)",
        env,
        runtime,
        engine,
        MODES[0],
        {"participants": wrapped([EXTERNAL], UNTRUSTED)},
    )
    assert isinstance(evaluated, result.Ok)
    assert env.calendar.events["2"].description == ""
    assert env.calendar.events["2"].location is None


@pytest.mark.parametrize("end", ["", ", new_end_time=None", ", new_end_time='2024-06-02 12:00'"])
def test_reschedule_optional_end_time_and_duration(end):
    env, runtime, engine = setup("workspace")
    evaluated, _, _, _ = execute(
        "reschedule_calendar_event('1', '2024-06-02 10:00'" + end + ")",
        env,
        runtime,
        engine,
        MODES[0],
    )
    assert isinstance(evaluated, result.Ok)
    event = env.calendar.events["1"]
    assert event.start_time == datetime.datetime(2024, 6, 2, 10)
    assert event.end_time == datetime.datetime(2024, 6, 2, 12 if "12:00" in end else 11)
    assert len(env.inbox.sent) == 1


@pytest.mark.parametrize("field", ["new_start_time", "new_end_time"])
def test_reschedule_rejects_unreadable_supplied_times(field):
    env, runtime, engine = setup("workspace")
    kwargs = {"event_id": wrapped("1"), "new_start_time": wrapped("2024-06-02 10:00")}
    kwargs[field] = wrapped("2024-06-02 10:00", PRIVATE)
    verdict = engine.reschedule_calendar_event_policy("reschedule_calendar_event", kwargs)
    assert isinstance(verdict, Denied)
    before = env.calendar.events["1"].model_copy(deep=True)
    with pytest.raises(SecurityPolicyDeniedError):
        execute(
            "reschedule_calendar_event(**arguments)",
            env,
            runtime,
            engine,
            MODES[0],
            {
                "arguments": value.CaMeLDict(
                    {wrapped(key): val for key, val in kwargs.items()},
                    TRUSTED,
                    (),
                )
            },
        )
    assert env.calendar.events["1"] == before
    assert not env.inbox.sent


@pytest.mark.parametrize("recipient", ["", ", recipient=None", ", recipient=''", ", recipient='ACCT-EXISTING'"])
def test_payment_update_uses_existing_payee(recipient):
    env, runtime, engine = setup("banking")
    evaluated, _, _, _ = execute(
        "update_scheduled_transaction(id=1, amount=120.0" + recipient + ")", env, runtime, engine, MODES[0]
    )
    assert isinstance(evaluated, result.Ok)
    transaction = env.bank_account.scheduled_transactions[0]
    assert transaction.recipient == PAYEE
    assert transaction.amount == 120.0
    assert transaction.subject == "Rent"
    assert transaction.date == "2024-06-01"


@pytest.mark.parametrize(
    "optional",
    [
        "",
        ", recipient=None, amount=None, subject=None, date=None, recurring=None",
        ", recipient='', amount=0.0, subject='', date='', recurring=False",
    ],
)
def test_payment_no_op_defaults(optional):
    env, runtime, engine = setup("banking")
    before = env.bank_account.scheduled_transactions[0].model_copy(deep=True)
    evaluated, _, _, _ = execute("update_scheduled_transaction(id=1" + optional + ")", env, runtime, engine, MODES[0])
    assert isinstance(evaluated, result.Ok)
    assert env.bank_account.scheduled_transactions[0] == before


@pytest.mark.parametrize("recipient", [None, "", PAYEE])
@pytest.mark.parametrize("field, raw", [("amount", 120.0), ("subject", "Private memo"), ("date", "2024-07-01")])
@pytest.mark.parametrize("readable", [False, True])
def test_payment_update_checks_supplied_payload_against_effective_payee(recipient, field, raw, readable):
    env, runtime, engine = setup("banking")
    kwargs = {
        "id": wrapped(1),
        field: wrapped(raw, Capabilities(UNTRUSTED.sources_set, frozenset({PAYEE}) if readable else frozenset())),
    }
    if recipient is not None:
        kwargs["recipient"] = wrapped(recipient)
    verdict = engine.update_scheduled_transaction_policy("update_scheduled_transaction", kwargs)
    assert isinstance(verdict, Allowed if readable else Denied)
    before = env.bank_account.scheduled_transactions[0].model_copy(deep=True)
    code = "update_scheduled_transaction(" + ", ".join(f"{name}={name}" for name in kwargs) + ")"
    if readable:
        evaluated, _, _, _ = execute(code, env, runtime, engine, MODES[0], kwargs)
        assert isinstance(evaluated, result.Ok)
        assert getattr(env.bank_account.scheduled_transactions[0], field) == raw
        assert env.bank_account.scheduled_transactions[0].recipient == PAYEE
    else:
        with pytest.raises(SecurityPolicyDeniedError):
            execute(code, env, runtime, engine, MODES[0], kwargs)
        assert env.bank_account.scheduled_transactions[0] == before


def test_payment_redirect_checks_unchanged_data():
    env, _, engine = setup("banking")
    verdict = engine.update_scheduled_transaction_policy(
        "update_scheduled_transaction", {"id": wrapped(1), "recipient": wrapped(NEW_PAYEE)}
    )
    assert isinstance(verdict, Denied)


@pytest.mark.parametrize("suite_name", ["workspace", "travel"])
@pytest.mark.parametrize("description, location", [("''", "None"), ("''", "''"), ("None", "None")])
def test_calendar_explicit_optional_values(suite_name, description, location):
    env, runtime, engine = setup(suite_name)
    evaluated, _, _, _ = execute(
        "create_calendar_event('Meeting', '2024-06-02 12:00', '2024-06-02 13:00', "
        f"description={description}, location={location}, participants=participants)",
        env,
        runtime,
        engine,
        MODES[0],
        {"participants": wrapped([EXTERNAL], UNTRUSTED)},
    )
    if description == "None":
        assert isinstance(evaluated, result.Error)
        assert isinstance(evaluated.error.exception, pydantic.ValidationError)
        assert set(env.calendar.events) == {"1"}
        assert not env.inbox.sent
    else:
        assert isinstance(evaluated, result.Ok)
        assert env.calendar.events["2"].description == ""
        assert env.calendar.events["2"].location == (None if location == "None" else "")


def test_empty_reschedule_time_remains_invalid():
    env, runtime, engine = setup("workspace")
    before = env.calendar.events["1"].model_copy(deep=True)
    evaluated, _, _, _ = execute(
        "reschedule_calendar_event('1', '2024-06-02 10:00', new_end_time='')",
        env,
        runtime,
        engine,
        MODES[0],
    )
    assert isinstance(evaluated, result.Error)
    assert isinstance(evaluated.error.exception, ValueError)
    assert env.calendar.events["1"] == before
    assert not env.inbox.sent


@pytest.mark.parametrize("field, raw", [("amount", 0.0), ("subject", ""), ("date", "")])
def test_payment_no_op_payload_still_checked(field, raw):
    env, runtime, engine = setup("banking")
    kwargs = {"id": wrapped(1), field: wrapped(raw, PRIVATE)}
    assert isinstance(engine.update_scheduled_transaction_policy("update_scheduled_transaction", kwargs), Denied)
    before = env.bank_account.scheduled_transactions[0].model_copy(deep=True)
    code = "update_scheduled_transaction(" + ", ".join(f"{name}={name}" for name in kwargs) + ")"
    with pytest.raises(SecurityPolicyDeniedError):
        execute(code, env, runtime, engine, MODES[0], kwargs)
    assert env.bank_account.scheduled_transactions[0] == before


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("rebuild", [False, True])
def test_tool_returned_field_retains_labels_on_reconstruction(mode, rebuild):
    env, runtime, engine = setup("banking")
    prefix = "transaction = get_scheduled_transactions()[0]\n"
    if rebuild:
        prefix += "@dataclass\nclass Payee:\n    account: str\nrecord = Payee(transaction.recipient)\naccount = record.account\n"
    else:
        prefix += "account = transaction.recipient\n"
    with pytest.raises(SecurityPolicyDeniedError):
        execute(prefix + "send_money(account, 1.0, 'Payment', '2024-06-01')", env, runtime, engine, mode)
    assert not env.bank_account.transactions


def test_nullable_required_car_rental_end_time():
    env, runtime, engine = setup("travel")
    evaluated, _, _, _ = execute(
        "reserve_car_rental('Example Cars', '2024-06-01 10:00', end_time=None)",
        env,
        runtime,
        engine,
        MODES[0],
    )
    assert isinstance(evaluated, result.Ok)
    assert env.reservation.title == "Example Cars"
