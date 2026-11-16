# Dependency and policy regression coverage

Containers expose direct dependencies on their elements, including both keys
and values of mappings. Reader and source queries traverse this graph once per
query, using object identity to handle shared references and cycles. They do not
retain cached aggregate labels across queries, so container mutation and copies
made with `new_with_*` are observed. This supports cycles in wrapped dependency
graphs; it does not add support for converting arbitrary cyclic raw Python
objects into interpreter values.

Loop targets, comprehension targets, unpacked targets, and expanded call
arguments retain dependencies on their input container. Class construction
passes raw arguments to Python but keeps the wrapped arguments as dependencies;
raw field access depends on the instance. F-strings retain each evaluated
component, including components that produce no characters. NORMAL remains the
default; STRICT retains its additional assignment and control-flow tracking.
The existing source labels assigned to builtin and quarantined-model results
are preserved.

The policy regressions cover these behaviors:

| Operation | Corrected behavior |
| --- | --- |
| Email deletion | Trusted email IDs are allowed; untrusted IDs are denied. |
| Adding calendar participants | Participants must be trusted. A searched event ID does not prevent adding user-selected participants. |
| Travel reservations | Each policy checks its corresponding tool's field names. |
| Calendar creation in workspace and travel | Trusted participants are allowed; other participants must be able to read the event data. Omitted participants or `None` select only the owner. Description defaults to `""`; location defaults to `None`. |
| Calendar rescheduling | The supplied start time and any non-None end time must be readable by existing participants. Omitted or `None` end time preserves duration, as the tool specifies. |
| Scheduled payment updates | Omitted, None, or empty recipient uses the stored payee. A replacement payee must be trusted. Supplied subject, amount, and date remain reader-checked, including falsey values. Unchanged transaction data retain the stored transaction's readers when checking a redirect. |
| Unsupported constants | An Ellipsis literal returns an interpreter error containing `NotImplementedError`, rather than escaping with `AttributeError`. |

Payment updates match the installed AgentDojo tool's truthiness behavior:
empty strings, zero amounts, and `False` do not update the stored fields. This
change does not modify AgentDojo. Calendar description `None` and empty time
strings remain invalid tool inputs. Car rental `end_time` is nullable but has
no default in AgentDojo 0.1.34; this change does not make it optional or change
the reservation tool's handling of that value.

The tests assert labels, verdict types, exception types, and simulated payment,
email, calendar, and reservation state. They include trusted and readable
controls and a combined iteration/construction case. They use fixed model
responses and local environments; they do not call models or evaluate benchmark
attack-success scores. They do not establish comprehensive security.

## Related public contributions and attribution

The container-content dependency and f-string changes overlap with
[PR #3](https://github.com/google-research/camel-prompt-injection/pull/3)
by **@audityourcontracts**. The f-string accumulator changes adapt that
contribution's approach. This implementation uses direct container edges and
iterative capability queries rather than recursive dependency flattening.

Constructor argument retention and raw field access overlap with
[PR #4](https://github.com/google-research/camel-prompt-injection/pull/4)
by **@audityourcontracts**. Raw field wrapping adapts that contribution;
constructor arguments are attached in `call`, without reserving an extra
constructor keyword. This change does not incorporate that PR's separate
comprehension-filter and namespace-assignment changes.

Email deletion and travel reservation field corrections overlap with
[PR #5](https://github.com/google-research/camel-prompt-injection/pull/5)
by **@audityourcontracts**. Its separate email-recipient shape validation
proposal is not included here. These PRs were open and unmerged when this
change was prepared; their authors retain attribution for the adapted portions.

## Local checks

Use the dependencies in the upstream lockfile:

```sh
uv sync --frozen
uv run --offline --no-sync pytest
uv run --offline --no-sync ruff check .
uv run --offline --no-sync ruff format --check .
uv run --offline --no-sync pyright
git diff --check
```

The repository does not contain GitHub Actions workflows. These Python checks
follow the README and `pyproject.toml`; `ruff format --check` is used for the
README's formatting step.
