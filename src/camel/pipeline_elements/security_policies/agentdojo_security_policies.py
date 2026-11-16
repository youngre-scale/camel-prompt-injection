# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections.abc import Iterable, Mapping
from typing import Generic, TypeVar

from agentdojo.default_suites.v1.workspace.task_suite import (
    WorkspaceEnvironment,
)
from agentdojo.functions_runtime import TaskEnvironment

from camel.capabilities import Capabilities, can_readers_read_value, is_trusted
from camel.interpreter.value import CaMeLList, CaMeLNone, CaMeLStr, CaMeLValue
from camel.security_policy import Allowed, Denied, SecurityPolicy, SecurityPolicyEngine, SecurityPolicyResult

_E = TypeVar("_E", bound=TaskEnvironment)


class AgentDojoSecurityPolicyEngine(SecurityPolicyEngine, Generic[_E]):
    def __init__(self, env: _E) -> None:
        self._env = env


class ADNoSecurityPolicyEngine(AgentDojoSecurityPolicyEngine[WorkspaceEnvironment]):
    def __init__(self, env: WorkspaceEnvironment) -> None:
        super().__init__(env)
        self.policies = []
        self.no_side_effect_tools = set()

    def check_policy(
        self, tool_name: str, kwargs: Mapping[str, CaMeLValue], dependencies: Iterable[CaMeLValue]
    ) -> SecurityPolicyResult:
        return Allowed()


def make_trusted_fields_policy(fields: tuple[str, ...]) -> SecurityPolicy:
    def policy(tool_name: str, kwargs: Mapping[str, CaMeLValue]) -> SecurityPolicyResult:
        for arg_name in fields:
            arg = kwargs[arg_name]
            if not is_trusted(arg):
                return Denied(f"{arg_name} does not come directly from user")
        return Allowed()

    return policy


def calendar_event_creation_policy(kwargs: Mapping[str, CaMeLValue]) -> SecurityPolicyResult:
    """Check new participants against the data exposed by calendar creation.

    Omitted or None participants select only the calendar owner. Description
    defaults to an empty string and location defaults to None in both suites.
    """
    participants = kwargs.get("participants")
    if participants is None or isinstance(participants, CaMeLNone):
        return Allowed()
    if not isinstance(participants, CaMeLList) or not all(
        isinstance(participant, CaMeLStr) for participant in participants.iterate_python()
    ):
        return Denied("Participants must be a list of email addresses")
    if is_trusted(participants):
        return Allowed()
    participants_set = set(participants.raw)
    data = {
        "title": kwargs["title"],
        "description": kwargs.get("description", CaMeLStr.from_raw("", Capabilities.camel(), ())),
        "location": kwargs.get("location", CaMeLNone(Capabilities.camel(), ())),
        "end_time": kwargs["end_time"],
        "start_time": kwargs["start_time"],
    }
    for name, field in data.items():
        if name == "location" and isinstance(field, CaMeLNone):
            continue
        if not can_readers_read_value(participants_set, field):
            return Denied(f"The {name} is not public or shared with the recipients")
    return Allowed()
