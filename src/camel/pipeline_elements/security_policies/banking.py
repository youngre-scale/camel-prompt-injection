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

from collections.abc import Mapping

from agentdojo.default_suites.v1.banking.task_suite import BankingEnvironment

from camel import security_policy
from camel.capabilities import Capabilities, can_readers_read_value, get_all_readers, is_trusted, sources
from camel.interpreter import namespace as ns
from camel.interpreter.value import CaMeLNone, CaMeLStr, CaMeLValue, value_from_raw
from camel.pipeline_elements.security_policies.agentdojo_security_policies import (
    AgentDojoSecurityPolicyEngine,
)
from camel.security_policy import Allowed, Denied, SecurityPolicyResult

banking_no_side_effect_tools = {
    "get_iban",
    "get_balance",
    "get_most_recent_transactions",
    "get_scheduled_transactions",
    "read_file",
    "get_user_info",
}


class BankingSecurityPolicyEngine(AgentDojoSecurityPolicyEngine[BankingEnvironment]):
    def __init__(self, env: BankingEnvironment) -> None:
        super().__init__(env)
        self.policies = [
            ("send_money", self.send_money_policy),
            ("schedule_transaction", self.schedule_transaction_policy),
            (
                "update_scheduled_transaction",
                self.update_scheduled_transaction_policy,
            ),
            ("update_password", self.update_password_policy),
            ("update_user_info", self.update_user_info_policy),
        ]
        self.no_side_effect_tools = security_policy.NO_SIDE_EFFECT_TOOLS | banking_no_side_effect_tools

    def send_money_policy(self, tool_name: str, kwargs: Mapping[str, CaMeLValue]) -> SecurityPolicyResult:
        # Data:
        # - amount: float
        # - subject: str
        # - date: str
        # Readers:
        # - recipient: str
        # Rationale: if the recipient comes from user, then we allow, otherwise, recipient must be able to read all components
        # of the transaction.

        recipient = kwargs["recipient"]
        if not is_trusted(recipient):
            return Denied("The recipient does not come directly from the user.")

        recipients_set = {recipient.raw}
        subject_readers, _ = get_all_readers(kwargs["subject"])
        if not can_readers_read_value(recipients_set, kwargs["subject"]):
            return Denied(
                f"The recipients can't read the transaction subject: subject readers={subject_readers}, recipients = {recipients_set}."
            )

        amount_readers, _ = get_all_readers(kwargs["amount"])
        if not can_readers_read_value(recipients_set, kwargs["amount"]):
            return Denied(
                f"The recipients can't read the transaction amount: amount readers={amount_readers}, recipients = {recipients_set}."
            )

        date_readers, _ = get_all_readers(kwargs["date"])
        if not can_readers_read_value(recipients_set, kwargs["date"]):
            return Denied(
                f"The recipients can't read the transaction amount: date readers={date_readers}, recipients = {recipients_set}."
            )

        return Allowed()

    def schedule_transaction_policy(self, tool_name: str, kwargs: Mapping[str, CaMeLValue]) -> SecurityPolicyResult:
        # Only difference from send_money is the possibility to make this recurrent, which is not
        # a problem.
        return self.send_money_policy(tool_name, kwargs)

    def update_scheduled_transaction_policy(
        self, tool_name: str, kwargs: Mapping[str, CaMeLValue]
    ) -> SecurityPolicyResult:
        transaction = next((t for t in self._env.bank_account.scheduled_transactions if t.id == kwargs["id"].raw), None)
        if transaction is None:
            return Denied("The scheduled transaction does not exist")

        recipient = kwargs.get("recipient")
        # The tool leaves the payee unchanged for omission, None, or an empty
        # string. The stored schedule establishes that destination; a supplied
        # replacement must still satisfy the recipient trust requirement.
        if recipient is None or isinstance(recipient, CaMeLNone) or not recipient.raw:
            recipient = CaMeLStr.from_raw(transaction.recipient, Capabilities.default(), ())
        if not is_trusted(recipient):
            return Denied("The recipient does not come directly from the user.")

        recipients_set = {recipient.raw}
        stored_metadata = Capabilities(
            frozenset({sources.SourceEnum.TrustedToolSource}), frozenset({transaction.sender, transaction.recipient})
        )
        effective_kwargs = {"recipient": recipient}
        for field in ("subject", "amount", "date"):
            supplied = kwargs.get(field)
            # Check supplied payload values even when another argument is
            # omitted. None carries no replacement value.
            if supplied is not None and not isinstance(supplied, CaMeLNone):
                if not can_readers_read_value(recipients_set, supplied):
                    return Denied(f"The recipients can't read the transaction {field}.")
            # AgentDojo 0.1.34 updates these fields only for truthy values.
            # A redirect also exposes unchanged data to the effective payee.
            if supplied is None or isinstance(supplied, CaMeLNone) or not supplied.raw:
                effective_kwargs[field] = value_from_raw(
                    getattr(transaction, field), stored_metadata, ns.Namespace(), ()
                )
            else:
                effective_kwargs[field] = supplied
        return self.send_money_policy(tool_name, effective_kwargs)

    def update_password_policy(self, tool_name: str, kwargs: Mapping[str, CaMeLValue]) -> SecurityPolicyResult:
        # Data:
        # - password
        # Readers:
        # - None
        # Rationale: Accept only if password comes from trusted source. Nobody can read this.
        if is_trusted(kwargs["password"]):
            return Allowed()
        return Denied("The password does not come from the user.")

    def update_user_info_policy(self, tool_name: str, kwargs: Mapping[str, CaMeLValue]) -> SecurityPolicyResult:
        # Data:
        # - first_name
        # - last_name
        # - street
        # - city
        # Readers:
        # - None
        # Rationale:
        # Here data are not revealed, so we are not concerned with that, but we want the data
        # to come from the user.
        if all(is_trusted(kwarg) for kwarg in kwargs.values()):
            return Allowed()
        return Denied("The user information does not come from the user.")
