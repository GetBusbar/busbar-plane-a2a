#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Declared local fork of the Busbar TCK scenario executor; see PROVENANCE.json.

Reference server only. Protocol serialization and task storage use a2a-sdk 1.1.2.
The local boundary and handler fixes are declared in README.md.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os

import httpx
import uvicorn
from a2a.server.agent_execution.agent_executor import AgentExecutor
from a2a.server.agent_execution.context import RequestContext
from a2a.server.events.event_queue import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import (
    create_agent_card_routes,
)
from a2a.server.routes.jsonrpc_dispatcher import JsonRpcDispatcher
from a2a.server.tasks import (
    BasePushNotificationSender,
    InMemoryPushNotificationConfigStore,
    InMemoryTaskStore,
    TaskUpdater,
)
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentProvider,
    AgentSkill,
    Part,
    Task,
    TaskState,
    TaskStatus,
)
from a2a.utils.errors import A2AError, UnsupportedOperationError
from boundary import StrictBoundary
from google.protobuf import json_format
from google.protobuf.struct_pb2 import Value
from starlette.applications import Starlette
from starlette.routing import Route

# The JSON-RPC endpoint sits at the root because that is where the rig's registration points and
# where the pinned control served it. A card is served at the well-known path either way.
JSONRPC_URL = "/"

# `docs/SUT_REQUIREMENTS.md`: a task created by a `test-resubscribe-message-id` message must stay
# active for at least 2x TCK_STREAMING_TIMEOUT so the suite has time to resubscribe to it. The
# document names the environment variable; honour it rather than hard-coding the doubled default.
_STREAMING_TIMEOUT_S = float(os.environ.get("TCK_STREAMING_TIMEOUT", "2.0"))
_RESUBSCRIBE_HOLD_S = 2.0 * _STREAMING_TIMEOUT_S

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("a2a-scenario-agent")


class ScenarioExecutor(AgentExecutor):
    """Routes on the `messageId` prefix, exactly as the published scenarios specify.

    Order matters in two places only: `tck-message-response` is tested before any task is opened,
    because that scenario answers a bare Message; and `tck-artifact-file-url` is tested before its
    shorter sibling `tck-artifact-file`, which would otherwise swallow it. No other prefix is a
    prefix of another, so everything else is independent.
    """

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        task_id = context.task_id
        context_id = context.context_id
        if task_id is None or context_id is None:
            return

        updater = TaskUpdater(event_queue, task_id, context_id)
        message = context.message
        if message is None:
            await updater.complete(
                updater.new_agent_message([Part(text="No message provided")])
            )
            return

        message_id = message.message_id
        logger.info("scenario dispatch for messageId %s", message_id)

        # The one scenario that produces NO task: "return a message with a text part". It is
        # tested first because opening a task for it would answer a Task where the contract, and
        # DM-MSG-001, say a bare Message.
        if message_id.startswith("tck-message-response"):
            await event_queue.enqueue_event(
                updater.new_agent_message([Part(text="Direct message response")])
            )
            return

        # Every other scenario is about a task. A first turn has to OPEN the task before any
        # status update names it; a follow-up turn must not, because the task already exists and
        # re-opening it would discard the history the multi-turn and history requirements are
        # about. This is SDK scaffolding, not a scenario decision -- the scenarios say what state
        # to leave the task in, not how a task comes into being -- and it is the idiom the SDK's
        # own sample executor uses.
        if context.current_task is None:
            await event_queue.enqueue_event(
                Task(
                    id=task_id,
                    context_id=context_id,
                    status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED),
                    history=[message],
                )
            )

        # -- streaming scenarios (scenarios/streaming.feature) ------------------------------
        if message_id.startswith("tck-stream-artifact-chunked"):
            await updater.start_work()
            await updater.add_artifact(parts=[Part(text="chunk-1 ")], append=True)
            await updater.add_artifact(
                parts=[Part(text="chunk-2")], append=True, last_chunk=True
            )
            await updater.complete()
            return

        if message_id.startswith("test-resubscribe-message-id"):
            await updater.start_work()
            await asyncio.sleep(_RESUBSCRIBE_HOLD_S)
            await updater.complete()
            return

        if message_id.startswith("tck-stream-artifact-text"):
            await updater.start_work()
            await updater.add_artifact(parts=[Part(text="Streamed text content")])
            await updater.complete()
            return

        if message_id.startswith("tck-stream-artifact-file"):
            await updater.start_work()
            await updater.add_artifact(
                parts=[Part(raw=b"tck", media_type="text/plain", filename="output.txt")]
            )
            await updater.complete()
            return

        if message_id.startswith("tck-stream-ordering-001"):
            await updater.start_work()
            await updater.add_artifact(parts=[Part(text="Ordered output")])
            await updater.complete()
            return

        if message_id.startswith("tck-stream-001"):
            await updater.start_work()
            await updater.add_artifact(parts=[Part(text="Stream hello from TCK")])
            await updater.complete()
            return

        if message_id.startswith("tck-stream-002"):
            await updater.complete()
            return

        if message_id.startswith("tck-stream-003"):
            await updater.start_work()
            await updater.add_artifact(parts=[Part(text="Stream task lifecycle")])
            await updater.complete()
            return

        # -- core scenarios (scenarios/core_operations.feature) -----------------------------
        if message_id.startswith("tck-artifact-file-url"):
            await updater.add_artifact(
                parts=[
                    Part(
                        url="https://example.com/output.txt",
                        media_type="text/plain",
                        filename="output.txt",
                    )
                ]
            )
            await updater.complete()
            return

        if message_id.startswith("tck-artifact-file"):
            await updater.add_artifact(
                parts=[Part(raw=b"tck", media_type="text/plain", filename="output.txt")]
            )
            await updater.complete()
            return

        if message_id.startswith("tck-artifact-text"):
            await updater.add_artifact(parts=[Part(text="Generated text content")])
            await updater.complete()
            return

        if message_id.startswith("tck-artifact-data"):
            await updater.add_artifact(
                parts=[
                    Part(
                        data=json_format.Parse('{"key": "value", "count": 42}', Value())
                    )
                ]
            )
            await updater.complete()
            return

        # The scenario that unblocks the eleven: park the task, do not finish it. A second turn
        # carrying the same taskId with a `tck-complete-task` id closes it, which is what the
        # multi-turn, history and push-delivery setups do.
        if message_id.startswith("tck-input-required"):
            await updater.requires_input()
            return

        if message_id.startswith("tck-complete-task"):
            await updater.complete(
                updater.new_agent_message([Part(text="Hello from TCK")])
            )
            return

        if message_id.startswith("tck-reject-task"):
            raise A2AError("rejected")

        # ── NOT A TCK SCENARIO. `a2asup-auth-required` belongs to the SUPPLEMENTARY suite. ──
        #
        # SPEC 7.6.1 puts four MUSTs on an agent that needs a client to fulfil an authorization
        # request, and the official suite has no test for any of them because no fixture it drives
        # ever enters `TASK_STATE_AUTH_REQUIRED`. Nothing in the TCK sends this prefix, so this
        # branch is unreachable from the official run and cannot change its number; it exists so
        # that `testing/a2a-supplement` can observe whether the A2A server under test PRESERVES the
        # three observable consequences end to end -- a Task rather than a bare Message, the
        # `auth_required` state, and a status message explaining what is wanted.
        #
        # THE MESSAGE TEXT IS NOT ARBITRARY and it is not a marker the checks look for. SPEC 7.6.1
        # requires "a TaskStatus message explaining the required authorization", so the fixture
        # supplies a plausible explanation and the checks assert only that SOME non-empty status
        # message survived. A check that matched this exact string would be testing the fixture.
        if message_id.startswith("a2asup-auth-required"):
            await updater.requires_auth(
                updater.new_agent_message(
                    [
                        Part(
                            text=(
                                "Authorization is required before this operation can continue: an OAuth "
                                "access token for the downstream API, obtained out of band."
                            )
                        )
                    ]
                )
            )
            return

        # No prefix claimed it. The contract says "normal task processing, no special behaviour",
        # and says so out loud rather than silently echoing, so a prefix this agent has not
        # implemented is visible in the transcript instead of passing for a handled one.
        await updater.complete(
            updater.new_agent_message(
                [Part(text="Unhandled messageId prefix: " + message_id)]
            )
        )

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        task_id = context.task_id
        context_id = context.context_id
        if task_id is None or context_id is None:
            return
        await TaskUpdater(event_queue, task_id, context_id).cancel()


class ReferenceJsonRpcDispatcher(JsonRpcDispatcher):
    async def _handle_list_tasks(self, request_obj, context):
        # SDK's always-print-defaults serializer restores artifacts=[] after
        # the handler clears it. Honor projection without touching stored tasks.
        result = await super()._handle_list_tasks(request_obj, context)
        if not request_obj.include_artifacts:
            for task in result.get("tasks", []):
                task.pop("artifacts", None)
        return result


class ReferenceRequestHandler(DefaultRequestHandler):
    async def _setup_active_task(self, params, call_context):
        # Guard before the SDK appends the new message to stored history.
        if params.message.task_id:
            task = await self.task_store.get(params.message.task_id, call_context)
            if task and task.status.state in {
                TaskState.TASK_STATE_COMPLETED,
                TaskState.TASK_STATE_FAILED,
                TaskState.TASK_STATE_CANCELED,
                TaskState.TASK_STATE_REJECTED,
            }:
                raise UnsupportedOperationError(
                    message="Terminal tasks cannot accept messages"
                )
        return await super()._setup_active_task(params, call_context)


def build_card(public_url: str) -> AgentCard:
    """The card this agent publishes.

    `pushNotifications` IS TRUE, and it is true because the agent really does it: `main` gives the
    SDK's request handler a push configuration store and a webhook sender, so a config set on this
    agent is stored and a webhook is called from this process. The claim was checked before it was
    made -- a fixture that advertises a capability it does not implement is a fixture that lies to
    every suite that reads its card.

    It has to be declared rather than left off for a reason worth stating: a gateway that fronts
    this agent may serve a card derived from THIS one, in which case a capability omitted here is
    a capability the suite never asks the gateway about. Whether that derivation is right is the
    gateway's business and not this file's -- but a fixture must not be the reason a requirement
    goes untested.
    """
    return AgentCard(
        name="A2A Python reference fixture (local fork)",
        description=(
            "An A2A agent implementing the TCK SUT behaviour contract published in that "
            "suite's scenario feature files. Used as the backend agent in conformance rigs."
        ),
        version="1.0.0",
        provider=AgentProvider(organization="busbar", url="https://getbusbar.com"),
        supported_interfaces=[
            AgentInterface(
                url=public_url,
                protocol_binding="JSONRPC",
                protocol_version="1.0",
            ),
        ],
        capabilities=AgentCapabilities(
            streaming=True,
            push_notifications=True,
        ),
        default_input_modes=["text"],
        default_output_modes=["text"],
        skills=[
            AgentSkill(
                id="tck-scenarios",
                name="TCK scenarios",
                description="Behaviour selected in-band by the messageId prefix.",
                tags=["tck", "conformance"],
            ),
        ],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--public-url", default=None)
    args = parser.parse_args()

    public_url = args.public_url or f"http://{args.host}:{args.port}/"

    card = build_card(public_url)
    # Push is implemented, not merely claimed: the SDK's own config store and webhook sender.
    push_store = InMemoryPushNotificationConfigStore()
    push_sender = BasePushNotificationSender(
        httpx_client=httpx.AsyncClient(timeout=10.0),
        config_store=push_store,
    )
    handler = ReferenceRequestHandler(
        agent_executor=ScenarioExecutor(),
        task_store=InMemoryTaskStore(),
        agent_card=card,
        push_config_store=push_store,
        push_sender=push_sender,
    )

    routes = [
        Route(
            path=JSONRPC_URL,
            endpoint=ReferenceJsonRpcDispatcher(
                request_handler=handler, enable_v0_3_compat=False
            ).handle_requests,
            methods=["POST"],
        ),
        *create_agent_card_routes(agent_card=card),
    ]

    uvicorn.run(
        StrictBoundary(Starlette(routes=routes)),
        host=args.host,
        port=args.port,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
