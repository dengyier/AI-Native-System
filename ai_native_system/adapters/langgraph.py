"""Drive a bounded workflow graph using authoritative framework transactions."""

import hashlib
import json
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from typing import Callable, TypedDict

from ..model import ModelError


_GRAPH_PROTOCOL = "ai-native/langgraph/v1"
_SDK_VERSION = "1.2.22"


class GraphVersionError(ModelError):
    """The saved checkpoint is bound to a different release or graph implementation."""


class _WorkflowState(TypedDict, total=False):
    binding: str
    status: str
    stage: int
    round: int
    object_grounded: bool
    relationships_grounded: bool
    knowledge_grounded: bool


@dataclass
class _WorkflowContext:
    observe: Callable[[], dict]
    plan: Callable[[int], dict]
    execute: Callable[[str], dict]
    check: Callable[[str], bool]
    block: Callable[[str], dict]
    resume_approval: bool
    result: dict | None = None

    def record(self, task):
        self.result = task
        return _cursor(task)


def _digest(document):
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _cursor(task):
    return {"status": task["status"], "stage": task["next_stage"]}


def _compile(spec, saver):
    from langgraph.graph import END, START, StateGraph
    from langgraph.runtime import Runtime
    from langgraph.types import interrupt

    graph = StateGraph(_WorkflowState, context_schema=_WorkflowContext)

    def observe(_state, runtime: Runtime[_WorkflowContext]):
        return {**_cursor(runtime.context.observe()), "round": 0}

    def route(state):
        return {"planning": "check_round" if spec.checks else "plan", "awaiting_approval": "approval",
                "ready": "execute", "reconciling": "execute"}.get(state["status"], END)

    def plan(state, runtime: Runtime[_WorkflowContext]):
        task = runtime.context.observe()
        if _cursor(task) == {"status": "planning", "stage": state["stage"]}:
            task = runtime.context.plan(state["stage"])
        return runtime.context.record(task)

    def execute(state, runtime: Runtime[_WorkflowContext]):
        task = runtime.context.observe()
        if task["status"] == state["status"] and task["status"] in ("ready", "reconciling"):
            task = runtime.context.execute(state["status"])
        return runtime.context.record(task)

    def approval(_state, runtime: Runtime[_WorkflowContext]):
        task = runtime.context.observe()
        if task["status"] == "awaiting_approval":
            interrupt({"kind": "approval"})
            task = runtime.context.observe()
        return _cursor(task)

    def after_approval(state, runtime: Runtime[_WorkflowContext]):
        if runtime.context.resume_approval and state["status"] in ("ready", "reconciling"):
            return "execute"
        return END

    graph.add_node("observe", observe)
    graph.add_node("plan", plan)
    graph.add_node("approval", approval)
    graph.add_node("execute", execute)
    graph.add_edge(START, "observe")
    graph.add_conditional_edges("observe", route)
    graph.add_conditional_edges("plan", lambda state: "approval" if state["status"] == "awaiting_approval" else END)
    graph.add_conditional_edges("approval", after_approval)
    graph.add_edge("execute", END)

    if spec.checks:
        def new_round(state):
            return {"round": state["round"] + 1}

        def guard(name):
            def evaluate(_state, runtime: Runtime[_WorkflowContext]):
                return {name: runtime.context.check(name) is True}
            return evaluate

        def joined(state, runtime: Runtime[_WorkflowContext]):
            task = runtime.context.observe()
            if task["status"] != "planning" or task["next_stage"] != state["stage"]:
                return END
            if all(state[name] for name in spec.checks):
                return "plan"
            if spec.on_check_failure == "retry" and state["round"] < spec.max_rounds:
                return "check_round"
            return "block"

        def block(state, runtime: Runtime[_WorkflowContext]):
            task = runtime.context.observe()
            if _cursor(task) == {"status": "planning", "stage": state["stage"]}:
                task = runtime.context.block("graph_checks_failed")
            return runtime.context.record(task)

        graph.add_node("check_round", new_round)
        graph.add_node("join", lambda _: {})
        graph.add_node("block", block)
        for name in spec.checks:
            graph.add_node("check_" + name, guard(name))
            graph.add_edge("check_round", "check_" + name)
        graph.add_edge(["check_" + name for name in spec.checks], "join")
        graph.add_conditional_edges("join", joined)
        graph.add_edge("block", END)
    return graph.compile(checkpointer=saver)


class LangGraphDriver:
    """Run at most one planning or execution step under a checkpoint thread claim."""

    def __init__(self, store):
        self.store = store

    @staticmethod
    def thread_id(tenant, task_id):
        return _digest(("ai-native/task", tenant, task_id))

    def advance(self, tenant, task_id, spec, *, release_digest, observe, plan, execute, check, block):
        try:
            if version("langgraph") != _SDK_VERSION:
                raise GraphVersionError(f"Install LangGraph {_SDK_VERSION} from the integration lock")
            from langgraph.types import Command
            from langsmith import tracing_context
        except (PackageNotFoundError, ImportError):
            raise GraphVersionError("Install the locked LangGraph integrations") from None

        thread = self.thread_id(tenant, task_id)
        binding = _digest((_GRAPH_PROTOCOL, _SDK_VERSION, thread, release_digest, spec.to_document()))
        config = {"configurable": {"thread_id": thread}, "metadata": {"graph_binding": binding},
                  "recursion_limit": 32}
        with self.store.claim(thread) as saver, tracing_context(enabled=False):
            if saver is None:
                return observe()
            graph = _compile(spec, saver)
            saved = graph.get_state(config)
            has_checkpoint = saved.created_at is not None or bool(saved.values or saved.next or saved.metadata)
            if has_checkpoint and (saved.metadata or {}).get("graph_binding") != binding:
                raise GraphVersionError("Graph checkpoint does not match the task's published version")
            current = observe()
            waiting = bool(saved.interrupts)
            if waiting and current["status"] == "awaiting_approval":
                return current
            context = _WorkflowContext(observe, plan, execute, check, block, waiting)
            if waiting:
                stimulus = Command(resume=True)
            elif saved.next:
                stimulus = None
            else:
                stimulus = {"binding": binding}
            graph.invoke(stimulus, config=config, context=context, durability="sync")
            return context.result if context.result is not None else observe()
