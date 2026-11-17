"""P1a contracts for governed tasks and actions. They describe intent, not permission."""

from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
from types import MappingProxyType

from .fact_contracts import FactReadSet, ObjectIdentity, SourceVersion, canonical_json, freeze_json, json_data
from .registry import FIELD_TYPES, field_matches
from .storage import digest as legacy_digest


class ActionKind(StrEnum):
    READ = "read"
    GENERATE = "generate"
    WRITE_LOCAL = "write_local"
    WRITE_REMOTE = "write_remote"


def is_name(value):
    return type(value) is str and bool(value.strip())


def is_version(value):
    return (type(value) is int and value > 0) or is_name(value)


def _names(values, label):
    if not isinstance(values, (list, tuple)) or not all(map(is_name, values)) or len(set(values)) != len(values):
        raise ValueError(f"{label} must contain distinct nonempty names")
    return tuple(values)


def _schema(value, label):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a field declaration object")
    fields = {}
    for name, spec in value.items():
        if (not is_name(name) or not isinstance(spec, dict) or set(spec) - {"type", "required", "nullable"}
                or not is_name(spec.get("type")) or spec["type"] not in FIELD_TYPES
                or type(spec.get("required", True)) is not bool or type(spec.get("nullable", False)) is not bool):
            raise ValueError(f"Invalid {label} field {name!r}")
        fields[name] = MappingProxyType({"type": spec["type"], "required": spec.get("required", True),
                                         "nullable": spec.get("nullable", False)})
    return MappingProxyType(fields)


def _validate_fields(schema, value, label):
    if not isinstance(value, dict) or not all(map(is_name, value)) or value.keys() - schema.keys():
        raise ValueError(f"{label} contains undeclared fields")
    for name, spec in schema.items():
        if name not in value:
            if spec["required"]:
                raise ValueError(f"Missing {label} field {name!r}")
            continue
        item = value[name]
        if not (item is None and spec["nullable"]) and not field_matches(item, spec["type"]):
            raise ValueError(f"Invalid {label} field {name!r}")


@dataclass(frozen=True)
class ActionDefinition:
    name: str
    version: str | int
    kind: ActionKind
    target_type: str | None = None
    parameters: dict = field(default_factory=dict)
    result: dict = field(default_factory=dict)
    tool: str | None = None
    tool_version: str | None = None
    destination: str | None = None
    preconditions: tuple = ()
    postconditions: tuple = ()
    approval_required: bool = False
    artifact_scope: str | None = None
    read_fields: tuple = ()
    write_fields: tuple = ()
    read_relations: tuple = ()
    write_relations: tuple = ()

    def __post_init__(self):
        if not is_name(self.name) or not is_version(self.version) or type(self.approval_required) is not bool:
            raise ValueError("Action requires a name, version and boolean approval requirement")
        kind = ActionKind(self.kind)
        for label in ("target_type", "tool", "tool_version", "destination", "artifact_scope"):
            value = getattr(self, label)
            if value is not None and not is_name(value):
                raise ValueError(f"Invalid action {label}")
        if (self.tool is None) != (self.tool_version is None):
            raise ValueError("Tool name and version must be declared together")
        if self.destination is not None and self.tool is None:
            raise ValueError("A destination requires a versioned tool")
        writes = kind in (ActionKind.WRITE_LOCAL, ActionKind.WRITE_REMOTE)
        if writes and (self.target_type is None or self.tool is None):
            raise ValueError("A write action requires a target type and versioned tool")
        if kind is ActionKind.WRITE_REMOTE and self.destination is None:
            raise ValueError("A remote write requires a destination")
        if kind is ActionKind.WRITE_LOCAL and self.destination is not None:
            raise ValueError("Local writes are restricted to the framework transaction")
        if self.artifact_scope is not None and kind is not ActionKind.GENERATE:
            raise ValueError("Only generation actions declare an artifact scope")
        if (self.write_fields or self.write_relations) and not writes:
            raise ValueError("Read and generation actions cannot declare business writes")
        if (self.read_fields or self.write_fields or self.read_relations or self.write_relations) and self.target_type is None:
            raise ValueError("Field and relationship scope requires a target type")
        object.__setattr__(self, "kind", kind)
        for key in ("parameters", "result"):
            object.__setattr__(self, key, _schema(getattr(self, key), key))
        for key in ("preconditions", "postconditions", "read_fields", "write_fields", "read_relations", "write_relations"):
            object.__setattr__(self, key, _names(getattr(self, key), key))

    @classmethod
    def from_document(cls, name, document):
        if not isinstance(document, dict) or "name" in document:
            raise ValueError("Action definition must be an object keyed by action name")
        try:
            return cls(name, **document)
        except TypeError as error:
            raise ValueError(f"Invalid action definition {name!r}: {error}") from error

    @classmethod
    def from_legacy(cls, name, action, *, remote, destination=None):
        if type(remote) is not bool:
            raise ValueError("Legacy projection requires the registered tool's execution mode")
        return cls(name, action["version"], ActionKind.WRITE_REMOTE if remote else ActionKind.WRITE_LOCAL,
                   target_type=action["object_type"], tool=action.get("tool", "state.transition"),
                   tool_version=action.get("tool_version", "1"), destination=destination,
                   preconditions=(name,), approval_required=True, write_fields=("state",))

    def to_document(self):
        return {
            "version": self.version, "kind": self.kind.value, "target_type": self.target_type,
            "parameters": json_data(self.parameters), "result": json_data(self.result),
            "tool": self.tool, "tool_version": self.tool_version, "destination": self.destination,
            "preconditions": list(self.preconditions), "postconditions": list(self.postconditions),
            "approval_required": self.approval_required, "artifact_scope": self.artifact_scope,
            "read_fields": list(self.read_fields), "write_fields": list(self.write_fields),
            "read_relations": list(self.read_relations), "write_relations": list(self.write_relations),
        }

    def validate_result(self, result):
        _validate_fields(self.result, result, "result")


@dataclass(frozen=True)
class TaskRef:
    tenant: str
    actor: str
    task_id: str
    release: str

    def __post_init__(self):
        if not all(map(is_name, (self.tenant, self.actor, self.task_id, self.release))):
            raise ValueError("Task requires tenant, actor, task ID and release")


@dataclass(frozen=True)
class OperationRef:
    task: TaskRef
    action_instance_id: str
    operation_id: str

    def __post_init__(self):
        if not isinstance(self.task, TaskRef):
            raise ValueError("Operation requires a task reference")
        _names((self.task.task_id, self.action_instance_id, self.operation_id), "Operation identifiers")


@dataclass(frozen=True)
class AttemptRef:
    operation: OperationRef
    attempt_id: str
    trace_id: str

    def __post_init__(self):
        if not isinstance(self.operation, OperationRef):
            raise ValueError("Attempt requires an operation reference")
        _names((self.operation.task.task_id, self.operation.action_instance_id, self.operation.operation_id,
                self.attempt_id, self.trace_id), "Attempt identifiers")


@dataclass(frozen=True)
class ActionRequest:
    operation: OperationRef
    definition: ActionDefinition
    parameters: dict
    target: ObjectIdentity | None = None
    read_set: FactReadSet | None = None
    artifact_scope: str | None = None
    additional_targets: tuple[ObjectIdentity, ...] = ()

    def __post_init__(self):
        if not isinstance(self.operation, OperationRef) or not isinstance(self.definition, ActionDefinition):
            raise ValueError("An action request requires an operation and definition")
        task = self.operation.task
        definition = self.definition
        writes = definition.kind in (ActionKind.WRITE_LOCAL, ActionKind.WRITE_REMOTE)
        if self.target is None and writes:
            raise ValueError("A write request requires a target")
        if not isinstance(self.additional_targets, (tuple, list)) or (self.additional_targets and not writes):
            raise ValueError("Only writes can declare additional targets")
        targets = ([] if self.target is None else [self.target]) + list(self.additional_targets)
        if any(not isinstance(target, ObjectIdentity) or target.tenant != task.tenant
               or target.object_type != definition.target_type for target in targets):
            raise ValueError("Target tenant or type is outside the declared scope")
        if len(set(targets)) != len(targets):
            raise ValueError("Target scope cannot include duplicate objects")
        if self.read_set is not None and (not isinstance(self.read_set, FactReadSet) or self.read_set.tenant != task.tenant):
            raise ValueError("Read set tenant must match the task")
        if self.artifact_scope is not None and (not is_name(self.artifact_scope) or self.artifact_scope != definition.artifact_scope):
            raise ValueError("Artifact storage is outside the declared scope")
        _validate_fields(definition.parameters, self.parameters, "parameter")
        object.__setattr__(self, "parameters", MappingProxyType(self.parameters.copy()))
        object.__setattr__(self, "additional_targets", tuple(sorted(self.additional_targets)))

    def to_document(self):
        task = self.operation.task
        def target_ref(target):
            return {"tenant": target.tenant, "type": target.object_type, "id": target.object_id}

        return {
            "schema_version": "action-request/1", "tenant": task.tenant, "actor": task.actor,
            "task_id": task.task_id, "release": task.release,
            "action_instance_id": self.operation.action_instance_id, "operation_id": self.operation.operation_id,
            "action": self.definition.name, "definition": self.definition.to_document(),
            "parameters": dict(self.parameters),
            "target": None if self.target is None else target_ref(self.target),
            "additional_targets": [target_ref(target) for target in self.additional_targets],
            "fact_read_set_digest": None if self.read_set is None else self.read_set.digest,
            "artifact_scope": self.artifact_scope,
        }

    @property
    def request_digest(self):
        return sha256(canonical_json(self.to_document()).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class LegacyOperationRef:
    """Validate an existing SQLite operation with its original digest algorithm."""

    operation_id: str
    request_hash: str

    @classmethod
    def from_payload(cls, payload):
        if not isinstance(payload, dict) or not is_name(payload.get("operation_id")):
            raise ValueError("Legacy operation requires its stored operation ID")
        original = {key: value for key, value in payload.items() if key != "request_hash"}
        if payload.get("request_hash") != legacy_digest(original):
            raise ValueError("Legacy request hash does not match the stored payload")
        return cls(payload["operation_id"], payload["request_hash"])


class TaskProgress(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    READY = "ready"
    RECONCILING = "reconciling"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class EffectStatus(StrEnum):
    NOT_STARTED = "not_started"
    PENDING = "pending"
    UNKNOWN = "unknown"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PARTIAL = "partial"


@dataclass(frozen=True)
class AffectedObject:
    target: ObjectIdentity
    source_version: SourceVersion | None = None
    local_version: int | None = None

    def __post_init__(self):
        if not isinstance(self.target, ObjectIdentity):
            raise ValueError("Effect requires a canonical object identity")
        if self.source_version is not None and (not isinstance(self.source_version, SourceVersion)
                                                or self.source_version.identity.tenant != self.target.tenant):
            raise ValueError("Source version must belong to the affected object's tenant")
        if self.local_version is not None and (type(self.local_version) is not int or self.local_version < 1):
            raise ValueError("Local version must be a positive integer")


@dataclass(frozen=True)
class ActionReceipt:
    operation: OperationRef
    request_digest: str
    status: EffectStatus
    issuer: str
    result: dict = field(default_factory=dict)
    affected: tuple[AffectedObject, ...] = ()

    def __post_init__(self):
        if not isinstance(self.operation, OperationRef) or not is_name(self.issuer):
            raise ValueError("Receipt must identify its operation and issuer")
        if (not isinstance(self.request_digest, str) or len(self.request_digest) != 64
                or any(char not in "0123456789abcdef" for char in self.request_digest)):
            raise ValueError("Receipt requires a SHA-256 request digest")
        status = EffectStatus(self.status)
        if status is EffectStatus.NOT_STARTED:
            raise ValueError("A receipt describes an observed outcome")
        if not isinstance(self.result, dict) or not isinstance(self.affected, (list, tuple)):
            raise ValueError("Receipt requires an object result and a collection of affected objects")
        affected = tuple(self.affected)
        if any(not isinstance(item, AffectedObject) or item.target.tenant != self.operation.task.tenant for item in affected):
            raise ValueError("Receipt cannot include affected objects outside the task tenant")
        if len({item.target for item in affected}) != len(affected):
            raise ValueError("Receipt cannot contain duplicate affected objects")
        if affected and status not in (EffectStatus.SUCCEEDED, EffectStatus.PARTIAL):
            raise ValueError("Only confirmed outcomes can report affected objects")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "result", freeze_json(self.result))
        object.__setattr__(self, "affected", affected)

    def validate_for(self, request):
        if self.operation != request.operation or self.request_digest != request.request_digest:
            raise ValueError("Receipt does not belong to the request")
        writes = request.definition.kind in (ActionKind.WRITE_LOCAL, ActionKind.WRITE_REMOTE)
        targets = {request.target, *request.additional_targets} if writes else set()
        if any(item.target not in targets for item in self.affected):
            raise ValueError("Receipt reports an effect outside the request's write targets")
        if self.status is EffectStatus.SUCCEEDED:
            request.definition.validate_result(json_data(self.result))


class EvidenceStatus(StrEnum):
    PENDING = "pending"
    VERIFIED = "verified"
    UNAVAILABLE = "unavailable"
    INVALID = "invalid"


class AcceptanceStatus(StrEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


@dataclass(frozen=True)
class OperationStatus:
    progress: TaskProgress
    effect: EffectStatus = EffectStatus.NOT_STARTED
    evidence: EvidenceStatus = EvidenceStatus.PENDING
    acceptance: AcceptanceStatus = AcceptanceStatus.PENDING

    def __post_init__(self):
        for name, enum in (("progress", TaskProgress), ("effect", EffectStatus),
                           ("evidence", EvidenceStatus), ("acceptance", AcceptanceStatus)):
            object.__setattr__(self, name, enum(getattr(self, name)))

    @property
    def eligible_for_initial_dispatch(self):
        """Sequencing gate. The executor still has to verify current authorization."""
        return self.progress is TaskProgress.READY and self.effect is EffectStatus.NOT_STARTED
