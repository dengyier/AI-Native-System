"""Published model data boundaries and explicit per-route tariffs."""

from dataclasses import asdict, dataclass


def _names(values):
    if (not isinstance(values, (list, tuple)) or any(
        not isinstance(value, str) or not value.strip() for value in values
    ) or len(set(values)) != len(values)):
        raise ValueError("Expected a list of distinct model policy names")
    return tuple(sorted(values))


@dataclass(frozen=True)
class GenerationData:
    object_fields: tuple = ()
    related_fields: tuple = ()
    knowledge_ids: tuple = ()
    include_handoff: bool = False

    @classmethod
    def from_document(cls, config):
        if not isinstance(config, dict) or config.keys() - {
            "object_fields", "related_fields", "knowledge_ids", "include_handoff",
        }:
            raise ValueError("Invalid generation data policy")
        related = config.get("related_fields", {})
        handoff = config.get("include_handoff", False)
        if not isinstance(related, dict) or type(handoff) is not bool:
            raise ValueError("Invalid generation data policy")
        return cls(_names(config.get("object_fields", ())),
                   tuple((name, _names(related[name])) for name in _names(list(related))),
                   _names(config.get("knowledge_ids", ())), handoff)

    def document(self):
        return {"object_fields": list(self.object_fields),
                "related_fields": {name: list(fields) for name, fields in self.related_fields},
                "knowledge_ids": list(self.knowledge_ids), "include_handoff": self.include_handoff}

    def project(self, context):
        def project_object(item, fields):
            return {**{key: item[key] for key in ("type", "state", "version")},
                    "properties": {key: item["properties"][key] for key in fields if key in item["properties"]}}

        previous = context.get("handoff") if self.include_handoff else None
        handoff = {"action": previous["action"]} if previous else None
        return {
            "agent": context["agent"], "scenario": context["scenario"],
            "allowed_actions": context["allowed_actions"],
            "object": project_object(context["object"], self.object_fields),
            "related": {name: project_object(context["related"][name], fields)
                        for name, fields in self.related_fields if name in context["related"]},
            "knowledge": [{key: doc[key] for key in ("id", "version", "text")}
                          for doc in context["knowledge"] if doc.get("document_id", doc["id"]) in self.knowledge_ids],
            "handoff": handoff,
        }


@dataclass(frozen=True)
class RouteAccounting:
    price_version: str
    input_nanos: int
    output_nanos: int
    max_input_tokens: int

    def __post_init__(self):
        _names((self.price_version,))
        if any(type(value) is not int or not 0 <= value <= 10**9
               for value in (self.input_nanos, self.output_nanos)):
            raise ValueError("Invalid model tariff")
        if type(self.max_input_tokens) is not int or not 1 <= self.max_input_tokens <= 10**7:
            raise ValueError("Invalid model input reservation")

    @classmethod
    def from_document(cls, config):
        if not isinstance(config, dict) or set(config) != set(cls.__dataclass_fields__):
            raise ValueError("Model route requires a versioned tariff and an input reservation")
        return cls(**config)


@dataclass(frozen=True)
class GenerationPolicy:
    data: GenerationData
    accounting: RouteAccounting

    @classmethod
    def from_document(cls, config):
        if not isinstance(config, dict) or config.keys() != {"data", "accounting"}:
            raise ValueError("Invalid generation routing policy")
        return cls(GenerationData.from_document(config["data"]), RouteAccounting.from_document(config["accounting"]))

    def document(self):
        return {"data": self.data.document(), "accounting": asdict(self.accounting)}
