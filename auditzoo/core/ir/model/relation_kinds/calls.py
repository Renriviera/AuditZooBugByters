from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from auditzoo.core.ir.model.base import (
    CodeUnit,
    CodeUnitRelation,
    RelationDirection,
    RelationKind,
)
from auditzoo.core.ir.model.errors import IRUnsupportedError
from auditzoo.core.ir.model.unit_kinds.function import Function

if TYPE_CHECKING:
    from auditzoo.core.ir.backend_api import CPGBackend


@dataclass(frozen=True)
class Calls(RelationKind):
    """Kind of call relation between code units.

    Represents function/method calls.
    """

    def _to_kwargs(self) -> dict[str, Any]:
        return {}

    @classmethod
    def _from_kwargs(cls, **kwargs) -> RelationKind:
        return Calls()

    async def fetch_backend(
        self,
        source_unit: CodeUnit,
        direction: "RelationDirection",
        backend: "CPGBackend",
    ) -> list[tuple[CodeUnit, CodeUnitRelation]]:
        if source_unit.kind != Function():
            return []

        if direction == "out":
            # We are querying callees called by the source function
            query = f'cpg.method.id({source_unit.id}L).call.map {{ call => Map("callees" -> call.callee.l, "callsite" -> call) }}.toJson'
            response = await backend.query(query)

            results = []
            for call_info in response:
                callees = call_info["callees"]
                for callee in callees:
                    if callee["isExternal"]:
                        continue

                    callee_unit = (await Function().parse([callee], backend=backend))[0]
                    callsite = call_info["callsite"]
                    relation = CodeUnitRelation(
                        kind=Calls(),
                        callsite_id=f"{callsite['_id']}",
                        callsite_code=callsite["code"],
                        callsite_line=callsite.get("lineNumber"),
                        dispatch_type=callsite.get("dispatchType"),
                    )
                    results.append((callee_unit, relation))
            return results

        elif direction == "in":
            # We are querying callers that call the source function
            query = f'cpg.method.id({source_unit.id}L).callIn.map {{ call => Map("caller" -> call.method, "callsite" -> call) }}.toJson'
            response = await backend.query(query)

            results = []
            for call_info in response:
                caller = call_info["caller"]
                callsite = call_info["callsite"]

                if caller["isExternal"]:
                    continue

                caller_unit = (await Function().parse([caller], backend=backend))[0]
                relation = CodeUnitRelation(
                    kind=Calls(),
                    callsite_id=f"{callsite['_id']}",
                    callsite_code=callsite["code"],
                    callsite_line=callsite.get("lineNumber"),
                    dispatch_type=callsite.get("dispatchType"),
                )
                results.append((caller_unit, relation))

            return results

        else:
            raise IRUnsupportedError(
                "CallRelationKind only supports 'in' and 'out' directions."
            )
