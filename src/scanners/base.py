from abc import ABC, abstractmethod
from ..models import Identifier, Finding

class Scanner(ABC):
    name = "base"
    supported_types: set = set()

    def supports(self, i: Identifier) -> bool:
        return i.type in self.supported_types

    @abstractmethod
    def scan(self, identifier: Identifier, investigation_id: str, actor_id: str | None) -> list[Finding]:
        ...
