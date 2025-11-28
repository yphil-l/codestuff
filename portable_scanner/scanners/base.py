from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from ..context import ScanContext
from ..models import ArtifactCategory, Finding


class ArtifactScanner(ABC):
    category: ArtifactCategory
    name: str

    def __init__(self) -> None:
        self.name = getattr(self, "name", self.__class__.__name__)

    @abstractmethod
    def scan(self, context: ScanContext) -> Iterable[Finding]:
        """Yield findings for the artifact category."""

    def supported(self, context: ScanContext) -> bool:
        return True
