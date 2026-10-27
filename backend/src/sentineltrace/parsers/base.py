"""Parser interfaces."""

from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path

from sentineltrace.core.models import NormalizedEvent


class LogParser(ABC):
    @abstractmethod
    def parse_file(self, path: Path) -> Iterator[NormalizedEvent]:
        raise NotImplementedError

    @abstractmethod
    def detect_format(self, path: Path) -> bool:
        raise NotImplementedError
