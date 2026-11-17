from collections.abc import Iterator
from typing import Protocol

from camel.capabilities import Capabilities, readers, sources
from camel.interpreter.value import CaMeLValue


class HasDependenciesAndMetadata(Protocol):
    def get_dependencies(
        self, visited_objects: frozenset[int] = frozenset()
    ) -> tuple[tuple[CaMeLValue, ...], frozenset[int]]: ...
    @property
    def metadata(self) -> Capabilities: ...


def _walk(
    value: HasDependenciesAndMetadata, visited_objects: frozenset[int] = frozenset()
) -> Iterator[HasDependenciesAndMetadata]:
    """Yields `value` and everything it transitively depends on, once each (cycles are allowed)."""
    visited = set(visited_objects)
    pending = [value]
    while pending:
        current = pending.pop()
        if id(current) in visited:
            continue
        visited.add(id(current))
        yield current
        pending.extend(current.get_dependencies()[0])


def get_all_readers(
    value: HasDependenciesAndMetadata,
    visited_objects: frozenset[int] = frozenset(),
) -> tuple[readers.Readers, frozenset[int]]:
    value_readers: readers.Readers = readers.Public()
    for current in _walk(value, visited_objects):
        value_readers &= current.metadata.readers_set
    return value_readers, visited_objects


def is_public(value: HasDependenciesAndMetadata):
    return isinstance(get_all_readers(value)[0], readers.Public)


def can_readers_read_value(potential_readers: set, value: CaMeLValue) -> bool:
    value_readers, _ = get_all_readers(value)
    if isinstance(value_readers, readers.Public):
        return True
    return potential_readers.issubset(value_readers)


def get_all_sources(
    value: HasDependenciesAndMetadata,
    visited_objects: frozenset[int] = frozenset(),
) -> tuple[frozenset[sources.Source], frozenset[int]]:
    value_sources: frozenset[sources.Source] = frozenset()
    for current in _walk(value, visited_objects):
        value_sources |= current.metadata.sources_set
    return value_sources, visited_objects


_TRUSTED_SET = {
    sources.SourceEnum.User,
    sources.SourceEnum.CaMeL,
    sources.SourceEnum.Assistant,
    sources.SourceEnum.TrustedToolSource,
}


def _source_is_trusted(s: sources.Source) -> bool:
    if s in _TRUSTED_SET:
        return True
    if isinstance(s, sources.Tool) and not len(s.inner_sources) == 0 and s.inner_sources.issubset(_TRUSTED_SET):
        return True
    return False


def is_trusted(value: HasDependenciesAndMetadata, trusted_set: set | None = None) -> bool:
    trusted_set = trusted_set or _TRUSTED_SET
    return all(_source_is_trusted(source) for source in get_all_sources(value)[0])
