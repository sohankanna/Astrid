"""Generic entity extraction and an inverted index over it.

event -> {USER, HOST, IP, PROCESS, ACCOUNT, RESOURCE, DETECTION, TECHNIQUE}

No attack meaning is inferred: an entity is just a typed, normalized value.
The index maps each entity to the events that mention it (a posting list),
which is what lets correlation avoid all-pairs comparison.
"""

from __future__ import annotations

from array import array
from dataclasses import dataclass, field
from typing import Iterable

from .models import LINKING_ENTITY_TYPES, CorrelationConfig, EntityType, NormalizedEvent

Entity = tuple[EntityType, str]


def entities_of(event: NormalizedEvent, config: CorrelationConfig = CorrelationConfig()) -> tuple[Entity, ...]:
    """Typed entities of one event, deterministic order, ignored values removed.

    Case: hostnames and usernames are case-insensitive in the systems they
    come from (Windows, AD, most IdPs), so they are lower-cased for matching.
    Processes are lower-cased for the same reason. Resource and account IDs
    keep their case.
    """
    found: list[Entity] = []

    def add(kind: EntityType, value: str | None, fold: bool = False) -> None:
        if not value:
            return
        key = value.lower() if fold else value
        if key.lower() in config.ignored_values:
            return
        entity = (kind, key)
        if entity not in found:
            found.append(entity)

    add(EntityType.USER, event.username, fold=True)
    add(EntityType.HOST, event.hostname, fold=True)
    add(EntityType.IP, event.source_ip)
    add(EntityType.IP, event.destination_ip)
    add(EntityType.PROCESS, event.process, fold=True)
    add(EntityType.ACCOUNT, event.account)
    for resource in event.resources:
        add(EntityType.RESOURCE, resource)
    # Alert IDs and rule IDs are both DETECTION entities, kept distinct: events
    # cited by the same ALERT belong together (linking); a RULE can fire on
    # unrelated activity, so rule IDs only feed features.
    for detection in event.detection_ids:
        add(EntityType.DETECTION, f"alert:{detection}")
    for rule in event.rule_ids:
        add(EntityType.DETECTION, f"rule:{rule}")
    for technique in event.techniques:
        add(EntityType.TECHNIQUE, technique)
    return tuple(found)


@dataclass
class EntityIndex:
    """Interned entities, per-event entity IDs, and per-entity posting lists."""

    entities: list[Entity] = field(default_factory=list)
    ids: dict[Entity, int] = field(default_factory=dict)
    event_entities: list[tuple[int, ...]] = field(default_factory=list)
    postings: list[list[int]] = field(default_factory=list)
    hubs: frozenset[int] = frozenset()
    # IP role per event (entity id or -1): an IP entity alone does not say
    # whether it was the source or the destination.
    source_ip: array = field(default_factory=lambda: array("l"))
    destination_ip: array = field(default_factory=lambda: array("l"))

    @classmethod
    def build(cls, events: Iterable[NormalizedEvent], config: CorrelationConfig = CorrelationConfig()) -> "EntityIndex":
        index = cls()
        count = 0
        for event in events:
            ids: list[int] = []
            for entity in entities_of(event, config):
                entity_id = index.ids.get(entity)
                if entity_id is None:
                    entity_id = len(index.entities)
                    index.ids[entity] = entity_id
                    index.entities.append(entity)
                    index.postings.append([])
                index.postings[entity_id].append(event.index)
                ids.append(entity_id)
            index.event_entities.append(tuple(ids))
            index.source_ip.append(index.ids.get((EntityType.IP, event.source_ip or ""), -1))
            index.destination_ip.append(index.ids.get((EntityType.IP, event.destination_ip or ""), -1))
            count += 1
        if config.hub_fraction is not None:
            limit = max(config.hub_min_events, config.hub_fraction * count)
            index.hubs = frozenset(i for i, posting in enumerate(index.postings) if len(posting) > limit)
        return index

    def is_linking(self, entity_id: int) -> bool:
        """Can this entity build a graph edge? (actor/asset type or alert ID, not a hub)"""
        if entity_id in self.hubs:
            return False
        kind, value = self.entities[entity_id]
        return kind in LINKING_ENTITY_TYPES or (kind is EntityType.DETECTION and value.startswith("alert:"))

    def of_type(self, event_index: int, kind: EntityType) -> set[int]:
        return {e for e in self.event_entities[event_index] if self.entities[e][0] is kind}

    def relationships(self, events: list[NormalizedEvent]) -> list[dict[str, str]]:
        """event -> entity relationships, e.g. for inspection or export."""
        out = []
        for event in events:
            for entity_id in self.event_entities[event.index]:
                kind, value = self.entities[entity_id]
                out.append({"event_id": event.event_id, "relation": f"event->{kind.value.lower()}",
                            "entity_type": kind.value, "value": value})
        return out

    def stats(self) -> dict[str, object]:
        by_type: dict[str, int] = {}
        for kind, _ in self.entities:
            by_type[kind.value] = by_type.get(kind.value, 0) + 1
        return {
            "entities": len(self.entities),
            "by_type": dict(sorted(by_type.items())),
            "hubs": sorted(f"{self.entities[h][0].value}:{self.entities[h][1]}" for h in self.hubs),
        }
