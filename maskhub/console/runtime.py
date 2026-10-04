"""Composition root for the gateway."""

from __future__ import annotations

from dataclasses import dataclass

from maskhub.audit.journal import Journal
from maskhub.catalog.dataset import DatasetRegistry
from maskhub.mapping.authorizer import PurposeAuthorizer
from maskhub.mapping.registry import MappingRegistry
from maskhub.policy.registry import PolicyRegistry
from maskhub.rule.registry import RuleRegistry
from maskhub.source.registry import SourceRegistry
from maskhub.store.kvstore import RecordStore


@dataclass
class Runtime:
    store: RecordStore
    journal: Journal
    sources: SourceRegistry
    datasets: DatasetRegistry
    rules: RuleRegistry
    policies: PolicyRegistry
    mappings: MappingRegistry
    authorizer: PurposeAuthorizer


def build_runtime(store: RecordStore, reveal_grants: str = "") -> Runtime:
    return Runtime(
        store=store,
        journal=Journal(store),
        sources=SourceRegistry(store),
        datasets=DatasetRegistry(store),
        rules=RuleRegistry(store),
        policies=PolicyRegistry(store),
        mappings=MappingRegistry(store),
        authorizer=PurposeAuthorizer.from_config(reveal_grants),
    )
