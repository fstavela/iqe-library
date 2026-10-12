"""Safe YAML parsing with library-local Vault reference support."""

from typing import Any, TextIO

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode, Node

from iqe_library.config._runtime import normalize_lazy_values
from iqe_library.config.references import VaultReference


class _ConfigLoader(yaml.SafeLoader):
    """Keep custom constructors separate from PyYAML's global loaders."""


def _vault_reference(loader: _ConfigLoader, node: Node) -> VaultReference:
    if not isinstance(node, MappingNode):
        raise ConstructorError(
            "while constructing !from_vault",
            node.start_mark,
            f"expected a mapping node, found {getattr(node, 'id', type(node).__name__)}",
            node.start_mark,
        )

    fields = loader.construct_mapping(node, deep=True)
    unknown = fields.keys() - {"path", "key"}
    if unknown:
        raise ConstructorError(
            "while constructing !from_vault",
            node.start_mark,
            f"unknown fields: {', '.join(map(str, unknown))}",
            node.start_mark,
        )

    for name in ("path", "key"):
        if name == "key" and name not in fields:
            continue
        value = fields.get(name)
        if not isinstance(value, str) or not value:
            raise ConstructorError(
                "while constructing !from_vault",
                node.start_mark,
                f"{name} must be a nonempty string",
                node.start_mark,
            )
    return VaultReference(path=fields["path"], key=fields.get("key"))


_ConfigLoader.add_constructor("!from_vault", _vault_reference)


def yaml_reader(stream: TextIO) -> dict[str, Any]:
    """Read one configuration mapping, preserving YAML errors and source names."""
    loader = _ConfigLoader(stream)
    try:
        node = loader.get_single_node()
        if node is None:
            return {}
        data = loader.construct_document(node)
        if not isinstance(data, dict):
            source = getattr(stream, "name", "<stream>")
            raise ValueError(f"{source}: expected a YAML mapping")
        normalize_lazy_values(data)
        return data
    finally:
        loader.dispose()
