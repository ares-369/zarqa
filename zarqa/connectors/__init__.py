"""Connector hub: every intel source is an MCP server tagged with roles."""

from .hub import ConnectorHub, ToolCallError, get_hub
from .spec import ROLES, ConnectorSpec, parse_connectors

__all__ = ["ROLES", "ConnectorHub", "ConnectorSpec", "ToolCallError", "get_hub", "parse_connectors"]
