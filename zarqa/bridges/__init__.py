"""Generic bridges: MCP servers for sources that have no MCP server of their own.

Each bridge runs as a stdio MCP server started by a connector, for example::

    connectors:
      - name: sharing-server
        roles: [intel_platform]
        transport: stdio
        command: zarqa
        args: [bridge, taxii, --url, "${TAXII_URL}"]
        env: {BRIDGE_TOKEN: "${TAXII_TOKEN}"}

All bridges are read-only by construction: they only expose read operations
(the REST bridge allows POST only with ``--allow-post``).
"""

KINDS = ("taxii", "openapi", "web")
